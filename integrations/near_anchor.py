import hashlib
import json
import re
import subprocess
import time
from abc import ABC, abstractmethod

from core.interfaces import Anchor, AnchorUnavailable, CasResult, GateConfigError
from core.records import Record
from integrations.codec import header_to_dict
from integrations.near_rpc import NearRpc, NearRpcError, NearRpcUnavailable
from integrations.record_store import RecordStore

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


MIN_PROTOCOL_VERSION = 88   


def preflight(rpc: NearRpc, expect_chain="testnet", min_protocol=MIN_PROTOCOL_VERSION):
    """Returns a list of problems (empty = OK). Read-only. Checks the chain id and that the network's active
    protocol version is at least the one the contract's near-sdk requires."""
    try:
        st = rpc.status()
    except (NearRpcUnavailable, NearRpcError) as e:
        return ["cannot read node status: %s" % e]
    out = []
    if st["chain_id"] != expect_chain:
        out.append("chain_id is %r, expected %r" % (st["chain_id"], expect_chain))
    if st["protocol_version"] < min_protocol:
        out.append("protocol_version %d < %d required by near-sdk 5.30.0 (build with an older near-sdk/Rust instead)"
                   % (st["protocol_version"], min_protocol))
    return out


class AnchorIntegrityError(GateConfigError):
    """The chain head and the local record store disagree, or the chain belongs to another scope/policy."""


class SenderNotSent(Exception):
    """The transaction was definitely NOT broadcast (e.g. the signer binary is missing)."""


class TxSender(ABC):
    @abstractmethod
    def send_cas(self, args: dict) -> bool:
        """Broadcast contract call `cas`. Return True if the signer reported success, False if it reported
        failure or timed out (outcome ambiguous). Raise SenderNotSent only if nothing was broadcast."""


class NearCliSender(TxSender):
    """Calls `near contract call-function as-transaction ...` (near-cli-rs) with sign-with-keychain.
    argv syntax follows the near-cli-rs docs; it has NOT been executed here (see NEAR_EVIDENCE.md)."""
    SIGN_MODES = ("keychain", "legacy-keychain")        # never plaintext keys on a command line

    def __init__(self, contract_id, signer_id, network="testnet", cli="near", gas="30 TeraGas",
                 runner=subprocess.run, timeout=120.0, sign_with="keychain"):
        if sign_with not in self.SIGN_MODES:
            raise ValueError("sign_with must be one of %r" % (self.SIGN_MODES,))
        self.sign_with = sign_with
        self.contract_id, self.signer_id, self.network = contract_id, signer_id, network
        self.cli, self.gas, self._run, self.timeout = cli, gas, runner, timeout
        self.last = None            

    def argv(self, args: dict):
        return [self.cli, "contract", "call-function", "as-transaction", self.contract_id, "cas",
                "json-args", json.dumps(args, separators=(",", ":")), "prepaid-gas", self.gas,
                "attached-deposit", "0 NEAR", "sign-as", self.signer_id, "network-config", self.network,
                "sign-with-" + self.sign_with, "send"]

    def send_cas(self, args):
        try:
            r = self._run(self.argv(args), capture_output=True, timeout=self.timeout, check=False)
        except FileNotFoundError as e:
            raise SenderNotSent(str(e)) from e
        except subprocess.TimeoutExpired:
            return False
        err = r.stderr if isinstance(getattr(r, "stderr", None), (bytes, str)) else b""
        err = err.decode(errors="replace") if isinstance(err, bytes) else err
        self.last = (r.returncode, err[-300:])
        return r.returncode == 0


class NearAnchor(Anchor):
    def __init__(self, rpc: NearRpc, contract_id, sender: TxSender, store: RecordStore, writer_key,
                 scope_id, policy_digest, confirm_timeout=30.0, poll_interval=2.0,
                 sleep=time.sleep, clock=time.monotonic):
        self.rpc, self.contract_id, self.sender, self.store = rpc, contract_id, sender, store
        self.writer_key, self.scope_id, self.policy_digest = writer_key, scope_id, policy_digest
        self.confirm_timeout, self.poll_interval, self._sleep, self._clock = confirm_timeout, poll_interval, sleep, clock
        self.last_error = None

    # ---- chain head ----
    def _read_head(self):
        try:
            h = self.rpc.view_function(self.contract_id, "get_head")
        except (NearRpcUnavailable, NearRpcError) as e:
            self.last_error = repr(e)
            raise AnchorUnavailable(str(e)) from e
        ok = (isinstance(h, dict) and isinstance(h.get("version"), int) and not isinstance(h.get("version"), bool)
              and h["version"] >= 0 and isinstance(h.get("digest"), str) and _HEX64.match(h["digest"]))
        if not ok:
            raise AnchorIntegrityError("malformed head returned by the contract")
        if h.get("scope_id") != self.scope_id or h.get("policy_digest") != self.policy_digest:
            raise AnchorIntegrityError("chain head belongs to a different scope/policy")
        return h["version"], h["digest"]

    def read(self) -> Record:
        version, digest = self._read_head()
        rec = self.store.get(digest)
        if rec is None:
            raise AnchorUnavailable("record for the chain head is not in the local store")
        if rec.digest() != digest or rec.header.version != version:
            raise AnchorIntegrityError("stored record does not match the chain head")
        return rec

    @property
    def version(self) -> int:
        """Version of the chain head (read at finality=final, verified against the record store)."""
        return self.read().header.version

    def history(self, limit=64):
        """Records from the oldest locally stored one up to the head, oldest first, by following prev_digest
        through the record store. Read-only; never exposes more than the store already holds."""
        out, rec = [], self.read()
        while rec is not None and len(out) < limit:
            out.append(rec)
            if rec.header.version == 0:
                break
            rec = self.store.get(rec.header.prev_digest)
        return list(reversed(out))

    # ---- guarded write ----
    def compare_and_swap(self, writer_key, expected_version, expected_digest, new_record) -> CasResult:
        if writer_key != self.writer_key:
            return CasResult.UNAUTHORIZED
        h = new_record.header
        if (h.version != expected_version + 1 or h.prev_digest != expected_digest
                or h.scope_id != self.scope_id or h.policy_digest != self.policy_digest):
            return CasResult.MALFORMED
        new_digest = new_record.digest()
        self.store.put(new_record)                     
        args = {"expected_version": expected_version, "expected_digest": expected_digest,
                "new_digest": new_digest, "header": json.dumps(header_to_dict(h), separators=(",", ":"))}
        try:
            self.sender.send_cas(args)                
        except SenderNotSent as e:
            raise AnchorUnavailable(str(e)) from e
        return self._resolve(expected_version, h.version, new_digest)

    def _resolve(self, expected_version, new_version, new_digest) -> CasResult:
        deadline = self._clock() + self.confirm_timeout
        while True:
            try:
                v, d = self._read_head()
            except AnchorUnavailable:
                v = None
            if v is not None:
                if v == new_version:
                    return CasResult.COMMITTED if d == new_digest else CasResult.CONFLICT
                if v > new_version or v < expected_version:
                    return CasResult.UNKNOWN            
            if self._clock() >= deadline:
                return CasResult.UNKNOWN
            self._sleep(self.poll_interval)

    @staticmethod
    def init_args(writer_account, genesis: Record) -> dict:
        """Arguments for the contract's `new` (deploy-time init)."""
        return {"writer": writer_account, "scope_id": genesis.header.scope_id,
                "policy_digest": genesis.header.policy_digest, "genesis_digest": genesis.digest()}
