import re
import secrets
import sys
import threading
import time
import json
import os
from dataclasses import dataclass
from typing import Optional

from app.service import ApiError, VERIFIERS, _Session
from core.gate import Gate
from core.interfaces import AnchorUnavailable, GateConfigError
from core.records import Response, State, policy_digest
from harness.system import DEMO_POLICY, FIXTURE_SECRET, WRITER_KEY, Client
from integrations.near_anchor import NearAnchor, NearCliSender, preflight
from integrations.near_rpc import NearRpc, NearRpcError, NearRpcUnavailable
from integrations.record_store import DirRecordStore
from testdoubles.hmac_auth import HmacTestAuthenticator
from testdoubles.test_sealer import UnsealedTestSealer

LIVE_NOTICE = ("LIVE NEAR TESTNET MODE. The anchor is a smart contract deployed on NEAR testnet. Each question is "
               "committed there by THIS server's signing account; visitors cannot sign or submit authorized writes. "
               "The gate, the secret, the owner token and the sealed state stay on the operator's computer. The sealer "
               "does not encrypt and the credential is a mock: no confidentiality, rollback resistance or attestation. "
               "Testnet only, not production. Answers appear only after the transition is confirmed on chain.")
EXPLORER = {"testnet": "https://testnet.nearblocks.io"}
ACCOUNT_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$")
TX_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{43,44}$")
CHAIN_CACHE_SECONDS = 3.0


class NearModeError(Exception):
    """Startup problem in live mode (missing store, wrong chain, unreachable testnet, ...). Fail closed, say why."""


@dataclass
class LiveConfig:
    store: str
    contract: str
    writer: str
    rpc_url: str = "https://test.rpc.fastnear.com"
    network: str = "testnet"
    sign_with: str = "keychain"
    near_cli: str = "near"
    confirm_timeout: float = 45.0
    deploy_tx: Optional[str] = None


def explorer_links(cfg: LiveConfig) -> dict:
    base = EXPLORER[cfg.network]
    links = {"contract": f"{base}/address/{cfg.contract}", "signing_account": f"{base}/address/{cfg.writer}"}
    if cfg.deploy_tx:
        links["deployment_transaction"] = f"{base}/txns/{cfg.deploy_tx}"
    return links


class NearSystem:
    """Same attribute surface as harness.system.System (what Service/_execute use), backed by NEAR."""
    def __init__(self, cfg, anchor, gate, auth, sealer, scope_id, pd):
        self.cfg, self.anchor, self.gate, self.auth, self.sealer = cfg, anchor, gate, auth, sealer
        self.scope_id, self.pd = scope_id, pd
        self.policy, self.secret, self.verifier_ids = DEMO_POLICY, FIXTURE_SECRET, tuple(VERIFIERS)

    def state(self) -> State:
        return State.from_bytes(self.sealer.unseal(self.anchor.read().sealed_state))

    def client(self, vid):
        c = Client(self, vid)
        c.nonce = self.state().verifiers[vid].last_nonce + 1      
        return c


def build_live_system(cfg: LiveConfig, rpc=None, sender=None, sleep=None, clock=None) -> NearSystem:
    """Validates everything before serving. rpc/sender/sleep/clock are injectable for model-based tests."""
    if cfg.network != "testnet":
        raise NearModeError("only testnet is supported")
    for label, acct in (("contract", cfg.contract), ("writer", cfg.writer)):
        if not ACCOUNT_RE.match(cfg.__dict__[label] or ""):
            raise NearModeError(f"invalid {label} account id")
    if cfg.deploy_tx is not None and not TX_RE.match(cfg.deploy_tx):
        raise NearModeError("invalid deployment transaction id")
    cfg_file = os.path.join(cfg.store, "config.json")
    try:
        with open(cfg_file) as f:
            local = json.load(f)
        scope_id, pd = str(local["scope_id"]), str(local["policy_digest"])
    except (OSError, ValueError, KeyError) as e:
        raise NearModeError(f"cannot read {cfg_file}: the store is missing or was not created by "
                            f"`near_live_check.py init` ({type(e).__name__})") from e
    if pd != policy_digest(DEMO_POLICY):
        raise NearModeError("the store's policy digest does not match this build's demo policy")
    rpc = rpc or NearRpc(cfg.rpc_url)
    problems = preflight(rpc, expect_chain=cfg.network)
    if problems:
        raise NearModeError("preflight failed: " + "; ".join(problems))
    sender = sender or NearCliSender(cfg.contract, cfg.writer, network=cfg.network, cli=cfg.near_cli,
                                     sign_with=cfg.sign_with)
    kw = {}
    if sleep is not None:
        kw["sleep"] = sleep
    if clock is not None:
        kw["clock"] = clock
    anchor = NearAnchor(rpc, cfg.contract, sender, DirRecordStore(cfg.store), WRITER_KEY, scope_id, pd,
                        confirm_timeout=cfg.confirm_timeout, **kw)
    try:
        anchor.read()                                             
    except AnchorUnavailable as e:
        raise NearModeError(f"cannot read the chain head or its record from the store: {e}") from e
    except GateConfigError as e:
        raise NearModeError(f"integrity/config error: {e}") from e
    sealer = UnsealedTestSealer()
    auth = HmacTestAuthenticator({v: ("key-" + v).encode() for v in VERIFIERS})
    gate = Gate(DEMO_POLICY, scope_id, FIXTURE_SECRET, anchor, sealer, auth, WRITER_KEY)
    return NearSystem(cfg, anchor, gate, auth, sealer, scope_id, pd)


class _LiveSession(_Session):
    """The single live session. Never built by create_session; Service(live=...) registers it as id 'live'."""
    live = True
    READ_ERRORS = (AnchorUnavailable,)

    def __init__(self, system: NearSystem):
        self.id, self.policy, self.secret = "live", system.policy, system.secret
        self.owner_token = secrets.token_urlsafe(16)                  
        self.system, self.cfg = system, system.cfg
        self.clients = {v: system.client(v) for v in VERIFIERS}
        self.lock, self.log, self.created = threading.Lock(), [], time.time()
        self.pending, self.halted = {}, None                             
        self._chain_lock, self._chain_cache = threading.Lock(), (0.0, None)

    # ---- the one place a live request reaches the gate ----
    def ask(self, vid, t):
        """Exactly ONE gate round per API call: no loops, no blind retries. After RETRY the identical request (same
        nonce, same blinding) is kept and resent on the next call; a different threshold is refused until it resolves.
        An ANSWER/REFUSED is released only after the chain state shows this very request committed."""
        if self.halted:
            raise ApiError(503, "the live session is halted: " + self.halted)
        self._chain_cache = (0.0, None)          
        try:
            return self._ask(vid, t)
        finally:
            self._chain_cache = (0.0, None)      

    def _ask(self, vid, t):
        client, pend = self.clients[vid], self.pending.get(vid)
        if pend is not None:
            pt, req = pend
            if pt != t:
                raise ApiError(409, f"an earlier request from {vid} is not confirmed on chain yet; "
                                    f"resend the same threshold ({pt}) first")
        else:
            req = client.make(t)
        resp = self.system.gate.handle(req)                              
        if resp.kind == "RETRY":
            self.pending[vid] = (t, req)
            return resp
        if resp.kind == "REJECTED":
            self.pending.pop(vid, None)
            try:
                client.nonce = self.system.state().verifiers[vid].last_nonce + 1   
            except AnchorUnavailable:
                pass
            return resp
        try:                                                              
            vs = self.system.state().verifiers[vid]
        except AnchorUnavailable:
            self.pending[vid] = (t, req)
            return Response.retry()
        if vs.last_nonce != req.nonce or vs.last_digest != req.digest():
            self.pending[vid] = (t, req)
            return Response.retry()
        self.pending.pop(vid, None)
        client.nonce = req.nonce + 1
        return resp

    def check_open(self):
        if self.halted:
            raise ApiError(503, "the live session is halted: " + self.halted)

    def map_error(self, ex):
        """HTTP-safe error for an exception raised during a live request, or None if it is not one we classify."""
        print(f"[live] {type(ex).__name__}: {ex}", file=sys.stderr)       
        if isinstance(ex, AnchorUnavailable):
            return ApiError(503, "The NEAR testnet or the local record store could not be read. Nothing was released "
                                 "from this request; resend the same request later.")
        if isinstance(ex, GateConfigError):
            self.halted = "integrity or configuration error (details on the server console)"
            return ApiError(503, "Integrity or configuration error: the live session is halted and refuses all "
                                 "further requests.")
        return None

    # ---- public, credential-free views ----
    def mode_info(self):
        return {"mode": "near-testnet", "session_id": self.id, "notice": LIVE_NOTICE, "network": self.cfg.network,
                "contract": self.cfg.contract, "signing_account": self.cfg.writer,
                "explorer": explorer_links(self.cfg),
                "signing_note": "Writes are signed by this server's signing account. Visitors can read the chain head "
                                "but cannot submit authorized writes."}

    def public_chain_head(self):
        """Read-only `get_head` view call straight to the RPC (no store, no signing). Cached for a few seconds."""
        with self._chain_lock:
            at, cached = self._chain_cache
            if cached is not None and time.monotonic() - at < CHAIN_CACHE_SECONDS:
                return cached
            out = self.mode_info() | {"rpc_url": self.cfg.rpc_url, "read_at": int(time.time()), "head": None}
            try:
                h = self.system.anchor.rpc.view_function(self.cfg.contract, "get_head")
                out["head"] = {k: h.get(k) for k in ("version", "digest", "scope_id", "policy_digest", "writer")}
            except (NearRpcUnavailable, NearRpcError):
                out["error"] = "NEAR RPC unavailable or returned an error; the chain head could not be read"
            out["verify_with"] = ("curl -s " + self.cfg.rpc_url + " -H 'content-type: application/json' -d "
                                  "'{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"query\",\"params\":{\"request_type\":"
                                  "\"call_function\",\"finality\":\"final\",\"account_id\":\"" + self.cfg.contract +
                                  "\",\"method_name\":\"get_head\",\"args_base64\":\"e30=\"}}'")
            self._chain_cache = (time.monotonic(), out)
            return out

    def live_info(self):
        """Owner-view extras (owner token required)."""
        return {"mode": "near-testnet", "contract": self.cfg.contract, "signing_account": self.cfg.writer,
                "network": self.cfg.network, "halted": self.halted,
                "unconfirmed_requests": {v: p[0] for v, p in self.pending.items()},
                "confirm_timeout_seconds": self.cfg.confirm_timeout}


def build_live_session(cfg: LiveConfig, **kw) -> "_LiveSession":
    return _LiveSession(build_live_system(cfg, **kw))
