#!/usr/bin/env python3
"""GUARDED, STAGED deployment of a SEPARATE demo anchor contract on NEAR testnet.

Why it exists: the first deployment (bbanchor-teedor.testnet + ./bbstore) is evidence and must never be touched. A public
demo needs its own contract, its own fresh scope, its own fresh store and its own privacy budget. This script refuses to
operate on the evidence accounts/stores, verifies the wasm before anything is sent, sends AT MOST ONE transaction per
stage, runs near-cli-rs through a Python argument LIST (no shell, so no PowerShell/JSON quoting problems), and after any
ambiguous outcome re-reads the chain and STOPS. It never retries a transaction by itself.

Stages (run them in order; each mutating stage is a dry run unless you add --execute --confirm <contract>):
  plan            offline: show what will happen, the wasm hash, the required balance. Reads nothing, writes nothing.
  syntax          offline: ask the installed near binary to parse the exact command lines (--help only; nothing sent).
  prepare         creates the FRESH store (fresh scope, fresh genesis). Refuses if the directory already has content.
  create-account  ONE faucet transaction creating the contract account. Refuses if the account already exists.
  deploy          ONE transaction: deploy the verified wasm and call `new` (atomic). Refuses unless every precondition holds.
  verify          read-only: checks the chain head through the Python adapter AND the read-only chain-head reader.
Never run scripts/near_live_check.py selftest on the demo contract: it would spend the demo's privacy budget."""
import argparse
import hashlib
import io
import json
import locale
import os
import re
import subprocess
import sys
import time
import types
import contextlib

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)

from harness.system import WRITER_KEY                                                  # noqa: E402
from integrations.near_anchor import NearAnchor, TxSender, preflight                  # noqa: E402
from integrations.near_rpc import NearRpc, NearRpcError, NearRpcUnavailable           # noqa: E402
from integrations.record_store import DirRecordStore                                   # noqa: E402
from scripts import chain_head, near_live_check as nlc                                 # noqa: E402

# ---- the evidence deployment (owner-reported, NEAR_EVIDENCE.md section 8): never touched by this script ----
EVIDENCE_ACCOUNTS = {"bbanchor-teedor.testnet"}
EVIDENCE_STORE_NAMES = {"bbstore"}
EVIDENCE_SCOPE_ID = "6a8328d88ea9d71bbfa4d446117ec90b"
EVIDENCE_GENESIS_DIGEST = "43a084b2106e54d1c1158a2dccc189360f96111c2d806c0b0b7f0fc19900dc93"

EXPECTED_WASM_SHA256 = "1480a5e6b65f2e28bf5eb980f36d3f56725eacd7106a23dcb15828d30c90c2e7"
WASM_PATH = os.path.abspath(os.path.join(ROOT, "contracts", "anchor", "dist", "bitbudget_anchor.wasm"))
SUMS_PATH = os.path.join(os.path.dirname(WASM_PATH), "SHA256SUMS")
ACCOUNT_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$")
PLAN_FILE = "deploy_plan_demo.json"
JOURNAL_FILE = "attempts_demo.json"            # one entry per transaction attempt, written BEFORE it is sent
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
SECRET_LINE_RE = re.compile(r"seed phrase|secret|private key|mnemonic", re.I)
LONG_KEY_RE = re.compile(r"ed25519:[1-9A-HJ-NP-Za-km-z]{60,}")   # a secret key is ~88 base58 chars; a public key ~44
ZERO_CODE_HASH = "1" * 32                      # base58 of 32 zero bytes: the account has no contract
YOCTO, BYTE_COST = 10 ** 24, 10 ** 19
STORAGE_OVERHEAD_BYTES = 864                   # account record + one access key + contract state, rounded up
GAS_ALLOWANCE_YOCTO = 100 * 10 ** 12 * 10 ** 8  # 100 TGas prepaid at an upper-bound 1e8 yocto/gas = 0.01 NEAR
MARGIN = 1.05
EXIT_OK, EXIT_REFUSED, EXIT_AMBIGUOUS = 0, 1, 2
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


class Refuse(Exception):
    """A precondition failed. Nothing was sent."""


def b58encode(b: bytes) -> str:
    n, s = int.from_bytes(b, "big"), ""
    while n:
        n, r = divmod(n, 58)
        s = _B58[r] + s
    return "1" * (len(b) - len(b.lstrip(b"\0"))) + s


def code_hash_of(wasm: bytes) -> str:
    """NEAR's `code_hash` for a contract: base58 of the sha256 of the wasm."""
    return b58encode(hashlib.sha256(wasm).digest())


def required_yocto(wasm_len: int) -> int:
    return int(((wasm_len + STORAGE_OVERHEAD_BYTES) * BYTE_COST + GAS_ALLOWANCE_YOCTO) * MARGIN)


def near(yocto) -> str:
    return "%.4f NEAR" % (int(yocto) / YOCTO)


def load_wasm() -> bytes:
    try:
        with open(WASM_PATH, "rb") as f:
            wasm = f.read()
        with open(SUMS_PATH) as f:
            listed = f.read().split()[0]
    except OSError as e:
        raise Refuse("cannot read the wasm or its SHA256SUMS: %s" % e)
    got = hashlib.sha256(wasm).hexdigest()
    if got != EXPECTED_WASM_SHA256 or listed != EXPECTED_WASM_SHA256:
        raise Refuse("wasm hash mismatch: file %s, SHA256SUMS %s, expected %s" % (got, listed, EXPECTED_WASM_SHA256))
    return wasm


def guard(a) -> bytes:
    for label, acct in (("contract", a.contract), ("writer", a.writer)):
        if not ACCOUNT_RE.match(acct or ""):
            raise Refuse("invalid %s account id" % label)
    if a.contract in EVIDENCE_ACCOUNTS:
        raise Refuse("%s is the evidence deployment: this script never touches it" % a.contract)
    if a.contract == a.writer:
        raise Refuse("the demo contract account must differ from the writer account")
    store = os.path.abspath(a.store)
    if os.path.basename(store) in EVIDENCE_STORE_NAMES:
        raise Refuse("%s is the evidence store name: use a different --store (default bbstore-demo)" % os.path.basename(store))
    return load_wasm()


def build_argvs(a, wasm_path=WASM_PATH, init_json="{}"):
    create = [a.near_cli, "account", "create-account", "sponsor-by-faucet-service", a.contract,
              "autogenerate-new-keypair", "save-to-keychain", "network-config", "testnet", "create"]
    deploy = [a.near_cli, "contract", "deploy", a.contract, "use-file", wasm_path, "with-init-call", "new",
              "json-args", init_json, "prepaid-gas", "100 TeraGas", "attached-deposit", "0 NEAR",
              "network-config", "testnet", "sign-with-keychain", "send"]
    return create, deploy


def account_state(rpc, acct):
    """The account's on-chain summary, or None if it does not exist. Other errors propagate (never guessed)."""
    try:
        return rpc.view_account(acct)
    except NearRpcError as e:
        if "does not exist" in str(e).lower() or "unknown_account" in str(e).lower():
            return None
        raise


def poll_account(rpc, acct, done, sleep, clock, seconds=45):
    """Read the account until done(state) or the deadline. RPC errors count as 'not ready yet': this runs AFTER a
    transaction may have been sent, so it must never raise or imply that nothing was sent. -> (state_or_'unknown', reached)"""
    deadline, last = clock() + seconds, "unknown"
    while True:
        try:
            last = account_state(rpc, acct)
            if done(last):
                return last, True
        except (NearRpcUnavailable, NearRpcError):
            pass
        if clock() >= deadline:
            return last, False
        sleep(3)


def decode_output(raw) -> str:
    """Deliberate, crash-proof decoding of the near CLI's output. The bytes are decoded by US, never by subprocess
    (text mode uses the locale encoding, cp1252 on Windows, and raises on a bad byte). Strategy: strict UTF-8 first (what
    near-cli-rs emits); if that fails, the system's preferred encoding with errors='replace'; if even that name is
    unknown, latin-1 (which decodes every byte). ANSI colour codes are stripped. Cannot raise."""
    if raw is None:
        return ""
    if isinstance(raw, str):
        text = raw
    else:
        try:
            text = bytes(raw).decode("utf-8")
        except UnicodeDecodeError:
            try:
                text = bytes(raw).decode(locale.getpreferredencoding(False) or "latin-1", errors="replace")
            except (LookupError, ValueError):
                text = bytes(raw).decode("latin-1")
    return ANSI_RE.sub("", text)


def sanitize(text: str) -> str:
    """Text that is safe to print on ANY console (ASCII only; non-ASCII becomes \\uXXXX) and free of key material:
    lines mentioning a seed phrase/secret/private key are dropped and long ed25519 keys are masked. Raw CLI output is
    never written to disk."""
    kept = []
    for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        if SECRET_LINE_RE.search(line):
            kept.append("[line withheld: it mentions key material]")
        else:
            kept.append(LONG_KEY_RE.sub("ed25519:[secret key masked]", line))
    return "\n".join(kept).encode("ascii", "backslashreplace").decode("ascii")


def _tail(stdout, stderr, limit=1500) -> str:
    parts = []
    for label, raw in (("stdout", stdout), ("stderr", stderr)):
        t = sanitize(decode_output(raw)).strip()
        if t:
            parts.append("[%s] %s" % (label, t))
    text = "\n".join(parts) or "(no output captured)"
    return text[-limit:]


def run_cli(runner, argv, timeout):
    """(status, tail). status is one of:
       ok       the command exited 0
       failed   the command exited non-zero            -> the chain must still be checked: it may have been sent
       timeout  the command was killed after `timeout` -> NOT a failure: the transaction MAY have been sent
       error    anything unexpected while running it   -> NOT a failure: the transaction MAY have been sent
       missing  the binary could not be started        -> the only status that proves nothing was sent
    Output is captured as BYTES and decoded here (see decode_output); partial output is kept on timeout; stdin is closed
    so a hidden prompt fails fast instead of hanging. Never raises Exception; never retries."""
    try:
        r = runner(argv, capture_output=True, stdin=subprocess.DEVNULL, timeout=timeout, check=False)
    except (FileNotFoundError, PermissionError, NotADirectoryError):
        return "missing", "the near binary could not be started (nothing was sent)"
    except subprocess.TimeoutExpired as e:
        return "timeout", ("the near command timed out after %ss and was stopped; this is NOT proof of failure: the transaction MAY have "
                           "been sent. Partial output follows.\n" % timeout) + _tail(getattr(e, "stdout", None) or getattr(e, "output", None), getattr(e, "stderr", None))
    except Exception as e:  # noqa: BLE001  (anything unexpected, e.g. a decode error: report as ambiguous, never as failure)
        return "error", "the near command raised %s while running; this is NOT proof of failure: the transaction MAY have been sent." % type(e).__name__
    return ("ok" if r.returncode == 0 else "failed"), _tail(getattr(r, "stdout", None), getattr(r, "stderr", None))


# ---- attempt journal: every transaction attempt is recorded BEFORE it is sent, so a crash can never hide it ----
def journal_load(store):
    try:
        with open(os.path.join(store, JOURNAL_FILE)) as f:
            data = json.load(f)
    except FileNotFoundError:
        return []
    except (OSError, ValueError):
        raise Refuse("the attempt journal in %s is unreadable: inspect the chain and the store before doing anything else" % store)
    if not isinstance(data, list):
        raise Refuse("the attempt journal is malformed: inspect before doing anything else")
    return data


def journal_save(store, entries):
    tmp = os.path.join(store, JOURNAL_FILE + ".tmp")
    with open(tmp, "w") as f:
        json.dump(entries, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, os.path.join(store, JOURNAL_FILE))


def journal_start(store, stage):
    entries = journal_load(store)
    entries.append({"stage": stage, "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "outcome": "started"})
    journal_save(store, entries)
    return len(entries) - 1


def journal_finish(store, idx, outcome, cli_status, chain_after, tail):
    entries = journal_load(store)
    entries[idx].update(outcome=outcome, cli_status=cli_status, chain_after=chain_after, output_tail=tail[-500:])
    journal_save(store, entries)


def journal_unresolved(store, stage):
    """Attempts of this stage that are neither confirmed by the chain nor proven unsent."""
    return [e for e in journal_load(store) if e.get("stage") == stage and e.get("outcome") in ("started", "ambiguous")]


def prior_attempts_text(prior, stage):
    lines = ["PREVIOUS %s ATTEMPT(S) ARE UNRESOLVED (ambiguous or interrupted); a timeout or crash does not prove a failure:" % stage]
    for e in prior:
        lines.append("  - started %s, outcome %s, cli_status %s, chain_after %s" % (e.get("started_utc"), e.get("outcome"), e.get("cli_status", "n/a"), e.get("chain_after", "n/a")))
    lines.append("Before any further attempt: look the account up on the chain (`inspect`), wait, and only then add --acknowledge-ambiguous-attempt.")
    return "\n".join(lines)


def load_prepared(a):
    try:
        with open(os.path.join(a.store, "config.json")) as f:
            cfg = json.load(f)
        with open(os.path.join(a.store, PLAN_FILE)) as f:
            plan = json.load(f)
    except (OSError, ValueError) as e:
        raise Refuse("the store is not prepared (run `prepare` first): %s" % type(e).__name__)
    if plan.get("contract") != a.contract or plan.get("writer") != a.writer:
        raise Refuse("the prepared store belongs to a different contract/writer pair")
    ia = plan["init_args"]
    if ia.get("scope_id") != cfg.get("scope_id") or ia.get("policy_digest") != cfg.get("policy_digest"):
        raise Refuse("the prepared store is internally inconsistent")
    if DirRecordStore(a.store).get(ia["genesis_digest"]) is None:
        raise Refuse("the genesis record is missing from the store")
    return cfg, plan


def preflight_or_refuse(rpc):
    problems = preflight(rpc, expect_chain="testnet")
    if problems:
        raise Refuse("preflight failed: " + "; ".join(problems))


def need_execute(a):
    if not a.execute:
        return False
    if a.confirm != a.contract:
        raise Refuse("--execute needs --confirm %s (typing the account name is the deliberate second step)" % a.contract)
    return True


# ------------------------------------------------------------------ stages
def stage_plan(a, out, **_):
    wasm = guard(a)
    create, deploy = build_argvs(a, init_json="<init args JSON from prepare>")
    out("DEMO DEPLOYMENT PLAN (nothing has been sent; nothing is read from or written to any network)")
    out("  evidence deployment (never touched): %s, store name %s, scope %s" % (sorted(EVIDENCE_ACCOUNTS), sorted(EVIDENCE_STORE_NAMES), EVIDENCE_SCOPE_ID))
    out("  demo contract account : %s" % a.contract)
    out("  writer / signer       : %s (existing key in your keychain; signs the app's writes)" % a.writer)
    out("  fresh store           : %s" % os.path.abspath(a.store))
    out("  wasm                  : %d bytes, sha256 %s (verified against SHA256SUMS)" % (len(wasm), hashlib.sha256(wasm).hexdigest()))
    out("  expected on-chain code_hash: %s" % code_hash_of(wasm))
    out("  required balance      : at least %s on %s (storage %d bytes x 1e19 + 100 TGas allowance, x%.2f margin)" % (
        near(required_yocto(len(wasm))), a.contract, len(wasm) + STORAGE_OVERHEAD_BYTES, MARGIN))
    out("  faucet command (argument list, no shell): %s" % subprocess.list2cmdline(create))
    out("  deploy command  (argument list, no shell): %s" % subprocess.list2cmdline(deploy))
    out("  stage order: plan, syntax, prepare, create-account, deploy, verify. Mutating stages are dry runs without --execute --confirm %s." % a.contract)
    out("  stop rules: any refusal or ambiguous result ends the run; nothing is retried; re-read the chain first.")
    out("  do NOT run `near_live_check.py selftest` on the demo contract (it spends the demo budget).")
    return EXIT_OK


def stage_syntax(a, out, runner=subprocess.run, **_):
    guard(a)
    create, deploy = build_argvs(a)
    ver_status, ver = run_cli(runner, [a.near_cli, "--version"], 30)
    m = re.search(r"near-cli-rs\s+[\d.]+", ver or "")
    out("near binary: %s" % (m.group(0) if m else (ver.splitlines()[-1] if ver else ver_status)))
    if ver_status == "ok" and "0.30.1" not in ver:
        out("WARNING: verified against near-cli-rs 0.30.1; yours differs. Do NOT upgrade; tell the assistant.")
    ok = ver_status == "ok"
    for name, argv in (("faucet account creation", create), ("deploy + init call", deploy)):
        status, tail = run_cli(runner, argv + ["--help"], 30)
        out("%-4s %s" % ("OK" if status == "ok" else "FAIL", name))
        ok = ok and status == "ok"
    out("syntax check %s (parse only: it cannot show that a command succeeds)" % ("PASSED" if ok else "FAILED"))
    return EXIT_OK if ok else EXIT_REFUSED


def stage_prepare(a, out, **_):
    guard(a)
    store = os.path.abspath(a.store)
    if os.path.exists(store) and os.listdir(store):
        raise Refuse("%s already has content: a fresh scope needs a fresh, empty store directory" % store)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        nlc.cmd_init(types.SimpleNamespace(store=store, writer=a.writer))
    init_args = json.loads(buf.getvalue())
    if init_args["scope_id"] == EVIDENCE_SCOPE_ID or init_args["genesis_digest"] == EVIDENCE_GENESIS_DIGEST:
        raise Refuse("generated scope/genesis equals the evidence deployment's (should be impossible): stop")
    with open(os.path.join(store, PLAN_FILE), "w") as f:
        json.dump({"contract": a.contract, "writer": a.writer, "init_args": init_args,
                   "wasm_sha256": EXPECTED_WASM_SHA256,
                   "note": "demo contract plan; separate from the evidence deployment"}, f, indent=2)
    out("fresh store created: %s" % store)
    out("  scope_id       %s   (evidence scope is %s)" % (init_args["scope_id"], EVIDENCE_SCOPE_ID))
    out("  genesis_digest %s" % init_args["genesis_digest"])
    out("  policy_digest  %s" % init_args["policy_digest"])
    out("next: create-account (dry run first)")
    return EXIT_OK


def stage_create(a, out, rpc=None, runner=subprocess.run, sleep=time.sleep, clock=time.monotonic, **_):
    wasm = guard(a)
    load_prepared(a)
    rpc = rpc or NearRpc(a.rpc)
    preflight_or_refuse(rpc)
    if account_state(rpc, a.contract) is not None:
        raise Refuse("%s already exists on testnet: nothing was sent. Inspect it before doing anything else." % a.contract)
    create, _ = build_argvs(a)
    need = required_yocto(len(wasm))
    out("account %s does not exist yet. Faucet command (argument list): %s" % (a.contract, subprocess.list2cmdline(create)))
    out("required balance for the deployment: at least %s" % near(need))
    prior = journal_unresolved(a.store, "create-account")
    if prior:
        out(prior_attempts_text(prior, "create-account"))
    if not need_execute(a):
        out("DRY RUN: nothing sent. To execute: add --execute --confirm %s" % a.contract)
        return EXIT_OK
    if prior and not a.acknowledge_ambiguous_attempt:
        raise Refuse("an earlier create-account attempt is unresolved (see above); the chain was just re-read and shows no account. "
                     "Nothing was sent. A further attempt must be deliberate: add --acknowledge-ambiguous-attempt.")
    idx = journal_start(a.store, "create-account")              # recorded BEFORE sending: a crash cannot hide the attempt
    out("EXECUTING exactly one faucet transaction ...")
    status, tail = run_cli(runner, create, a.timeout)
    out("near command: %s\n%s" % (status, tail))
    if status == "missing":
        journal_finish(a.store, idx, "not_sent", status, "n/a", tail)
        return EXIT_REFUSED
    st, reached = poll_account(rpc, a.contract, lambda s_: s_ is not None, sleep, clock)
    if not reached:
        journal_finish(a.store, idx, "ambiguous", status, "unreadable" if st == "unknown" else "account_not_found", tail)
        out("AMBIGUOUS: the CLI said '%s' and the chain does not (yet) show account %s (%s). A transaction may have been sent; a timeout, "
            "a crash or a non-zero exit does NOT prove it failed. STOP. Do not re-run anything: wait, then run `inspect` and look the "
            "account up on the explorer, and tell the assistant what you see." % (status, a.contract, "chain unreadable" if st == "unknown" else "account not found"))
        return EXIT_AMBIGUOUS
    journal_finish(a.store, idx, "confirmed", status, "account_found", tail)
    if status != "ok":
        out("NOTE: the CLI reported '%s' but the chain shows the account exists (the chain is authoritative)." % status)
    bal = int(st["amount"])
    out("account exists. balance %s; required %s" % (near(bal), near(need)))
    if bal < need:
        out("WARNING: balance is below the requirement: `deploy` will refuse. Do not deploy; tell the assistant.")
    return EXIT_OK


def stage_deploy(a, out, rpc=None, runner=subprocess.run, sleep=time.sleep, clock=time.monotonic, **_):
    wasm = guard(a)
    cfg, plan = load_prepared(a)
    rpc = rpc or NearRpc(a.rpc)
    preflight_or_refuse(rpc)
    st = account_state(rpc, a.contract)
    if st is None:
        raise Refuse("%s does not exist: run create-account first" % a.contract)
    need = required_yocto(len(wasm))
    if int(st["amount"]) < need:
        raise Refuse("balance %s is below the required %s: nothing was sent" % (near(st["amount"]), near(need)))
    if st.get("code_hash") != ZERO_CODE_HASH:
        raise Refuse("the account already has a contract (code_hash %s): never redeploy. Run `verify` instead." % st.get("code_hash"))
    expected_hash = code_hash_of(wasm)
    init_json = json.dumps(plan["init_args"], separators=(",", ":"))
    _, deploy = build_argvs(a, init_json=init_json)
    out("preconditions hold: account exists, balance %s >= %s, no contract yet, wasm verified (code_hash will be %s)" % (
        near(st["amount"]), near(need), expected_hash))
    out("init args: %s" % init_json)
    prior = journal_unresolved(a.store, "deploy")
    if prior:
        out(prior_attempts_text(prior, "deploy"))
    if not need_execute(a):
        out("DRY RUN: nothing sent. To execute: add --execute --confirm %s" % a.contract)
        return EXIT_OK
    if prior and not a.acknowledge_ambiguous_attempt:
        raise Refuse("an earlier deploy attempt is unresolved (see above); the chain was just re-read and shows no contract. "
                     "Nothing was sent. A further attempt must be deliberate: add --acknowledge-ambiguous-attempt.")
    idx = journal_start(a.store, "deploy")                      # recorded BEFORE sending
    out("EXECUTING exactly one deploy+init transaction (atomic) ...")
    status, tail = run_cli(runner, deploy, a.timeout)
    out("near command: %s\n%s" % (status, tail))
    if status == "missing":
        journal_finish(a.store, idx, "not_sent", status, "n/a", tail)
        return EXIT_REFUSED
    st2, reached = poll_account(rpc, a.contract, lambda s_: isinstance(s_, dict) and s_.get("code_hash") != ZERO_CODE_HASH, sleep, clock)
    if not reached:
        journal_finish(a.store, idx, "ambiguous", status, "unreadable" if st2 == "unknown" else "no_contract_visible", tail)
        out("AMBIGUOUS: the CLI said '%s' and the chain does not (yet) show a contract on %s (%s). A transaction may have been sent; a timeout, "
            "a crash or a non-zero exit does NOT prove it failed. STOP. Do NOT re-run `deploy` until you have run `inspect`, looked at the "
            "chain (explorer address page / transaction list) and told the assistant what you see." % (status, a.contract, "chain unreadable" if st2 == "unknown" else "no contract visible"))
        return EXIT_AMBIGUOUS
    journal_finish(a.store, idx, "confirmed", status, "contract_found", tail)
    got = st2.get("code_hash")
    if got != expected_hash:
        out("STOP: the account now has code_hash %s but the expected hash is %s. Do not continue; tell the assistant." % (got, expected_hash))
        return EXIT_REFUSED
    if status != "ok":
        out("NOTE: the CLI reported '%s' but the chain shows the verified wasm deployed (the chain is authoritative)." % status)
    try:
        head = chain_head.read_head(rpc, a.contract)
    except (NearRpcError, NearRpcUnavailable) as e:
        out("STOP: wasm is deployed but get_head could not be read (%s). Do not retry; run `verify` and tell the assistant." % type(e).__name__)
        return EXIT_AMBIGUOUS
    ia = plan["init_args"]
    ok = (head["version"] == 0 and head["digest"] == ia["genesis_digest"] and head["scope_id"] == ia["scope_id"]
          and head["policy_digest"] == ia["policy_digest"] and head["writer"] == a.writer)
    out("deployed. head read back: %s" % json.dumps(head))
    out("deployment %s. Next: `verify` (read-back through two independent paths). No browser until it passes." % ("CONFIRMED by the chain" if ok else "has an UNEXPECTED initial state: STOP"))
    return EXIT_OK if ok else EXIT_REFUSED


class _NoSend(TxSender):
    def send_cas(self, args):
        raise AssertionError("verify is read-only and must never sign or send")


def stage_verify(a, out, rpc=None, **_):
    wasm = guard(a)
    cfg, plan = load_prepared(a)
    rpc = rpc or NearRpc(a.rpc)
    results = []

    def check(name, cond, detail=""):
        results.append(bool(cond))
        out("%-4s %s %s" % ("PASS" if cond else "FAIL", name, detail))

    problems = preflight(rpc, expect_chain="testnet")
    check("testnet preflight (chain id, protocol version)", not problems, "; ".join(problems))
    if problems:
        return EXIT_REFUSED
    st = account_state(rpc, a.contract)
    check("account exists", st is not None)
    if st is None:
        return EXIT_REFUSED
    check("on-chain code_hash equals the verified wasm", st.get("code_hash") == code_hash_of(wasm), st.get("code_hash"))
    ia = plan["init_args"]
    # path 1: the Python adapter (store + chain), strictly read-only
    anchor = NearAnchor(rpc, a.contract, _NoSend(), DirRecordStore(a.store), WRITER_KEY, cfg["scope_id"], cfg["policy_digest"])
    try:
        rec = anchor.read()
        p1 = {"version": rec.header.version, "digest": rec.digest()}
        check("Python adapter read (store matches chain)", True, "version=%d digest=%s" % (p1["version"], p1["digest"]))
    except Exception as e:  # noqa: BLE001  (report, never guess)
        p1 = None
        check("Python adapter read (store matches chain)", False, type(e).__name__ + ": " + str(e)[:120])
    # path 2: the read-only chain-head reader (no store, no keys)
    buf = io.StringIO()
    rc = chain_head.main(["--contract", a.contract, "--rpc", a.rpc, "--json"], rpc=rpc, out=lambda s: buf.write(str(s) + "\n"))
    try:
        p2 = json.loads(buf.getvalue())["head"] if rc == 0 else None
    except ValueError:
        p2 = None
    check("read-only chain_head reader", p2 is not None, "" if p2 is None else "version=%s digest=%s" % (p2["version"], p2["digest"]))
    if p1 and p2:
        check("both paths agree", p1["version"] == p2["version"] and p1["digest"] == p2["digest"])
        check("version is %d" % a.expect_version, p1["version"] == a.expect_version, "(found %d)" % p1["version"])
        if a.expect_version == 0:
            check("head is the genesis of THIS store", p2["digest"] == ia["genesis_digest"])
        check("scope id matches the store", p2["scope_id"] == cfg["scope_id"] and cfg["scope_id"] != EVIDENCE_SCOPE_ID)
        check("policy digest matches the store", p2["policy_digest"] == cfg["policy_digest"])
        check("writer is %s" % a.writer, p2["writer"] == a.writer)
    ok = all(results) and len(results) >= 10
    out("\nREAD-BACK %s (%d/%d)" % ("PASSED" if ok else "FAILED", sum(results), len(results)))
    if ok and a.expect_version == 0:
        out("Only now: start the app (no --deploy-tx unless you copied the deployment transaction id from the deploy output):")
        out("  py -m app.server --anchor near --store %s --contract %s --writer %s [--deploy-tx <id>]" % (a.store, a.contract, a.writer))
    return EXIT_OK if ok else EXIT_REFUSED


def stage_inspect(a, out, rpc=None, **_):
    """Read-only: what does the chain say about the demo account right now, and what did earlier attempts record?"""
    wasm = guard(a)
    rpc = rpc or NearRpc(a.rpc)
    problems = preflight(rpc, expect_chain="testnet")
    out("network: %s" % ("OK (testnet, protocol ok)" if not problems else "PROBLEM: " + "; ".join(problems)))
    st = account_state(rpc, a.contract)
    if st is None:
        out("account %s: DOES NOT EXIST on the chain right now" % a.contract)
    else:
        ch = st.get("code_hash")
        out("account %s: EXISTS, balance %s, code_hash %s (%s)" % (a.contract, near(st["amount"]), ch,
            "no contract yet" if ch == ZERO_CODE_HASH else ("the verified wasm" if ch == code_hash_of(wasm) else "UNEXPECTED code")))
    out("explorer (read-only): https://testnet.nearblocks.io/address/%s" % a.contract)
    try:
        entries = journal_load(a.store) if os.path.isdir(a.store) else []
    except Refuse as e:
        entries = []
        out("journal problem: %s" % e)
    if not entries:
        out("attempt journal: no recorded attempts")
    for e in entries:
        out("attempt: %s started %s, outcome %s, cli_status %s, chain_after %s" % (e.get("stage"), e.get("started_utc"), e.get("outcome"), e.get("cli_status", "n/a"), e.get("chain_after", "n/a")))
    out("this stage sent nothing and wrote nothing.")
    return EXIT_OK


def stage_note_prior_attempt(a, out, **_):
    """OFFLINE: record an attempt that ran under an older version of this script (which kept no journal), so the safeguards
    know it happened. It adds an 'ambiguous' entry: the next `--execute` of that stage then needs --acknowledge-ambiguous-attempt."""
    guard(a)
    load_prepared(a)
    entries = journal_load(a.store)
    entries.append({"stage": a.note_stage, "started_utc": "unknown (before the journal existed; reported by the owner)",
                    "outcome": "ambiguous", "cli_status": "timeout (owner-reported)",
                    "chain_after": "account_not_found (owner lookups)" if a.note_stage == "create-account" else "no_contract_visible (owner lookups)",
                    "output_tail": sanitize(a.note)[:300]})
    journal_save(a.store, entries)
    out("recorded: an earlier %s attempt is now journaled as AMBIGUOUS. Nothing was sent; no network was used." % a.note_stage)
    out("the next `%s --execute` will refuse until you add --acknowledge-ambiguous-attempt (and the chain is re-read first)." % a.note_stage)
    return EXIT_OK


STAGES = {"plan": stage_plan, "syntax": stage_syntax, "prepare": stage_prepare, "create-account": stage_create,
          "deploy": stage_deploy, "verify": stage_verify, "inspect": stage_inspect,
          "note-prior-attempt": stage_note_prior_attempt}


def parse_args(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("stage", choices=sorted(STAGES, key=list(STAGES).index))
    ap.add_argument("--contract", default="bbdemo-teedor.testnet")
    ap.add_argument("--writer", default="teedor.testnet")
    ap.add_argument("--store", default="bbstore-demo")
    ap.add_argument("--rpc", default="https://test.rpc.fastnear.com")
    ap.add_argument("--near-cli", default="near")
    ap.add_argument("--execute", action="store_true", help="actually send the single transaction of a mutating stage")
    ap.add_argument("--confirm", default="", help="must equal --contract when --execute is given")
    ap.add_argument("--expect-version", type=int, default=0, help="verify: the chain version you expect")
    ap.add_argument("--note-stage", choices=("create-account", "deploy"), default="create-account",
                    help="note-prior-attempt: which stage's earlier (unjournaled) attempt to record")
    ap.add_argument("--note", default="recorded by the owner", help="note-prior-attempt: free text (sanitised)")
    ap.add_argument("--acknowledge-ambiguous-attempt", action="store_true",
                    help="allow a further attempt of a stage whose earlier attempt is unresolved (ambiguous or interrupted)")
    ap.add_argument("--timeout", type=float, default=180.0, help="seconds to wait for the near command")
    return ap.parse_args(argv)


def safe_print(text):
    """print() that cannot raise UnicodeEncodeError on a narrow console code page (e.g. cp1252)."""
    try:
        print(text)
    except UnicodeEncodeError:
        print(str(text).encode("ascii", "backslashreplace").decode("ascii"))


def main(argv=None, out=safe_print, **inject):
    a = parse_args(argv)
    try:
        return STAGES[a.stage](a, out, **inject)
    except Refuse as e:
        out("REFUSED (nothing was sent): %s" % e)
        return EXIT_REFUSED
    except (NearRpcUnavailable, NearRpcError) as e:
        out("NEAR RPC problem (%s): no transaction was sent by this check; do not retry blindly." % type(e).__name__)
        return EXIT_AMBIGUOUS


if __name__ == "__main__":
    sys.exit(main())
