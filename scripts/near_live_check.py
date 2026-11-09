import argparse
import json
import os
import sys
import types

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from core.gate import Gate                                   
from core.interfaces import AnchorUnavailable, GateConfigError   
from core.policy import Policy                                
from core.records import make_genesis, policy_digest          
from harness.system import DEMO_POLICY, FIXTURE_SECRET, WRITER_KEY, Client   
from core.interfaces import CasResult                         
from core.records import Header, Record                        
from integrations.near_anchor import NearAnchor, NearCliSender, TxSender, preflight   
from integrations.near_rpc import NearRpc                     
from integrations.record_store import DirRecordStore           
from testdoubles.hmac_auth import HmacTestAuthenticator       
from testdoubles.mock_credential import MockCredential         
from testdoubles.test_sealer import UnsealedTestSealer        

VERIFIERS = ("V1", "V2", "V3")
DEFAULT_RPC = "https://test.rpc.fastnear.com"
CFG = "config.json"


def load(args):
    with open(os.path.join(args.store, CFG)) as f:
        return json.load(f)


def cmd_init(a):
    os.makedirs(a.store, exist_ok=True)
    if os.path.exists(os.path.join(a.store, CFG)):
        sys.exit("refusing to re-initialise: %s already exists. A new genesis would not match an already deployed "
                 "contract. Use a new --store directory (and redeploy) for a fresh start." % os.path.join(a.store, CFG))
    cred = MockCredential.new(FIXTURE_SECRET)
    genesis = make_genesis(cred.scope_id, DEMO_POLICY, VERIFIERS, UnsealedTestSealer())
    DirRecordStore(a.store).put(genesis)
    with open(os.path.join(a.store, CFG), "w") as f:
        json.dump({"scope_id": cred.scope_id, "policy_digest": policy_digest(DEMO_POLICY)}, f)
    print(json.dumps(NearAnchor.init_args(a.writer, genesis)))


def anchor_for(a, sender=None):
    cfg = load(a)
    return NearAnchor(NearRpc(a.rpc), a.contract, sender, DirRecordStore(a.store), WRITER_KEY,
                      cfg["scope_id"], cfg["policy_digest"], confirm_timeout=a.confirm_timeout), cfg


def cmd_read(a):
    anchor, _ = anchor_for(a)
    rec = anchor.read()
    print("chain head: version=%d digest=%s" % (rec.header.version, rec.digest()))


def cmd_run(a):
    sender = NearCliSender(a.contract, a.writer, network=a.network, sign_with=a.sign_with)
    anchor, cfg = anchor_for(a, sender)
    auth = HmacTestAuthenticator({v: ("key-" + v).encode() for v in VERIFIERS})
    gate = Gate(DEMO_POLICY, cfg["scope_id"], FIXTURE_SECRET, anchor, UnsealedTestSealer(), auth, WRITER_KEY)
    sysobj = types.SimpleNamespace(scope_id=cfg["scope_id"], pd=cfg["policy_digest"], auth=auth, gate=gate)
    start = anchor.read().header.version
    print("start version:", start)
    client = Client(sysobj, "V1")
    client.nonce = _next_nonce(anchor, "V1")
    for t in (499_999, 249_999, 124_999):
        r = client.ask(t, retries=3)
        print("threshold %7d -> %s %s | chain version now %d" % (t, r.kind, r.answer, anchor.read().header.version))


def _next_nonce(anchor, vid):
    from core.records import State
    st = State.from_bytes(UnsealedTestSealer().unseal(anchor.read().sealed_state))
    return st.verifiers[vid].last_nonce + 1


class WrapSender(TxSender):
    """Counts real broadcasts. mode: real | real_but_report_lost (broadcasts, then claims failure: a lost response)
    | never_send (claims failure without broadcasting)."""
    def __init__(self, inner, mode="real"):
        self.inner, self.mode, self.broadcasts = inner, mode, 0

    def send_cas(self, args):
        if self.mode == "never_send":
            return False
        self.broadcasts += 1
        ok = self.inner.send_cas(args)
        return False if self.mode == "real_but_report_lost" else ok


def cmd_preflight(a):
    problems = preflight(NearRpc(a.rpc), expect_chain=a.network)
    for p in problems:
        print("PROBLEM:", p)
    print("preflight:", "FAILED" if problems else "OK")
    if problems:
        sys.exit(1)


def cmd_selftest(a):
    ok = run_selftest(a, lambda: NearRpc(a.rpc), lambda acct: NearCliSender(a.contract, acct, network=a.network, sign_with=a.sign_with))
    sys.exit(0 if ok else 1)


def run_selftest(a, make_rpc, make_inner_sender, sleep=None, clock=None, out=print):
    """Each line is PASS/FAIL. Needs a deployed contract and funded writer (see NEAR_DEPLOY.md).
    make_rpc() -> NearRpc; make_inner_sender(account) -> TxSender that signs as `account`. Returns True if all passed."""
    import time as _t
    sleep, clock = sleep or _t.sleep, clock or _t.monotonic
    print = out                                                     # noqa: A001  (tests capture output)
    results = []

    def check(name, cond, detail=""):
        results.append(bool(cond))
        print("%-4s %s %s" % ("PASS" if cond else "FAIL", name, detail))

    problems = preflight(make_rpc(), expect_chain=a.network)
    check("preflight (chain id, protocol version)", not problems, "; ".join(problems))
    if problems:
        return False
    cfg = load(a)
    real = make_inner_sender(a.writer)
    auth = HmacTestAuthenticator({v: ("key-" + v).encode() for v in VERIFIERS})

    def mk(sender, timeout):
        an = NearAnchor(make_rpc(), a.contract, sender, DirRecordStore(a.store), WRITER_KEY, cfg["scope_id"],
                        cfg["policy_digest"], confirm_timeout=timeout, sleep=sleep, clock=clock)
        g = Gate(DEMO_POLICY, cfg["scope_id"], FIXTURE_SECRET, an, UnsealedTestSealer(), auth, WRITER_KEY)
        return an, g, types.SimpleNamespace(scope_id=cfg["scope_id"], pd=cfg["policy_digest"], auth=auth, gate=g)

    an, gate, sysobj = mk(real, a.confirm_timeout)
    v0 = an.read().header.version
    check("read head from chain", True, "version=%d" % v0)

    # successful writes through the Gate (V1)
    c1 = Client(sysobj, "V1"); c1.nonce = _next_nonce(an, "V1")
    for t in (499_999, 249_999):
        r = c1.ask(t, retries=3)
        check("successful write t=%d" % t, r.kind == "ANSWER" and r.answer is False, "-> %s %s" % (r.kind, r.answer))
    v1 = an.read().header.version
    check("chain advanced by exactly 2", v1 == v0 + 2, "%d -> %d" % (v0, v1))

    # stale compare-and-swap: a record built on the previous head
    head = an.read()
    prev = DirRecordStore(a.store).get(head.header.prev_digest)
    alt = Record(Header(prev.header.scope_id, prev.header.version + 1, prev.digest(), "V3", 99, "1" * 64, "2" * 64,
                        prev.header.policy_digest), prev.sealed_state)
    res = an.compare_and_swap(WRITER_KEY, prev.header.version, prev.digest(), alt)
    check("stale CAS is CONFLICT", res is CasResult.CONFLICT, res.value)
    check("head unchanged after stale CAS", an.read().digest() == head.digest())

    # unauthorized writer: signs as another account; the contract must refuse and the head must not move
    if a.other_signer:
        bad = WrapSender(make_inner_sender(a.other_signer))
        an_bad, _, _ = mk(bad, 8.0)
        nxt = Record(Header(head.header.scope_id, head.header.version + 1, head.digest(), "V3", 98, "3" * 64, "4" * 64,
                            head.header.policy_digest), head.sealed_state)
        res = an_bad.compare_and_swap(WRITER_KEY, head.header.version, head.digest(), nxt)
        check("unauthorized signer does not commit", an.read().digest() == head.digest() and res is CasResult.UNKNOWN,
              "%s, broadcasts=%d" % (res.value, bad.broadcasts))
    else:
        print("SKIP unauthorized-writer scenario (pass --other-signer with a second funded account)")

    # ambiguous outcome 1: transaction lands but the signer reports failure -> resolved by rereading, one broadcast
    s1 = WrapSender(real, "real_but_report_lost")
    _, g1, so1 = mk(s1, a.confirm_timeout)
    r = g1.handle(Client(so1, "V2").make(499_999))
    check("lost response: answer released only after reread confirms commit, 1 broadcast",
          r.kind == "ANSWER" and s1.broadcasts == 1, "-> %s, broadcasts=%d" % (r.kind, s1.broadcasts))

    # ambiguous outcome 2: nothing broadcast, signer reports failure -> RETRY, head unchanged, no answer
    s2 = WrapSender(real, "never_send")
    an2, g2, so2 = mk(s2, 8.0)
    before = an2.read().digest()
    r = g2.handle(Client(so2, "V3").make(499_999))
    check("failed write releases no answer, head unchanged", r.kind == "RETRY" and an2.read().digest() == before, "-> %s" % r.kind)

    ok = all(results)
    last = getattr(real, "last", None)
    if not ok and last:
        print("last near-cli-rs exit code %s; stderr tail: %s" % last)
    print("\nSELFTEST: %s (%d/%d)" % ("ALL PASSED" if ok else "FAILURES PRESENT", sum(results), len(results)))
    return ok


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("cmd", choices=("init", "run", "read", "preflight", "selftest"))
    p.add_argument("--store")
    p.add_argument("--contract")
    p.add_argument("--writer")
    p.add_argument("--other-signer", help="a second funded testnet account, used to test the unauthorized-writer path")
    p.add_argument("--rpc", default=DEFAULT_RPC)
    p.add_argument("--network", default="testnet")
    p.add_argument("--sign-with", default="keychain", choices=NearCliSender.SIGN_MODES,
                   help="near-cli-rs key storage: keychain (system) or legacy-keychain (files, works headless)")
    p.add_argument("--confirm-timeout", type=float, default=45.0)
    a = p.parse_args()
    if a.cmd != "preflight" and not a.store:
        p.error("--store is required")
    if a.cmd == "selftest" and not (a.contract and a.writer):
        p.error("selftest needs --contract and --writer")
    if a.cmd == "init" and not a.writer:
        p.error("init needs --writer")
    if a.cmd in ("run", "read", "selftest") and not a.contract:
        p.error("--contract required")
    if a.cmd == "run" and not a.writer:
        p.error("run needs --writer")
    try:
        {"init": cmd_init, "run": cmd_run, "read": cmd_read, "preflight": cmd_preflight, "selftest": cmd_selftest}[a.cmd](a)
    except AnchorUnavailable as e:
        sys.exit("NEAR unavailable (nothing was committed by this step): %s" % e)
    except GateConfigError as e:
        sys.exit("INTEGRITY/CONFIG ERROR, refusing to continue: %s" % e)


if __name__ == "__main__":
    main()
