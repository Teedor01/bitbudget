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
from integrations.near_anchor import NearAnchor, NearCliSender   
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
    sender = NearCliSender(a.contract, a.writer, network=a.network)
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


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("cmd", choices=("init", "run", "read"))
    p.add_argument("--store", required=True)
    p.add_argument("--contract")
    p.add_argument("--writer")
    p.add_argument("--rpc", default=DEFAULT_RPC)
    p.add_argument("--network", default="testnet")
    p.add_argument("--confirm-timeout", type=float, default=45.0)
    a = p.parse_args()
    if a.cmd == "init" and not a.writer:
        p.error("init needs --writer")
    if a.cmd in ("run", "read") and not a.contract:
        p.error("--contract required")
    if a.cmd == "run" and not a.writer:
        p.error("run needs --writer")
    try:
        {"init": cmd_init, "run": cmd_run, "read": cmd_read}[a.cmd](a)
    except AnchorUnavailable as e:
        sys.exit("NEAR unavailable (nothing was committed by this step): %s" % e)
    except GateConfigError as e:
        sys.exit("INTEGRITY/CONFIG ERROR, refusing to continue: %s" % e)


if __name__ == "__main__":
    main()
