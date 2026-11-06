from . import credential as cred
from .policy import Policy
from .anchor import SimulatedAnchor
from .gate import Gate, Store, make_genesis

ISSUER_KEY = b"test-issuer-key-NOT-A-SECRET"
VERIFIER_KEYS = {"V1": b"k1", "V2": b"k2", "V3": b"k3"}
SECRET_USD = 83_250                        
POLICY = Policy(lo=0, hi=999_999, min_width=10_000, per_verifier_bits=3.0)

def build(secret=SECRET_USD, policy=POLICY):
    c = cred.issue(ISSUER_KEY, secret)
    g0 = make_genesis(c, policy)
    anchor, store = SimulatedAnchor(g0), Store(g0)
    gate = Gate(ISSUER_KEY, c, policy, anchor, store, VERIFIER_KEYS)
    return gate, anchor, store

def ask(gate, vid, rid, t, **kw):
    return gate.request(vid, rid, t, Gate.auth_tag(VERIFIER_KEYS[vid], vid, rid, t), **kw)
