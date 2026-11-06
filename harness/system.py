import secrets
from dataclasses import dataclass

from core.gate import Gate
from core.policy import Policy
from core.records import Request, Response, make_genesis, policy_digest, State
from testdoubles.hmac_auth import HmacTestAuthenticator
from testdoubles.local_anchor import LocalTestAnchor
from testdoubles.mock_credential import MockCredential
from testdoubles.test_sealer import UnsealedTestSealer

DEMO_POLICY = Policy(lo=0, hi=999_999, W=10_000)          
FIXTURE_SECRET = 83_250                                   
WRITER_KEY = "test-writer-key"


class Client:
    """A verifier client: strict sequential nonces, fresh random blinding per new request."""
    def __init__(self, system, verifier_id):
        self.s, self.vid, self.nonce = system, verifier_id, 1

    def make(self, t, nonce=None, blinding=None):
        n = self.nonce if nonce is None else nonce
        b = secrets.token_bytes(32) if blinding is None else blinding
        req = Request(self.s.scope_id, self.vid, n, t, self.s.pd, b, "")
        return Request(req.scope_id, req.verifier_id, req.nonce, req.threshold, req.policy_digest,
                       req.blinding, self.s.auth.tag(self.vid, req.digest()))

    def ask(self, t, gate=None, retries=5):
        """Send, retrying the SAME request on RETRY. Advances the nonce after a processed request."""
        g = gate or self.s.gate
        req = self.make(t)
        for _ in range(retries):
            resp = g.handle(req)
            if resp.kind in ("ANSWER", "REFUSED"):
                self.nonce += 1
                return resp
            if resp.kind == "REJECTED":
                return resp
        return resp


@dataclass
class System:
    policy: Policy
    scope_id: str
    pd: str
    anchor: LocalTestAnchor
    sealer: UnsealedTestSealer
    auth: HmacTestAuthenticator
    gate: Gate
    secret: int
    verifier_ids: tuple

    def new_gate(self, **kw):
        return Gate(self.policy, self.scope_id, self.secret, self.anchor, self.sealer, self.auth, WRITER_KEY)

    def client(self, vid):
        return Client(self, vid)

    def state(self) -> State:
        """Auditor view of the authoritative state (works only because the local sealer is a test double)."""
        return State.from_bytes(self.sealer.unseal(self.anchor.read().sealed_state))


def build_system(policy=DEMO_POLICY, secret=FIXTURE_SECRET, verifier_ids=("V1", "V2", "V3"),
                 anchor_cls=LocalTestAnchor, history_limit=256, scope_id=None) -> System:
    cred = MockCredential.new(secret) if scope_id is None else MockCredential(scope_id, secret)
    sealer = UnsealedTestSealer()
    keys = {v: ("key-" + v).encode() for v in verifier_ids}
    auth = HmacTestAuthenticator(keys)
    genesis = make_genesis(cred.scope_id, policy, verifier_ids, sealer)
    anchor = anchor_cls(genesis, WRITER_KEY, history_limit=history_limit)
    sysobj = System(policy, cred.scope_id, policy_digest(policy), anchor, sealer, auth, None, secret,
                    tuple(verifier_ids))
    sysobj.gate = sysobj.new_gate()
    return sysobj
