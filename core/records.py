import hashlib
import json
from dataclasses import dataclass, field
from typing import Dict, Optional

from core.policy import Interval, Policy

STATE_LEN = 2048        
MIN_BLINDING_BYTES = 32 
ZERO64 = "0" * 64


def _lp(b: bytes) -> bytes:
    return len(b).to_bytes(4, "big") + b


def policy_digest(p: Policy) -> str:
    body = json.dumps([p.lo, p.hi, p.W, p.K, p.R], separators=(",", ":")).encode()
    return hashlib.sha256(b"bitbudget/policy/v1\x00" + body).hexdigest()


def request_digest(scope_id: str, verifier_id: str, nonce: int, threshold: int,
                   pol_digest: str, blinding: bytes) -> str:
    h = hashlib.sha256(b"bitbudget/request/v1\x00")
    for part in (scope_id.encode(), verifier_id.encode(), str(nonce).encode(),
                 str(threshold).encode(), pol_digest.encode(), bytes(blinding)):
        h.update(_lp(part))
    return h.hexdigest()


def status_commitment(status_code: str, gamma: bytes) -> str:
    return hashlib.sha256(b"bitbudget/status/v1\x00" + _lp(status_code.encode()) + _lp(gamma)).hexdigest()


@dataclass(frozen=True)
class Request:
    scope_id: str
    verifier_id: str
    nonce: int
    threshold: int
    policy_digest: str
    blinding: bytes = field(repr=False)     
    auth_tag: str = field(repr=False)

    def digest(self) -> str:
        return request_digest(self.scope_id, self.verifier_id, self.nonce, self.threshold,
                              self.policy_digest, self.blinding)


@dataclass(frozen=True)
class Response:
    kind: str                      
    answer: Optional[bool] = None

    @staticmethod
    def answered(a: bool): return Response("ANSWER", bool(a))
    @staticmethod
    def refused(): return Response("REFUSED")
    @staticmethod
    def rejected(): return Response("REJECTED")
    @staticmethod
    def retry(): return Response("RETRY")

    def encode(self) -> bytes:
        if self.kind == "ANSWER":
            return b"ANSWER:1" if self.answer else b"ANSWER:0"
        return self.kind.encode()


@dataclass
class VerifierState:
    last_nonce: int = 0
    last_digest: str = ""
    informative: int = 0
    requests: int = 0
    last_response: str = ""       
    last_gamma: str = ""


@dataclass
class State:
    scope_id: str
    policy_digest: str
    lo: int
    hi: int
    verifiers: Dict[str, VerifierState] = field(default_factory=dict)

    @property
    def interval(self) -> Interval:
        return Interval(self.lo, self.hi)

    def to_bytes(self) -> bytes:
        obj = {"scope": self.scope_id, "pol": self.policy_digest, "lo": self.lo, "hi": self.hi,
               "v": {k: [v.last_nonce, v.last_digest, v.informative, v.requests, v.last_response, v.last_gamma]
                     for k, v in sorted(self.verifiers.items())}}
        raw = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
        if len(raw) > STATE_LEN:
            raise ValueError("state exceeds STATE_LEN")
        return raw.ljust(STATE_LEN, b"\x00")

    @staticmethod
    def from_bytes(b: bytes) -> "State":
        obj = json.loads(b.rstrip(b"\x00").decode())
        vs = {k: VerifierState(*v) for k, v in obj["v"].items()}
        return State(obj["scope"], obj["pol"], obj["lo"], obj["hi"], vs)


@dataclass(frozen=True)
class Header:
    scope_id: str
    version: int
    prev_digest: str
    verifier_id: str
    nonce: int
    request_digest: str
    status_commitment: str
    policy_digest: str


@dataclass(frozen=True)
class Record:
    header: Header
    sealed_state: bytes

    def encode(self) -> bytes:
        h = self.header
        head = "|".join([h.scope_id.ljust(32), "%012d" % h.version, h.prev_digest, h.verifier_id.ljust(16),
                         "%012d" % h.nonce, h.request_digest, h.status_commitment, h.policy_digest])
        return head.encode() + self.sealed_state

    def digest(self) -> str:
        return hashlib.sha256(b"bitbudget/record/v1\x00" + self.encode()).hexdigest()


def make_genesis(scope_id: str, policy: Policy, verifier_ids, sealer) -> Record:
    pd = policy_digest(policy)
    st = State(scope_id, pd, policy.lo, policy.hi, {v: VerifierState() for v in verifier_ids})
    hdr = Header(scope_id, 0, ZERO64, "", 0, ZERO64, ZERO64, pd)
    return Record(hdr, sealer.seal(st.to_bytes()))
