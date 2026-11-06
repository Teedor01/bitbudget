from __future__ import annotations
import hashlib, json, math
from dataclasses import dataclass, asdict

@dataclass(frozen=True)
class Policy:
    lo: int                
    hi: int                 
    min_width: int          
    per_verifier_bits: float  
    version: str = "1"

    def __post_init__(self):
        if self.hi - self.lo + 1 < 2 * self.min_width:
            raise ValueError("domain must be at least twice the floor width")

    def digest(self) -> str:
        return hashlib.sha256(json.dumps(asdict(self), sort_keys=True).encode()).hexdigest()

def width(iv):
    return iv[1] - iv[0] + 1

def outcomes(iv, t):
    """Feasible intervals after answering YES (v > t) / NO (v <= t). None if impossible."""
    a, b = iv
    yes = (max(a, t + 1), b) if t + 1 <= b else None
    no = (a, min(b, t)) if t >= a else None
    return yes, no

def decide(policy: Policy, iv, t: int, verifier_bits_used: float):
    """Return (allowed, reason, worst_case_cost_bits). Pure function; no secret input."""
    yes, no = outcomes(iv, t)
    if yes is None or no is None:           
        return True, "DETERMINED", 0.0
    w0 = width(iv)
    for o in (yes, no):
        if width(o) < policy.min_width:
            return False, "FLOOR", 0.0
    cost = max(math.log2(w0 / width(o)) for o in (yes, no))   
    if verifier_bits_used + cost > policy.per_verifier_bits + 1e-12:
        return False, "ALLOCATION", cost
    return True, "OK", cost

def apply(iv, t, answer_yes: bool):
    yes, no = outcomes(iv, t)
    return yes if answer_yes else no
