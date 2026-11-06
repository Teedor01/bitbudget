from dataclasses import dataclass
from enum import Enum
from typing import Optional, Tuple


def _is_int(x) -> bool:
    return isinstance(x, int) and not isinstance(x, bool)


class Kind(Enum):
    DETERMINED = "DETERMINED"
    INFORMATIVE = "INFORMATIVE"
    REFUSED = "REFUSED"


class Reason(Enum):  
    NONE = "NONE"
    FLOOR = "FLOOR"
    CAP = "CAP"


@dataclass(frozen=True)
class Interval:
    lo: int
    hi: int

    def __post_init__(self):
        if not (_is_int(self.lo) and _is_int(self.hi)) or self.lo > self.hi:
            raise ValueError("interval needs integers with lo <= hi")

    @property
    def size(self) -> int:
        return self.hi - self.lo + 1


@dataclass(frozen=True)
class Policy:
    lo: int
    hi: int
    W: int                    
    K: Optional[int] = None   
    R: Optional[int] = None  

    def __post_init__(self):
        for x in (self.lo, self.hi, self.W):
            if not _is_int(x):
                raise ValueError("policy parameters must be integers")
        for x in (self.K, self.R):
            if x is not None and (not _is_int(x) or x < 1):
                raise ValueError("K and R must be None or integers >= 1")
        if self.W < 1 or self.lo > self.hi or (self.hi - self.lo + 1) < 2 * self.W:
            raise ValueError("need W >= 1 and domain size >= 2W")

    @property
    def domain(self) -> Interval:
        return Interval(self.lo, self.hi)


@dataclass(frozen=True)
class Decision:
    kind: Kind
    reason: Reason
    forced_answer: Optional[bool]  


def branches(iv: Interval, t: int) -> Tuple[Optional[Interval], Optional[Interval]]:
    """(YES branch for 'v > t', NO branch for 'v <= t'); None when impossible."""
    yes = Interval(max(iv.lo, t + 1), iv.hi) if t < iv.hi else None
    no = Interval(iv.lo, min(iv.hi, t)) if t >= iv.lo else None
    return yes, no


def decide(policy: Policy, iv: Interval, t: int, informative_count: int = 0) -> Decision:
    if not _is_int(t) or not _is_int(informative_count):
        raise TypeError("threshold and counters must be integers")
    yes, no = branches(iv, t)
    if yes is None:
        return Decision(Kind.DETERMINED, Reason.NONE, False)
    if no is None:
        return Decision(Kind.DETERMINED, Reason.NONE, True)
    if yes.size < policy.W or no.size < policy.W:
        return Decision(Kind.REFUSED, Reason.FLOOR, None)
    if policy.K is not None and informative_count >= policy.K:
        return Decision(Kind.REFUSED, Reason.CAP, None)
    return Decision(Kind.INFORMATIVE, Reason.NONE, None)


def quota_exceeded(policy: Policy, request_count: int) -> bool:
    if not _is_int(request_count):
        raise TypeError("request_count must be an integer")
    return policy.R is not None and request_count >= policy.R


def advance(iv: Interval, t: int, answer: bool) -> Interval:
    yes, no = branches(iv, t)
    chosen = yes if answer else no
    if chosen is None:
        raise ValueError("answer inconsistent with the feasible interval")
    return chosen
