from dataclasses import dataclass
from typing import Optional

from core.records import Response
from harness.system import Client


@dataclass
class ClientResult:
    status: str                       
    response: Optional[Response]
    attempts: int
    note: str = ""
    expected_nonce: Optional[int] = None


class AnchorObserver:
    """Reads PUBLIC headers only. Requires an append-only public history (the local test double provides one;
    whether a real anchor does is UNVERIFIED). `complete` is True only if the history reaches version 0."""
    def __init__(self, anchor):
        self.anchor = anchor

    def view(self, verifier_id):
        recs = self.anchor.history()
        complete = bool(recs) and recs[0].header.version == 0
        mine = [(r.header.nonce, r.header.request_digest) for r in recs
                if r.header.version > 0 and r.header.verifier_id == verifier_id]
        return complete, mine


class PolicyClient:
    def __init__(self, system, verifier_id, observer=None, max_attempts=4):
        self.s, self.vid, self.max = system, verifier_id, max_attempts
        self.obs = observer or AnchorObserver(system.anchor)
        self.nonce, self.pending = 1, None
        self._mk = Client(system, verifier_id)

    # --- public API ---
    def ask(self, t, gate=None):
        if self.pending is not None:
            return ClientResult("PENDING", None, 0, "unresolved request outstanding: resolve_pending() or abandon_pending()")
        self.pending = self._mk.make(t, nonce=self.nonce)
        return self._drive(gate)

    def resolve_pending(self, gate=None):
        return self._drive(gate)

    def abandon_pending(self):
        """Only on authoritative PUBLIC evidence that no request ever committed at this nonce."""
        complete, mine = self.obs.view(self.vid)
        if self.pending is None or not complete or any(n == self.pending.nonce for n, _ in mine):
            return False
        self.pending = None
        return True

    def resync(self):
        """Set the next nonce from complete public history; refuses on incomplete evidence."""
        complete, mine = self.obs.view(self.vid)
        if not complete or self.pending is not None:
            return False
        self.nonce = (max((n for n, _ in mine), default=0)) + 1
        return True

    # --- core loop ---
    def _drive(self, gate):
        g, req = gate or self.s.gate, self.pending
        d, attempts, resp = req.digest(), 0, None
        while attempts < self.max:
            attempts += 1
            resp = g.handle(req)                        
            if resp.kind in ("ANSWER", "REFUSED"):       
                self.pending, self.nonce = None, req.nonce + 1
                return ClientResult(resp.kind, resp, attempts)
            if resp.kind == "RETRY":                    
                continue
            complete, mine = self.obs.view(self.vid)     
            if any(n == req.nonce and dd == d for n, dd in mine):
                continue                               
            nxt = (max((n for n, _ in mine), default=0) + 1) if complete else None
            if any(n == req.nonce and dd != d for n, dd in mine):
                self.pending = None
                return ClientResult("CONFLICT", resp, attempts, "nonce already used by a different committed request", nxt)
            if complete and nxt != req.nonce:
                self.pending = None
                return ClientResult("INVALID_NONCE", resp, attempts, "nonce is not the next unused nonce", nxt)
        return ClientResult("UNRESOLVED", resp, attempts,
                            "rejected after bounded retries; cause (stale read, auth, scope, quota) not distinguishable")
