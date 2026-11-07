import threading

from core.interfaces import Anchor, AnchorUnavailable, CasResult


class SimulatedCrash(Exception):
    """Injected process crash (propagates out of the Gate, which does not catch it)."""


class LocalTestAnchor(Anchor):
    def __init__(self, genesis, writer_key, history_limit=256):
        self._lock = threading.RLock()
        self._records = {0: genesis}
        self._head = 0
        self._writer_key = writer_key
        self._limit = history_limit
        self._cas_fault = None      
        self._read_fault = None     
        self.cas_calls = 0
        self.read_calls = 0

    # ---- fault injection (tests only) ----
    def inject_cas_fault(self, kind, after=None):
        """kind: unavailable | unknown_applied | unknown_not_applied | crash_before_apply | crash_after_apply"""
        self._cas_fault = (kind, after)

    def inject_read_fault(self, kind, version=None):
        self._read_fault = (kind, version)

    # ---- inspection ----
    @property
    def version(self):
        with self._lock:
            return self._head

    def record_at(self, version):
        with self._lock:
            return self._records[version]

    def history(self):
        with self._lock:
            return [self._records[v] for v in sorted(self._records)]

    # ---- Anchor API ----
    def read(self):
        with self._lock:
            self.read_calls += 1
            f, self._read_fault = self._read_fault, None
            if f is not None:
                if f[0] == "unavailable":
                    raise AnchorUnavailable()
                if f[0] == "stale":
                    return self._records[f[1]]
            return self._records[self._head]

    def _apply(self, writer_key, expected_version, expected_digest, new):
        if writer_key != self._writer_key:
            return CasResult.UNAUTHORIZED
        cur = self._records[self._head]
        if (new.header.version != expected_version + 1 or new.header.prev_digest != expected_digest
                or new.header.scope_id != cur.header.scope_id
                or new.header.policy_digest != cur.header.policy_digest):
            return CasResult.MALFORMED
        if cur.header.version != expected_version or cur.digest() != expected_digest:
            return CasResult.CONFLICT
        self._head = new.header.version
        self._records[self._head] = new
        for v in [v for v in self._records if v < self._head - self._limit]:
            del self._records[v]
        return CasResult.COMMITTED

    def compare_and_swap(self, writer_key, expected_version, expected_digest, new_record):
        with self._lock:
            self.cas_calls += 1
            f, self._cas_fault = self._cas_fault, None
            kind, after = f if f else (None, None)
            if kind == "unavailable":
                raise AnchorUnavailable()                
            if kind == "crash_before_apply":
                raise SimulatedCrash()
            if kind == "unknown_not_applied":
                return CasResult.UNKNOWN
            res = self._apply(writer_key, expected_version, expected_digest, new_record)
            if kind in ("unknown_applied", "crash_after_apply"):
                if after is not None:
                    after()
                if kind == "crash_after_apply":
                    raise SimulatedCrash()
                return CasResult.UNKNOWN if res is CasResult.COMMITTED else res
            return res

    def _violate_revert_to(self, version):
        """ASSUMPTION VIOLATION (A4): revert committed history. Used only by T-R02."""
        with self._lock:
            self._head = version
            for v in [v for v in self._records if v > version]:
                del self._records[v]
