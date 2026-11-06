import threading

class SimulatedAnchor:
    def __init__(self, genesis_hash: str):
        self._lock = threading.Lock()
        self.seq, self.head = 0, genesis_hash

    def read(self):
        with self._lock:
            return self.seq, self.head

    def cas(self, exp_seq, exp_head, new_seq, new_head) -> bool:
        with self._lock:
            if (self.seq, self.head) != (exp_seq, exp_head) or new_seq != exp_seq + 1:
                return False
            self.seq, self.head = new_seq, new_head
            return True
