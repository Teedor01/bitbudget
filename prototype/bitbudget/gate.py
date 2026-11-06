import hashlib, hmac, json, math, secrets, threading
from . import credential as cred
from .policy import Policy, decide, apply

def H(*parts) -> str:
    return hashlib.sha256(json.dumps(parts, sort_keys=True).encode()).hexdigest()

class Store:
    """Stands in for enclave-encrypted persistent storage. Encryption gives NO freshness, so the
    operator can restore an old copy: snapshot()/restore() model exactly that."""
    def __init__(self, genesis):
        self.entries, self.head, self.seq = [], genesis, 0
        self.iv, self.bits, self.pending = None, {}, None
    def snapshot(self): return json.dumps(self.__dict__, sort_keys=True)
    def restore(self, s):
        self.__dict__.clear(); d = json.loads(s)
        d["iv"] = tuple(d["iv"]) if d["iv"] else None
        self.__dict__.update(d)

def make_genesis(credential, policy):
    return H("genesis", secrets.token_hex(32), credential.cred_id, policy.digest())

class Gate:
    def __init__(self, issuer_key, credential, policy: Policy, anchor, store, verifier_keys):
        if not cred.verify(issuer_key, credential): raise ValueError("bad credential")
        if not (policy.lo <= credential.value <= policy.hi): raise ValueError("value outside domain")
        self._secret, self.cred_id = credential.value, credential.cred_id
        self.policy, self.anchor, self.store, self.vkeys = policy, anchor, store, verifier_keys
        self._lock = threading.Lock()
        if store.iv is None: store.iv = (policy.lo, policy.hi)

    @staticmethod
    def auth_tag(vkey: bytes, vid, rid, t):
        return hmac.new(vkey, f"{vid}|{rid}|{t}".encode(), hashlib.sha256).hexdigest()

    def recover(self):
        """Crash recovery from the write-ahead pending entry."""
        s = self.store
        if not s.pending: return "NOTHING"
        a_seq, a_head = self.anchor.read()
        if a_head == s.pending["head"]:       
            self._promote(); return "PROMOTED"
        if a_head == s.head:                  
            s.pending = None; return "DISCARDED"
        return "MISMATCH"

    def _promote(self):
        s, p = self.store, self.store.pending
        s.entries.append(p["entry"]); s.head, s.seq = p["head"], p["entry"]["seq"]
        s.iv = tuple(p["iv"]); s.bits[p["entry"]["verifier"]] = p["bits"]; s.pending = None

    def request(self, vid, rid, t, auth, _drop_response=False):
        with self._lock:
            s = self.store
            vk = self.vkeys.get(vid)
            if vk is None or not hmac.compare_digest(auth, self.auth_tag(vk, vid, rid, t)):
                return {"status": "REFUSED", "reason": "AUTH"}
            for e in s.entries:                              # idempotency / reuse
                if e["req"] == rid:
                    if e["verifier"] == vid and e["t"] == t:
                        return {"status": "ANSWERED", "answer": e["ans"], "replay": True}
                    return {"status": "REFUSED", "reason": "REQUEST_ID_REUSED"}
            if s.pending: return {"status": "REFUSED", "reason": "RECOVERY_REQUIRED"}
            a_seq, a_head = self.anchor.read()
            if (a_seq, a_head) != (s.seq, s.head):
                return {"status": "REFUSED", "reason": "STATE_MISMATCH"}   
            ok, why, cost = decide(self.policy, s.iv, t, s.bits.get(vid, 0.0))
            if not ok: return {"status": "REFUSED", "reason": why}
            ans = self._secret > t                           
            new_iv = apply(s.iv, t, ans)
            entry = {"seq": s.seq + 1, "prev": s.head, "req": rid, "verifier": vid, "t": t,
                     "ans": ans, "iv": list(new_iv), "pol": self.policy.digest(), "cred": self.cred_id}
            new_head = H(entry)
            s.pending = {"entry": entry, "head": new_head, "iv": list(new_iv),
                         "bits": s.bits.get(vid, 0.0) + cost}
            if not self.anchor.cas(s.seq, s.head, s.seq + 1, new_head):
                s.pending = None
                return {"status": "REFUSED", "reason": "COMMIT_FAILED_RETRY"}
            if _drop_response:                              
                return {"status": "LOST"}
            self._promote()
            return {"status": "ANSWERED", "answer": ans, "replay": False}
