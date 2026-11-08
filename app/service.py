import hmac
import math
import secrets
import threading
import time

from core.policy import Interval, Policy, decide, quota_exceeded
from harness.attackers import adaptive_attack, baseline_binary_search
from harness.system import build_system

DOMAIN_LO, DOMAIN_HI, FLOOR = 0, 999_999, 10_000     
VERIFIERS = ("V1", "V2", "V3")
MAX_SESSIONS = 100
MAX_LOG = 500
THRESHOLD_LIMIT = 10 ** 12
DEMO_SECRET = 120_000                                 
DEMO_THRESHOLDS = (500_000, 250_000, 125_000, 62_500, 93_750, 109_375, 117_187, 119_375)   
SIMULATION_NOTICE = ("LOCAL SIMULATION: mock credential, test-double anchor, non-cryptographic sealer. "
                     "No real identity or income verification, confidentiality, rollback resistance or attestation.")


class ApiError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status, self.message = status, message


def _int(value, name, lo=None, hi=None, allow_none=False):
    if value is None and allow_none:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ApiError(400, f"{name} must be an integer")
    if (lo is not None and value < lo) or (hi is not None and value > hi):
        raise ApiError(400, f"{name} must be between {lo} and {hi}")
    return value


def _iv(i: Interval):
    return {"lo": i.lo, "hi": i.hi, "size": i.size}


class _Session:
    def __init__(self, sid, policy, secret):
        self.id, self.policy, self.secret = sid, policy, secret
        self.owner_token = secrets.token_urlsafe(16)          
        self.system = build_system(policy, secret=secret, verifier_ids=VERIFIERS, history_limit=64)
        self.clients = {v: self.system.client(v) for v in VERIFIERS}
        self.lock = threading.Lock()
        self.log, self.created = [], time.time()


class Service:
    def __init__(self):
        self._sessions, self._lock = {}, threading.Lock()

    # ---- sessions ----
    def create_session(self, body):
        income = _int(body.get("income_usd"), "income_usd", DOMAIN_LO, DOMAIN_HI)
        K = _int(body.get("K"), "K", 1, 10 ** 6, allow_none=True)
        R = _int(body.get("R"), "R", 1, 10 ** 6, allow_none=True)
        policy = Policy(DOMAIN_LO, DOMAIN_HI, FLOOR, K=K, R=R)
        sid = secrets.token_urlsafe(9)
        with self._lock:
            if len(self._sessions) >= MAX_SESSIONS:
                self._sessions.pop(next(iter(self._sessions)))
            self._sessions[sid] = _Session(sid, policy, income)
        return {"session_id": sid, "owner_token": self._sessions[sid].owner_token, "notice": SIMULATION_NOTICE,
                "verifiers": list(VERIFIERS),
                "policy": {"lo": policy.lo, "hi": policy.hi, "floor": policy.W, "K": policy.K, "R": policy.R}}

    def _get(self, sid):
        with self._lock:
            s = self._sessions.get(sid)
        if s is None:
            raise ApiError(404, "unknown session")
        return s

    def _owner(self, sid, token):
        s = self._get(sid)
        if not isinstance(token, str) or not hmac.compare_digest(token.encode(), s.owner_token.encode()):
            raise ApiError(403, "owner token required")
        return s

    # ---- the vertical slice: threshold query -> real policy -> real gate ----
    def query(self, sid, body):
        """VERIFIER-FACING. Returns only what a verifier may see: its own query and the gate's response."""
        s = self._get(sid)
        vid = body.get("verifier_id")
        if vid not in VERIFIERS:
            raise ApiError(400, "verifier_id must be one of " + ", ".join(VERIFIERS))
        t = _int(body.get("threshold"), "threshold", -THRESHOLD_LIMIT, THRESHOLD_LIMIT)
        with s.lock:
            e = self._execute(s, vid, t)
        return {"verifier_id": vid, "threshold": t,
                "response": e["verifier_view"]["response"], "answer": e["verifier_view"]["answer"]}

    def _execute(self, s, vid, t):
        """Run one query through the real policy and gate. Caller holds s.lock. Returns the FULL (owner/auditor) entry."""
        sys_ = s.system
        st0 = sys_.state()                                  
        iv0, vs0, ver0 = st0.interval, st0.verifiers[vid], sys_.anchor.version
        quota = quota_exceeded(s.policy, vs0.requests)
        dec = decide(s.policy, iv0, t, vs0.informative)      
        resp = s.clients[vid].ask(t)                         
        st1, ver1 = sys_.state(), sys_.anchor.version
        expected = "REJECTED" if quota else ("REFUSED" if dec.kind.value == "REFUSED" else "ANSWER")
        consistent = resp.kind == expected and (resp.kind != "ANSWER" or resp.answer == (s.secret > t))
        decision = "QUOTA_EXHAUSTED" if quota else dec.kind.value
        reason = "R quota" if quota else (dec.reason.value if dec.reason.value != "NONE" else "-")
        entry = {
            "n": len(s.log) + 1, "verifier_id": vid, "threshold": t,
            "verifier_view": {"response": resp.kind, "answer": resp.answer if resp.kind == "ANSWER" else None},
            "auditor_view": {"policy_decision": decision, "reason": reason,
                             "feasible_before": _iv(iv0), "feasible_after": _iv(st1.interval),
                             "anchor_version_before": ver0, "anchor_version_after": ver1,
                             "committed": ver1 == ver0 + 1, "consistent_with_policy": consistent},
        }
        s.log.append(entry)
        del s.log[:-MAX_LOG]
        return entry

    def owner_view(self, sid, token):
        s = self._owner(sid, token)
        with s.lock:
            st, n = s.system.state(), DOMAIN_HI - DOMAIN_LO + 1
            hist = s.system.anchor.history()[-30:]
            return {
                "session_id": s.id, "notice": SIMULATION_NOTICE,
                "owner_secret_usd": s.secret,                      
                "feasible": _iv(st.interval), "floor": s.policy.W,
                "floor_holds": st.interval.size >= s.policy.W,
                "advantage_bits_display_only": round(math.log2(n / st.interval.size), 2),   
                "anchor_version": s.system.anchor.version,
                "verifiers": {v: {"informative_answers": x.informative, "committed_requests": x.requests,
                                  "last_nonce": x.last_nonce} for v, x in st.verifiers.items()},
                "transitions": [{"version": r.header.version, "verifier_id": r.header.verifier_id,
                                 "nonce": r.header.nonce, "request_digest": r.header.request_digest[:16],
                                 "status_commitment": r.header.status_commitment[:16]} for r in hist if r.header.version > 0],
                "log": list(s.log),
            }

    # ---- adversarial demo on a SHADOW session (does not touch the interactive one) ----
    def attack(self, sid, token, body):
        s = self._owner(sid, token)
        strategy = body.get("strategy", "squeeze")
        if strategy not in ("binary", "squeeze"):
            raise ApiError(400, "strategy must be 'binary' or 'squeeze'")
        shadow = build_system(s.policy, secret=s.secret, verifier_ids=VERIFIERS, history_limit=8)
        clients, steps = [shadow.client(v) for v in VERIFIERS], []

        def q(t):
            c = clients[len(steps) % len(clients)]
            r = c.ask(t)
            steps.append({"n": len(steps) + 1, "verifier_id": c.vid, "threshold": t, "response": r.kind,
                          "answer": r.answer, "feasible_after": _iv(shadow.state().interval)})
            return r.answer if r.kind == "ANSWER" else None

        class _R:  
            def randint(self, a, b): return (a + b) // 2
        (a, b), answers = adaptive_attack(q, s.policy.lo, s.policy.hi, s.policy.W, _R(), strategy, max_queries=300)
        value, n_base = baseline_binary_search(s.secret, s.policy.lo, s.policy.hi)
        gi = shadow.state().interval
        return {"notice": SIMULATION_NOTICE,
                "baseline_stateless": {"recovered_usd": value, "queries": n_base, "secret_recovered": value == s.secret},
                "gated": {"strategy": strategy, "answers_obtained": answers, "requests_sent": len(steps),
                          "attacker_feasible": {"lo": a, "hi": b, "size": b - a + 1},
                          "gate_feasible": _iv(gi), "floor": s.policy.W,
                          "floor_held": gi.size >= s.policy.W and b - a + 1 >= s.policy.W,
                          "secret_recovered": a == b},
                "steps": steps[:150]}

    # ---- the product story: fixed public demo secret, deterministic sequence, numbers straight from the engine ----
    def demo_story(self):
        n = DOMAIN_HI - DOMAIN_LO + 1
        a, b, open_steps = DOMAIN_LO, DOMAIN_HI, []
        while a < b:
            t = (a + b) // 2
            a, b = (t + 1, b) if DEMO_SECRET > t else (a, t)
            open_steps.append({"threshold": t, "candidates": b - a + 1})
        recovered, queries = baseline_binary_search(DEMO_SECRET, DOMAIN_LO, DOMAIN_HI)
        s = _Session("demo", Policy(DOMAIN_LO, DOMAIN_HI, FLOOR), DEMO_SECRET)
        steps, first_refusal = [], None
        for i, t in enumerate(DEMO_THRESHOLDS):
            vid = VERIFIERS[i % len(VERIFIERS)]
            with s.lock:
                e = self._execute(s, vid, t)
            a_ = e["auditor_view"]
            if e["verifier_view"]["response"] == "REFUSED" and first_refusal is None:
                first_refusal = i + 1
            steps.append({"step": i + 1, "verifier_id": vid, "threshold": t,
                          "verifier_sees": e["verifier_view"]["response"] if e["verifier_view"]["answer"] is None
                          else ("YES" if e["verifier_view"]["answer"] else "NO"),
                          "candidates_before": a_["feasible_before"]["size"],
                          "candidates_after": a_["feasible_after"]["size"],
                          "consistent_with_policy": a_["consistent_with_policy"]})
        return {"notice": SIMULATION_NOTICE, "secret_usd": DEMO_SECRET, "domain_size": n, "floor": FLOOR,
                "unrestricted": {"queries": queries, "recovered_usd": recovered, "secret_recovered": recovered == DEMO_SECRET,
                                 "steps": open_steps},
                "bit_budget": {"steps": steps, "first_refusal_step": first_refusal,
                               "final_candidates": steps[-1]["candidates_after"],
                               "floor_held": steps[-1]["candidates_after"] >= FLOOR,
                               "secret_recovered": steps[-1]["candidates_after"] == 1}}
