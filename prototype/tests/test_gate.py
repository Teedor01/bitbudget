import math, random, threading, unittest
from bitbudget.fixtures import build, ask, POLICY, SECRET_USD, ISSUER_KEY, VERIFIER_KEYS
from bitbudget.policy import decide, width
from bitbudget import credential as cred
from bitbudget.gate import Gate, Store, make_genesis
from bitbudget.anchor import SimulatedAnchor

class Core(unittest.TestCase):
    def test_baseline_recovers_exact_in_log2_queries(self):
        a, b, n = POLICY.lo, POLICY.hi, 0
        while a != b:
            t = (a + b) // 2; n += 1
            a, b = (t + 1, b) if SECRET_USD > t else (a, t)
        self.assertEqual(a, SECRET_USD); self.assertLessEqual(n, math.ceil(math.log2(POLICY.hi + 1)))

    def test_floor_holds_under_fuzzed_attacks(self):
        rng = random.Random(7)
        for trial in range(60):
            gate, _, store = build(secret=rng.randint(0, 999_999))
            for i in range(150):
                ask(gate, rng.choice(["V1", "V2", "V3"]), f"r{trial}-{i}", rng.randint(-5000, 1_005_000))
                self.assertGreaterEqual(width(store.iv), POLICY.min_width)

    def test_refusal_independent_of_secret(self):
        g1, _, s1 = build(secret=83_250); g2, _, s2 = build(secret=83_251)
        for i, t in enumerate([500_000, 250_000, 125_000, 83_250, 90_000, 85_000, 84_000]):
            r1, r2 = ask(g1, "V1", f"a{i}", t), ask(g2, "V1", f"a{i}", t)
            if s1.iv == s2.iv or r1["status"] == "REFUSED" or r2["status"] == "REFUSED":
                self.assertEqual(r1["status"], r2["status"], f"query {t}")
            if r1["status"] != "ANSWERED" or r2["status"] != "ANSWERED": break

    def test_allocation_enforced_per_verifier(self):
        gate, _, store = build(); res = []
        for i, t in enumerate([500_000, 250_000, 125_000, 60_000]):
            res.append(ask(gate, "V1", f"q{i}", t))
        self.assertTrue(any(r.get("reason") == "ALLOCATION" for r in res))
        self.assertGreaterEqual(width(store.iv), POLICY.min_width)

class StateIntegrity(unittest.TestCase):
    def test_1_replay_returns_same_answer_no_extra_charge(self):
        gate, anchor, store = build()
        r1 = ask(gate, "V1", "dup", 500_000); seq = anchor.seq; bits = dict(store.bits)
        r2 = ask(gate, "V1", "dup", 500_000)
        self.assertEqual(r1["answer"], r2["answer"]); self.assertTrue(r2["replay"])
        self.assertEqual((seq, bits), (anchor.seq, store.bits))

    def test_2_rollback_to_old_snapshot_refused(self):
        gate, anchor, store = build()
        ask(gate, "V1", "a", 500_000); snap = store.snapshot()
        ask(gate, "V2", "b", 250_000)
        store.restore(snap)                      
        r = ask(gate, "V3", "c", 125_000)
        self.assertEqual((r["status"], r["reason"]), ("REFUSED", "STATE_MISMATCH"))

    def test_3_two_workers_same_state_only_one_commits(self):
        gate1, anchor, store1 = build()
        s2 = Store(store1.head); s2.restore(store1.snapshot())
        gate2 = Gate(ISSUER_KEY, gate1_cred(gate1), POLICY, anchor, s2, VERIFIER_KEYS)
        r1 = ask(gate1, "V1", "w1", 500_000); r2 = ask(gate2, "V2", "w2", 250_000)
        self.assertEqual(sorted([r1["status"], r2["status"]]), ["ANSWERED", "REFUSED"])
        self.assertEqual(anchor.seq, 1)

    def test_4_concurrent_queries_cannot_exceed_budget(self):
        gate, anchor, store = build(); out = []
        def worker(k):
            for j in range(40): out.append(ask(gate, f"V{k%3+1}", f"c{k}-{j}", random.Random(k*100+j).randint(0, 999_999)))
        th = [threading.Thread(target=worker, args=(k,)) for k in range(6)]
        [t.start() for t in th]; [t.join() for t in th]
        self.assertGreaterEqual(width(store.iv), POLICY.min_width)
        self.assertEqual(anchor.seq, store.seq)

    def test_5_uncertain_commit_then_recover_and_retry(self):
        gate, anchor, store = build()
        r = ask(gate, "V1", "u1", 500_000, _drop_response=True)    
        self.assertEqual(r["status"], "LOST"); self.assertEqual(anchor.seq, 1)
        self.assertEqual(ask(gate, "V1", "u2", 250_000)["reason"], "RECOVERY_REQUIRED")
        self.assertEqual(gate.recover(), "PROMOTED")
        r2 = ask(gate, "V1", "u1", 500_000)                         
        self.assertTrue(r2["replay"]); self.assertEqual(anchor.seq, 1)

    def test_6_request_id_reuse_with_different_query_refused(self):
        gate, _, _ = build(); ask(gate, "V1", "same", 500_000)
        self.assertEqual(ask(gate, "V1", "same", 100_000)["reason"], "REQUEST_ID_REUSED")

    def test_7_verifier_cannot_bypass_allocation_or_forge_identity(self):
        gate, _, _ = build()
        r = gate.request("V1", "f1", 500_000, "00" * 32)             # forged auth tag
        self.assertEqual(r["reason"], "AUTH")
        r = gate.request("V9", "f2", 500_000, Gate.auth_tag(b"x", "V9", "f2", 500_000))
        self.assertEqual(r["reason"], "AUTH")

    def test_8_tampered_credential_or_policy_rejected(self):
        c = cred.issue(ISSUER_KEY, 83_250)
        forged = cred.Credential(**{**c.__dict__, "value": 999_000})
        with self.assertRaises(ValueError): Gate(ISSUER_KEY, forged, POLICY, SimulatedAnchor("g"), Store("g"), VERIFIER_KEYS)
        self.assertNotEqual(POLICY.digest(), type(POLICY)(0, 999_999, 5_000, 3.0).digest())

def gate1_cred(gate):
    return _recred(gate)

def _recred(gate):
    import hmac, hashlib
    base = cred.Credential(gate.cred_id, "annual_income_usd", gate._secret, "USD", cred.ISSUER)
    tag = hmac.new(ISSUER_KEY, cred._body(base), hashlib.sha256).hexdigest()
    return cred.Credential(**{**base.__dict__, "tag": tag})

if __name__ == "__main__":
    unittest.main()
