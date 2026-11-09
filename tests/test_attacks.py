import math, random, unittest
from core.policy import Interval, Policy
from harness.attackers import adaptive_attack, baseline_binary_search, make_query_fn
from harness.system import DEMO_POLICY, FIXTURE_SECRET, build_system
from tests.reference_model import ref_simulate

P = DEMO_POLICY
SECRETS = [0, 1, 9_999, 10_000, 83_250, 499_999, 500_000, 500_001, 989_999, 990_000, 990_001, 999_998, 999_999]


def gate_interval(system):
    return system.state().interval


class Attacks(unittest.TestCase):
    def test_T_A01_stateless_baseline_recovers_exact_value(self):
        value, n = baseline_binary_search(FIXTURE_SECRET, P.lo, P.hi)
        self.assertEqual(value, FIXTURE_SECRET)
        self.assertEqual(n, math.ceil(math.log2(P.hi - P.lo + 1)))    
        rng = random.Random(1)
        for s in SECRETS + [rng.randint(0, 999_999) for _ in range(50)]:
            v, n = baseline_binary_search(s, P.lo, P.hi)
            self.assertEqual(v, s); self.assertLessEqual(n, 20)

    def test_T_A02_gated_binary_search_stalls_at_floor(self):
        s = build_system()
        q = make_query_fn(s, ["V1", "V2", "V3"], random.Random(0))
        (a, b), answers = adaptive_attack(q, P.lo, P.hi, P.W, random.Random(0), "binary")
        gi = gate_interval(s)
        self.assertGreaterEqual(b - a + 1, P.W)
        self.assertGreaterEqual(gi.size, P.W)
        self.assertTrue(gi.lo <= FIXTURE_SECRET <= gi.hi)
        self.assertEqual((a, b), (gi.lo, gi.hi))                   
        self.assertGreater(answers, 0)

    def test_T_A03_colluding_verifiers_many_secrets(self):
        rng = random.Random(7)
        for k in (1, 3, 10):
            vids = [f"V{i}" for i in range(k)]
            for assign in ("rr", "random"):
                for secret in SECRETS + [rng.randint(0, 999_999) for _ in range(3)]:
                    for strategy in ("binary", "squeeze"):
                        s = build_system(secret=secret, verifier_ids=vids, history_limit=4)
                        q = make_query_fn(s, vids, rng, assign)
                        (a, b), _ = adaptive_attack(q, P.lo, P.hi, P.W, rng, strategy)
                        gi = gate_interval(s)
                        self.assertGreaterEqual(b - a + 1, P.W, (k, assign, secret, strategy))
                        self.assertGreaterEqual(gi.size, P.W)
                        self.assertTrue(gi.lo <= secret <= gi.hi)

    def test_T_A04_greedy_squeeze_reaches_but_not_below_floor(self):
        rng = random.Random(11)
        sizes = []
        for secret in SECRETS + [rng.randint(0, 999_999) for _ in range(25)]:
            s = build_system(secret=secret, history_limit=4)
            q = make_query_fn(s, ["V1", "V2", "V3"], rng)
            (a, b), _ = adaptive_attack(q, P.lo, P.hi, P.W, rng, "squeeze")
            sizes.append(b - a + 1)
            self.assertGreaterEqual(b - a + 1, P.W, secret)
        for secret, t in ((0, 9_999), (5_000, 9_999), (9_999, 9_999), (989_999 + 1, 989_999), (999_999, 989_999)):
            s = build_system(secret=secret, history_limit=4)
            c = s.client("V1")
            self.assertEqual(c.ask(t).kind, "ANSWER")
            self.assertEqual(s.state().interval.size, P.W, (secret, t))
            for probe in (t - 1, t + 1, 5_000, 995_000, 500_000):      
                c.ask(probe)
            self.assertGreaterEqual(s.state().interval.size, P.W)

    def test_T_A05_tail_prober_refused_while_interval_touches_edge(self):
        s = build_system(history_limit=4)
        c = s.client("V1")
        for t in list(range(0, 9_999)) + list(range(990_000, 1_000_000)):
            r = c.ask(t)
            self.assertEqual(r.kind, "REFUSED" if t <= 9_998 or t <= 998_999 and t >= 990_000 and t <= 999_998 else r.kind, t)
            if 990_000 <= t <= 999_998 or t <= 9_998:
                self.assertEqual(r.kind, "REFUSED", t)
            else:
                self.assertEqual(r.kind, "ANSWER", t)    
        self.assertEqual(s.state().interval, Interval(0, 999_999))   

    def test_T_A06_sybil_verifier_ids_rejected(self):
        s = build_system()
        before = s.anchor.version
        from core.records import Request
        for vid in ("V9", "", "V1 ", "v1"):
            req = Request(s.scope_id, vid, 1, 500_000, s.pd, b"\x01" * 32, "00" * 32)
            self.assertEqual(s.gate.handle(req).kind, "REJECTED", vid)
        self.assertEqual(s.anchor.version, before)
        self.assertEqual(s.anchor.cas_calls, 0)

    def test_T_A07_retry_spam_gives_no_extra_information(self):
        pol = Policy(0, 999_999, 10_000, K=3, R=8)
        s = build_system(pol)
        c = s.client("V1")
        req = c.make(500_000)
        first = s.gate.handle(req)
        v = s.anchor.version
        for _ in range(20):                               
            self.assertEqual(s.gate.handle(req), first)
        self.assertEqual(s.anchor.version, v)
        c.nonce = 2
        informative = 0
        for i in range(20):                              
            r = c.ask(500_000)
            informative += r.kind == "ANSWER"
        self.assertEqual(s.state().interval, Interval(0, 500_000))     
        self.assertLessEqual(s.state().verifiers["V1"].requests, pol.R)

    def test_T_A08_determined_spam_changes_nothing_but_consumes_quota(self):
        pol = Policy(0, 999_999, 10_000, K=3, R=6)
        s = build_system(pol)
        c = s.client("V1")
        for _ in range(10):
            c.ask(2_000_000)
        st = s.state()
        self.assertEqual(st.interval, Interval(0, 999_999))
        self.assertEqual(st.verifiers["V1"].informative, 0)
        self.assertEqual(st.verifiers["V1"].requests, 6)               
        self.assertEqual(s.anchor.version, 6)

    def test_T_A09_decision_oracle_attacker_scaled_domain(self):
        lo, hi, W = 0, 999, 100
        pol = Policy(lo, hi, W)
        rng = random.Random(5)
        for secret in [0, 1, 99, 100, 499, 500, 899, 900, 999] + [rng.randint(0, 999) for _ in range(30)]:
            for strategy in ("binary", "squeeze", "random"):
                s = build_system(pol, secret=secret, history_limit=4)
                log = []
                q = make_query_fn(s, ["V1", "V2", "V3"], rng, "rr", log)
                adaptive_attack(q, lo, hi, W, rng, strategy, max_queries=60)
                observed, F_true = ref_simulate(lo, hi, W, None, secret, log)
                consistent = [v for v in range(lo, hi + 1) if ref_simulate(lo, hi, W, None, v, log)[0] == observed]
                gi = s.state().interval
                self.assertIn(secret, consistent)
                self.assertGreaterEqual(len(consistent), W, (secret, strategy))
                self.assertEqual(set(consistent), set(range(gi.lo, gi.hi + 1)))   
                self.assertEqual(set(consistent), F_true)


if __name__ == "__main__":
    unittest.main()
