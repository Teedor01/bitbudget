import random, threading, unittest
from core.gate import Gate
from core.interfaces import AnchorUnavailable, CasResult, GateConfigError
from core.policy import Interval, Kind, Policy, decide
from core.records import Request, State, policy_digest
from harness.attackers import adaptive_attack, make_query_fn
from harness.audit import audit_chain
from harness.system import DEMO_POLICY, WRITER_KEY, Client, build_system
from testdoubles.local_anchor import LocalTestAnchor, SimulatedCrash


class BarrierAnchor(LocalTestAnchor):
    """Forces two gates to read the SAME version before either commits."""
    barrier = None
    def read(self):
        rec = super().read()
        if self.barrier is not None:
            self.barrier.wait(timeout=5)
        return rec


def ok(resp):
    return resp.kind in ("ANSWER", "REFUSED")


class StateMachine(unittest.TestCase):
    def test_T_S01_duplicate_request_is_idempotent(self):
        s = build_system(); c = s.client("V1")
        req = c.make(500_000)
        r1 = s.gate.handle(req); v = s.anchor.version; cas = s.anchor.cas_calls
        r2 = s.gate.handle(req)
        self.assertEqual(r1, r2); self.assertEqual(r2.kind, "ANSWER")
        self.assertEqual((s.anchor.version, s.anchor.cas_calls), (v, cas))
        self.assertEqual(s.state().verifiers["V1"].requests, 1)               # charged once

    def test_T_S02_same_nonce_different_content_rejected(self):
        s = build_system(); c = s.client("V1")
        req = c.make(500_000, blinding=b"\x07" * 32)
        s.gate.handle(req); v = s.anchor.version
        other_t = c.make(100_000, nonce=1)
        other_blind = c.make(500_000, nonce=1, blinding=b"\x08" * 32)          # same t, different blinding
        for r in (other_t, other_blind):
            self.assertEqual(s.gate.handle(r).kind, "REJECTED")
        self.assertEqual(s.anchor.version, v)

    def test_T_S03_nonce_must_be_exactly_next(self):
        s = build_system(); c = s.client("V1")
        for n in (0, 2, 5, -1):
            self.assertEqual(s.gate.handle(c.make(500_000, nonce=n)).kind, "REJECTED", n)
        self.assertEqual(s.anchor.version, 0)
        self.assertTrue(ok(s.gate.handle(c.make(500_000, nonce=1))))
        for n in (0, 3, 4):
            self.assertEqual(s.gate.handle(c.make(250_000, nonce=n)).kind, "REJECTED", n)
        self.assertEqual(s.anchor.version, 1)
        self.assertTrue(ok(s.gate.handle(c.make(250_000, nonce=2))))
        self.assertEqual(s.anchor.version, 2)

    def test_T_S04_two_gates_same_state_only_one_commits(self):
        s = build_system(anchor_cls=BarrierAnchor)
        g1, g2 = s.gate, s.new_gate()
        r1, r2 = s.client("V1").make(500_000), s.client("V2").make(500_000)
        s.anchor.barrier = threading.Barrier(2)
        out = {}
        ts = [threading.Thread(target=lambda: out.__setitem__(1, g1.handle(r1))),
              threading.Thread(target=lambda: out.__setitem__(2, g2.handle(r2)))]
        [t.start() for t in ts]; [t.join() for t in ts]
        s.anchor.barrier = None
        kinds = sorted(r.kind for r in out.values())
        self.assertEqual(kinds, ["ANSWER", "RETRY"])
        self.assertEqual(s.anchor.version, 1)
        loser = out[1] if out[1].kind == "RETRY" else out[2]
        self.assertIsNone(loser.answer)                                       

    def test_T_S05_unknown_outcomes_resolved_by_reread(self):
        s = build_system(); c = s.client("V1")
        s.anchor.inject_cas_fault("unknown_applied")
        r = s.gate.handle(c.make(500_000))
        self.assertEqual(r.kind, "ANSWER"); self.assertEqual(s.anchor.version, 1)
        s = build_system(); c = s.client("V1")
        s.anchor.inject_cas_fault("unknown_not_applied")
        req = c.make(500_000)
        r = s.gate.handle(req)
        self.assertEqual(r.kind, "RETRY"); self.assertEqual(s.anchor.version, 0); self.assertEqual(s.anchor.cas_calls, 1)
        self.assertEqual(s.gate.handle(req).kind, "ANSWER"); self.assertEqual(s.anchor.version, 1)
        s = build_system(); g2 = s.new_gate()
        req1, req2 = s.client("V1").make(500_000), s.client("V2").make(250_000)
        inner = {}
        s.anchor.inject_cas_fault("unknown_applied", after=lambda: inner.__setitem__("r", g2.handle(req2)))
        r = s.gate.handle(req1)
        self.assertEqual(r.kind, "RETRY"); self.assertIn(inner["r"].kind, ("ANSWER", "REFUSED"))
        self.assertEqual(s.anchor.version, 2); self.assertEqual(s.anchor.cas_calls, 2)   
        v = s.anchor.version
        again = s.gate.handle(req1)
        self.assertEqual(again.kind, "ANSWER"); self.assertEqual(s.anchor.version, v)    
        self.assertEqual(s.state().verifiers["V1"].requests, 1)

    def test_T_S06_anchor_unavailable_fails_closed(self):
        s = build_system(); c = s.client("V1"); req = c.make(500_000)
        s.anchor.inject_cas_fault("unavailable")
        r = s.gate.handle(req); self.assertEqual(r.kind, "RETRY"); self.assertEqual(s.anchor.version, 0)
        s.anchor.inject_read_fault("unavailable")
        r = s.gate.handle(req); self.assertEqual(r.kind, "RETRY"); self.assertEqual(s.anchor.version, 0)
        self.assertEqual(s.gate.handle(req).kind, "ANSWER")                       

    def test_T_S07_stale_read_never_releases(self):
        s = build_system(); c1, c2 = s.client("V1"), s.client("V2")
        c1.ask(500_000); c1.ask(250_000)                                         
        self.assertEqual(s.anchor.version, 2)
        s.anchor.inject_read_fault("stale", version=1)
        r = s.gate.handle(c2.make(100_000))
        self.assertEqual(r.kind, "RETRY"); self.assertIsNone(r.answer); self.assertEqual(s.anchor.version, 2)
        s.anchor.inject_read_fault("stale", version=1)
        r = s.gate.handle(c1.make(120_000))
        self.assertIn(r.kind, ("RETRY", "REJECTED")); self.assertIsNone(r.answer); self.assertEqual(s.anchor.version, 2)
        self.assertTrue(ok(c1.ask(120_000)))                                    

    def test_T_S08_concurrent_verifiers_single_linear_history(self):
        s = build_system(history_limit=100_000)
        vids = ["V1", "V2", "V3"]; results = {v: [] for v in vids}
        def worker(vid, seed):
            rng = random.Random(seed); g = s.new_gate(); c = s.client(vid)
            for _ in range(60):
                results[vid].append(c.ask(rng.randint(0, 999_999), gate=g, retries=50))
        ts = [threading.Thread(target=worker, args=(v, i)) for i, v in enumerate(vids)]
        [t.start() for t in ts]; [t.join() for t in ts]
        committed = sum(1 for v in vids for r in results[v] if ok(r))
        self.assertEqual(s.anchor.version, committed)                              
        self.assertEqual(audit_chain(s), [])                                       
        self.assertGreaterEqual(s.state().interval.size, DEMO_POLICY.W)
        for v in vids:
            self.assertEqual(s.state().verifiers[v].last_nonce, sum(1 for r in results[v] if ok(r)))

    def test_T_S09_crash_after_commit_replayed_by_fresh_gate(self):
        s = build_system(); c = s.client("V1"); req = c.make(500_000)
        s.anchor.inject_cas_fault("crash_after_apply")
        with self.assertRaises(SimulatedCrash):
            s.gate.handle(req)
        self.assertEqual(s.anchor.version, 1)                                      
        fresh = s.new_gate()                                                       
        r = fresh.handle(req)
        self.assertEqual(r.kind, "ANSWER"); self.assertEqual(s.anchor.version, 1)

    def test_T_S10_crash_before_commit_leaves_no_trace(self):
        s = build_system(); c = s.client("V1"); req = c.make(500_000)
        s.anchor.inject_cas_fault("crash_before_apply")
        with self.assertRaises(SimulatedCrash):
            s.gate.handle(req)
        self.assertEqual(s.anchor.version, 0)
        self.assertEqual(s.new_gate().handle(req).kind, "ANSWER"); self.assertEqual(s.anchor.version, 1)

    def test_T_S11_gate_replacement_continues_from_anchor(self):
        s = build_system(); c = s.client("V1")
        c.ask(500_000); c.ask(250_000)
        g2 = s.new_gate()
        r = c.ask(125_000, gate=g2)
        self.assertEqual(r.kind, "ANSWER"); self.assertEqual(s.anchor.version, 3)
        self.assertEqual(s.state().verifiers["V1"].last_nonce, 3)

    def test_T_S12_scope_and_policy_binding(self):
        s = build_system(); c = s.client("V1")
        v = s.anchor.version
        bad_scope = Request("ab" * 16, "V1", 1, 5, s.pd, b"\x01" * 32, "")
        bad_scope = Request(bad_scope.scope_id, "V1", 1, 5, s.pd, b"\x01" * 32, s.auth.tag("V1", bad_scope.digest()))
        bad_pol = Request(s.scope_id, "V1", 1, 5, "00" * 32, b"\x01" * 32, "")
        bad_pol = Request(s.scope_id, "V1", 1, 5, "00" * 32, b"\x01" * 32, s.auth.tag("V1", bad_pol.digest()))
        self.assertEqual(s.gate.handle(bad_scope).kind, "REJECTED")
        self.assertEqual(s.gate.handle(bad_pol).kind, "REJECTED")
        self.assertEqual(s.anchor.version, v)
        other_scope = Gate(s.policy, "ff" * 16, s.secret, s.anchor, s.sealer, s.auth, WRITER_KEY)
        rq = Request("ff" * 16, "V1", 1, 500_000, s.pd, b"\x02" * 32, "")
        rq = Request(rq.scope_id, "V1", 1, 500_000, s.pd, rq.blinding, s.auth.tag("V1", rq.digest()))
        with self.assertRaises(GateConfigError):
            other_scope.handle(rq)
        pol2 = Policy(0, 999_999, 9_000)
        other_pol = Gate(pol2, s.scope_id, s.secret, s.anchor, s.sealer, s.auth, WRITER_KEY)
        rq = Request(s.scope_id, "V1", 1, 500_000, policy_digest(pol2), b"\x03" * 32, "")
        rq = Request(rq.scope_id, "V1", 1, 500_000, rq.policy_digest, rq.blinding, s.auth.tag("V1", rq.digest()))
        with self.assertRaises(GateConfigError):
            other_pol.handle(rq)
        self.assertEqual(s.anchor.version, v)

    def test_T_S13_unauthorized_writer_rejected(self):
        s = build_system(); c = s.client("V1"); c.ask(500_000)
        rec = s.anchor.read(); v = s.anchor.version
        res = s.anchor.compare_and_swap("wrong-key", rec.header.version, rec.digest(), rec)
        self.assertIs(res, CasResult.UNAUTHORIZED); self.assertEqual(s.anchor.version, v)
        bad = Gate(s.policy, s.scope_id, s.secret, s.anchor, s.sealer, s.auth, "wrong-key")
        with self.assertRaises(GateConfigError):
            bad.handle(c.make(250_000))
        self.assertEqual(s.anchor.version, v)

    def test_T_S14_transition_binding_audit(self):
        s = build_system(history_limit=10_000); rng = random.Random(3)
        cl = {v: s.client(v) for v in ("V1", "V2", "V3")}
        for i in range(120):
            cl[rng.choice(list(cl))].ask(rng.choice([rng.randint(0, 999_999), 5_000, 2_000_000, 995_000]))
        self.assertEqual(audit_chain(s), [])
        recs = s.anchor.history()
        from dataclasses import replace
        tampered = replace(recs[10], header=replace(recs[10].header, request_digest="ab" * 32))
        s.anchor._records[recs[10].header.version] = tampered
        self.assertNotEqual(audit_chain(s), [])

    def test_T_S15_caps_per_verifier(self):
        pol = Policy(0, 999_999, 10_000, K=2, R=5)
        s = build_system(pol); c1, c2 = s.client("V1"), s.client("V2")
        kinds = [c1.ask(t).kind for t in (500_000, 250_000, 125_000)]
        self.assertEqual(kinds, ["ANSWER", "ANSWER", "REFUSED"])                   
        self.assertEqual(s.state().verifiers["V1"].informative, 2)
        self.assertEqual(c2.ask(60_000).kind, "ANSWER")                          
        c1.ask(1_500_000); c1.ask(1_500_000)                                       
        v = s.anchor.version
        self.assertEqual(s.gate.handle(c1.make(1_500_000)).kind, "REJECTED")      
        self.assertEqual(s.anchor.version, v)
        before = s.state().interval
        t_low, t_high = before.lo + 4_999, before.hi - 5_000    
        self.assertEqual(c2.ask(t_low).kind, "REFUSED"); self.assertEqual(c2.ask(t_high).kind, "REFUSED")
        self.assertEqual(s.state().interval, before)

    def test_T_S16_caps_and_floor_together_never_break_floor(self):
        rng = random.Random(9)
        for K, R in ((1, 4), (2, 10), (None, 20), (3, None)):
            pol = Policy(0, 999_999, 10_000, K=K, R=R)
            s = build_system(pol, secret=rng.randint(0, 999_999), history_limit=8)
            cl = {v: s.client(v) for v in ("V1", "V2", "V3")}
            for _ in range(150):
                cl[rng.choice(list(cl))].ask(rng.randint(-10, 1_000_010))
                self.assertGreaterEqual(s.state().interval.size, pol.W)

    def test_T_S22_squeeze_attackers_with_generous_caps_never_breach_floor_at_any_step(self):
        rng = random.Random(16)
        for K, R in ((30, None), (30, 500), (8, None), (8, 500)):
            pol = Policy(0, 999_999, 10_000, K=K, R=R)
            for secret in (0, 5_000, 83_250, 500_000, 989_999, 999_999):
                s = build_system(pol, secret=secret, history_limit=8)
                q = make_query_fn(s, ["V1", "V2", "V3"], rng)
                def checked(t, q=q, s=s, pol=pol):
                    r = q(t); self.assertGreaterEqual(s.state().interval.size, pol.W, (K, R, secret, t)); return r
                (a, b), _ = adaptive_attack(checked, 0, 999_999, pol.W, rng, "squeeze")
                self.assertGreaterEqual(b - a + 1, pol.W)

    def test_T_S20_caps_never_make_any_decision_more_permissive_differential(self):
        """Failure mode caught: enabling/changing K or R alters a decision in the PERMISSIVE direction.
        Exhaustive differential over a tiny domain: compare every (interval, t, count) with caps vs without."""
        lo, hi, W = 0, 39, 4
        base = Policy(lo, hi, W)
        variants = [Policy(lo, hi, W, K=k, R=r) for k in (None, 1, 2, 5) for r in (None, 1, 3)]
        n = 0
        for a in range(lo, hi + 1):
            for b in range(a, hi + 1):
                iv = Interval(a, b)
                for t in range(-3, 43):
                    for count in range(0, 7):
                        d0 = decide(base, iv, t, count)
                        for pv in variants:
                            d1 = decide(pv, iv, t, count)
                            if d0.kind is Kind.REFUSED:
                                self.assertIs(d1.kind, Kind.REFUSED, (a, b, t, pv))       
                            elif d0.kind is Kind.DETERMINED:
                                self.assertEqual((d1.kind, d1.forced_answer), (d0.kind, d0.forced_answer))
                            else:                                                         
                                self.assertIn(d1.kind, (Kind.INFORMATIVE, Kind.REFUSED))
                                if pv.K is not None and count >= pv.K:
                                    self.assertIs(d1.kind, Kind.REFUSED)
                            n += 1
        self.assertGreater(n, 400_000)

    def test_T_S21_floor_edge_battery_under_every_cap_configuration_end_to_end(self):
        """Failure mode caught: the floor is disabled/bypassed/weakened ONLY WHEN caps are configured
        (policy-level tests use default policies; this drives the real gate under each (K, R))."""
        refused = [0, 1, 5_000, 9_997, 9_998, 990_000, 990_001, 995_000, 999_998]
        for K, R in ((None, None), (1, None), (5, None), (30, 200), (None, 200), (2, 3)):
            pol = Policy(0, 999_999, 10_000, K=K, R=R)
            for t in refused:
                s = build_system(pol); r = s.client("V1").ask(t)
                self.assertEqual(r.kind, "REFUSED", (K, R, t))
                self.assertEqual(s.state().interval, Interval(0, 999_999), (K, R, t))
            for secret, t in ((0, 9_999), (999_999, 989_999)):               
                s = build_system(pol, secret=secret); self.assertEqual(s.client("V2").ask(t).kind, "ANSWER")
                self.assertEqual(s.state().interval.size, pol.W, (K, R, secret))

    def test_T_S17_runs_with_allocations_disabled(self):
        self.assertIsNone(DEMO_POLICY.K); self.assertIsNone(DEMO_POLICY.R)
        s = build_system(); c = s.client("V1")
        answered = sum(1 for _ in range(300) if c.ask(random.Random(_).randint(0, 999_999)).kind == "ANSWER")
        self.assertGreater(answered, 5)
        self.assertGreaterEqual(s.state().interval.size, DEMO_POLICY.W)
        self.assertEqual(s.state().verifiers["V1"].requests, 300)              

    def test_T_S18_rejections_never_commit(self):
        pol = Policy(0, 999_999, 10_000, R=2)
        s = build_system(pol); c = s.client("V1"); c.ask(500_000); c.ask(250_000)
        v, cas = s.anchor.version, s.anchor.cas_calls
        good = c.make(125_000)
        bad_tag = Request(good.scope_id, good.verifier_id, good.nonce, good.threshold, good.policy_digest, good.blinding, "00" * 32)
        cases = [bad_tag, c.make(125_000, nonce=0), c.make(125_000, nonce=9), good,        
                 Request(s.scope_id, "V9", 1, 5, s.pd, b"\x01" * 32, "00" * 32),
                 c.make(500_000, nonce=2, blinding=b"\x09" * 32)]                             
        for r in cases:
            self.assertEqual(s.gate.handle(r).kind, "REJECTED")
        self.assertEqual((s.anchor.version, s.anchor.cas_calls), (v, cas))

    def test_T_S19_committed_refusal_changes_exactly_the_documented_fields(self):
        s = build_system(); c = s.client("V1"); c.ask(500_000)
        before, v0 = s.state(), s.anchor.version
        r = c.ask(9_998)                                                           
        self.assertEqual(r.kind, "REFUSED")
        after = s.state()
        self.assertEqual(s.anchor.version, v0 + 1)
        self.assertEqual((after.lo, after.hi), (before.lo, before.hi))            
        b1, a1 = before.verifiers["V1"], after.verifiers["V1"]
        self.assertEqual(a1.informative, b1.informative)                           
        self.assertEqual((a1.last_nonce, a1.requests, a1.last_response), (b1.last_nonce + 1, b1.requests + 1, "REFUSED"))
        self.assertNotEqual(a1.last_digest, b1.last_digest); self.assertNotEqual(a1.last_gamma, b1.last_gamma)
        for v in ("V2", "V3"):
            self.assertEqual(after.verifiers[v], before.verifiers[v])


if __name__ == "__main__":
    unittest.main()
