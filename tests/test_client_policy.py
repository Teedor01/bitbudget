import unittest
from core.policy import Policy
from core.records import Request
from harness.client_policy import AnchorObserver, PolicyClient
from harness.system import build_system
from testdoubles.local_anchor import LocalTestAnchor


class CheckedGate:
    """Wraps a Gate and asserts, on EVERY response, that nothing is released unless the exact request is
    committed on the public anchor history (committed now, or committed earlier and replayed)."""
    def __init__(self, system, gate=None):
        self.s, self.g, self.log = system, gate or system.gate, []

    def handle(self, req):
        resp = self.g.handle(req)
        self.log.append((req, resp))
        if resp.kind in ("ANSWER", "REFUSED"):
            heads = {(r.header.verifier_id, r.header.nonce, r.header.request_digest) for r in self.s.anchor.history()}
            assert (req.verifier_id, req.nonce, req.digest()) in heads, "released without a committed transition"
        else:
            assert resp.answer is None
        return resp


def seeded(history_limit=256, policy=None):
    s = build_system(policy, history_limit=history_limit) if policy else build_system(history_limit=history_limit)
    return s, PolicyClient(s, "V1")


class StalePolicy(unittest.TestCase):
    def test_T_H01_stale_read_rejection_recovers_by_same_request_retry(self):
        s, pc = seeded(); pc.ask(500_000); pc.ask(250_000)
        g = CheckedGate(s); v = s.anchor.version
        s.anchor.inject_read_fault("stale", version=0)                 
        res = pc.ask(125_000, gate=g)
        self.assertEqual((res.status, res.attempts), ("ANSWER", 2))
        self.assertEqual([r.kind for _, r in g.log], ["REJECTED", "ANSWER"])   
        self.assertEqual(s.anchor.version, v + 1)                         
        self.assertEqual(pc.nonce, 4)                                    
        self.assertEqual(g.log[0][0], g.log[1][0])                        

    def test_T_H02_genuinely_invalid_nonce_is_not_retried_or_advanced(self):
        s, pc = seeded(); pc.ask(500_000); pc.ask(250_000)
        v, cas = s.anchor.version, s.anchor.cas_calls
        pc.nonce = 5                                                      
        res = pc.ask(100_000)
        self.assertEqual((res.status, res.attempts, res.expected_nonce), ("INVALID_NONCE", 1, 3))
        self.assertEqual((s.anchor.version, s.anchor.cas_calls, pc.nonce, pc.pending), (v, cas, 5, None))
        self.assertTrue(pc.resync()); self.assertEqual(pc.nonce, 3)
        self.assertEqual(pc.ask(100_000).status, "ANSWER")

    def test_T_H03_auth_or_quota_rejection_is_bounded_and_unresolved(self):
        s, pc = seeded()
        pc.pending = Request(s.scope_id, "V1", 1, 500_000, s.pd, b"\x01" * 32, "00" * 32)   # forged tag
        res = pc.resolve_pending()
        self.assertEqual((res.status, res.attempts), ("UNRESOLVED", pc.max))
        self.assertEqual((s.anchor.version, s.anchor.cas_calls), (0, 0))
        self.assertIsNotNone(pc.pending)                                 
        s2, pc2 = seeded(policy=Policy(0, 999_999, 10_000, R=2)); pc2.ask(500_000); pc2.ask(250_000)
        res = pc2.ask(125_000)                                            
        self.assertEqual((res.status, res.attempts), ("UNRESOLVED", pc2.max)); self.assertEqual(s2.anchor.version, 2)

    def test_T_H04_lost_response_and_stale_replay_resolve_by_same_request(self):
        s, pc = seeded()
        req = pc._mk.make(500_000, nonce=1); first = s.gate.handle(req)   
        pc.pending = req; g = CheckedGate(s)
        res = pc.resolve_pending(gate=g)
        self.assertEqual((res.status, res.attempts, s.anchor.version), ("ANSWER", 1, 1))
        self.assertEqual(res.response, first)
        pc.ask(250_000)
        req3 = pc._mk.make(125_000, nonce=3); r3 = s.gate.handle(req3); v = s.anchor.version
        pc.pending, pc.nonce = req3, 3
        s.anchor.inject_read_fault("stale", version=1)                    
        g = CheckedGate(s)
        res = pc.resolve_pending(gate=g)
        self.assertEqual(([r.kind for _, r in g.log], res.status, res.response), (["REJECTED", "ANSWER"], "ANSWER", r3))
        self.assertEqual(s.anchor.version, v)                             

    def test_T_H05_conflicting_retry_is_rejected_and_not_retried(self):
        s, pc = seeded(); pc.ask(500_000); v = s.anchor.version
        pc.nonce = 1
        res = pc.ask(100_000)                                             
        self.assertEqual((res.status, res.attempts, res.expected_nonce), ("CONFLICT", 1, 2))
        self.assertEqual((s.anchor.version, pc.pending), (v, None))

    def test_T_H06_unknown_commit_outcomes_resolved_by_reread_never_blind_retry(self):
        s, pc = seeded(); s.anchor.inject_cas_fault("unknown_applied")
        res = pc.ask(500_000)
        self.assertEqual((res.status, res.attempts, s.anchor.version, s.anchor.cas_calls), ("ANSWER", 1, 1, 1))
        s, pc = seeded(); s.anchor.inject_cas_fault("unknown_not_applied")
        res = pc.ask(500_000)
        self.assertEqual((res.status, res.attempts, s.anchor.version), ("ANSWER", 2, 1))
        self.assertEqual(s.anchor.cas_calls, 2)                           
        s, pc = seeded(); g2 = s.new_gate(); req2 = PolicyClient(s, "V2")._mk.make(250_000, nonce=1)
        s.anchor.inject_cas_fault("unknown_applied", after=lambda: g2.handle(req2))
        res = pc.ask(500_000)
        self.assertEqual((res.status, res.attempts, s.anchor.version), ("ANSWER", 2, 2))
        self.assertEqual(s.state().verifiers["V1"].requests, 1)          

    def test_T_H07_stale_read_may_replay_an_older_committed_request_information_neutrally(self):
        s, pc = seeded(); g = CheckedGate(s)
        r1 = pc.ask(500_000, gate=g).response; pc.ask(250_000, gate=g)
        req1 = g.log[0][0]; v, cas = s.anchor.version, s.anchor.cas_calls
        s.anchor.inject_read_fault("stale", version=1)                    
        again = g.handle(req1)
        self.assertEqual(again, r1)                                       
        self.assertEqual((s.anchor.version, s.anchor.cas_calls), (v, cas))

    def test_T_H08_pending_request_is_never_silently_skipped(self):
        s, pc = seeded()
        pc.pending = Request(s.scope_id, "V1", 1, 500_000, s.pd, b"\x01" * 32, "00" * 32)
        self.assertEqual(pc.resolve_pending().status, "UNRESOLVED")
        self.assertEqual(pc.ask(5).status, "PENDING")                     
        self.assertTrue(pc.abandon_pending())                            
        self.assertEqual(pc.ask(500_000).status, "ANSWER")
        req = pc._mk.make(250_000, nonce=2); s.gate.handle(req)           
        pc.pending = req
        self.assertFalse(pc.abandon_pending())                            
        self.assertEqual(pc.resolve_pending().status, "ANSWER")

    def test_T_H09_incomplete_public_history_makes_the_client_conservative(self):
        s, pc = seeded(history_limit=2)
        for t in (500_000, 250_000, 125_000, 60_000): pc.ask(t)
        self.assertFalse(AnchorObserver(s.anchor).view("V1")[0])         
        pc.nonce = 9                                                      
        res = pc.ask(30_000)
        self.assertEqual((res.status, res.attempts), ("UNRESOLVED", pc.max))   
        self.assertFalse(pc.abandon_pending()); self.assertFalse(pc.resync())

    def test_T_H10_what_an_external_verifier_can_observe(self):
        """All rejection causes are byte-identical to the verifier; so are all RETRY causes (documented limitation)."""
        s = build_system(policy=Policy(0, 999_999, 10_000, R=3)); c = s.client("V1"); c.ask(500_000)
        rejected = {
            "bad_tag": s.gate.handle(Request(s.scope_id, "V1", 2, 5, s.pd, b"\x01" * 32, "00" * 32)),
            "unadmitted": s.gate.handle(Request(s.scope_id, "V9", 1, 5, s.pd, b"\x01" * 32, "00" * 32)),
            "lower_nonce": s.gate.handle(c.make(5, nonce=0)),
            "higher_nonce": s.gate.handle(c.make(5, nonce=7)),
            "conflicting_duplicate": s.gate.handle(c.make(100_000, nonce=1)),
            "short_blinding": s.gate.handle(c.make(5, nonce=2, blinding=b"\x01" * 8)),
        }
        c.ask(250_000); c.ask(125_000)                                    
        rejected["quota"] = s.gate.handle(c.make(5))
        s.anchor.inject_read_fault("stale", version=0)
        rejected["stale"] = s.gate.handle(c.make(5))
        self.assertEqual({r.encode() for r in rejected.values()}, {b"REJECTED"}, {k: r.kind for k, r in rejected.items()})
        s2 = build_system(); c2 = s2.client("V1")
        s2.anchor.inject_cas_fault("unavailable"); a = s2.gate.handle(c2.make(500_000))
        s2.anchor.inject_cas_fault("unknown_not_applied"); b = s2.gate.handle(c2.make(500_000))
        s2.anchor.inject_read_fault("unavailable"); d = s2.gate.handle(c2.make(500_000))
        self.assertEqual({a.encode(), b.encode(), d.encode()}, {b"RETRY"})


if __name__ == "__main__":
    unittest.main()
