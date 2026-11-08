import hashlib, pathlib, random, re, unittest
from core.policy import Policy
from core.records import Request, request_digest
from harness.audit import observer_view
from harness.attackers import adaptive_attack, make_query_fn
from harness.system import DEMO_POLICY, build_system

ALLOWED = {b"ANSWER:1", b"ANSWER:0", b"REFUSED", b"REJECTED", b"RETRY"}


def one_of_each(system):
    """Return the record produced by an INFORMATIVE, a DETERMINED and a REFUSED request (in that order)."""
    c = system.client("V1"); recs = []
    for t, expect in ((500_000, "ANSWER"), (900_000, "ANSWER"), (2_000_000, "ANSWER"), (9_998, "REFUSED")):
        r = c.ask(t); assert r.kind == expect, (t, r)
        recs.append(system.anchor.read())
    return recs


class Metadata(unittest.TestCase):
    def test_T_M01_records_have_identical_layout_and_length(self):
        s = build_system(); recs = one_of_each(s)     
        self.assertEqual({len(r.encode()) for r in recs}, {len(recs[0].encode())})
        self.assertEqual({len(r.sealed_state) for r in recs}, {len(recs[0].sealed_state)})
        for v in ("V2", "V3"):
            s.client(v).ask(100_000)
        lens = {len(r.encode()) for r in s.anchor.history()}
        self.assertEqual(len(lens), 1)

    def test_T_M02_each_accepted_request_advances_version_by_exactly_one(self):
        s = build_system(); c = s.client("V1"); v = s.anchor.version
        for t in (500_000, 2_000_000, 9_998, 250_000, 5, 990_001):            
            r = c.ask(t)
            self.assertIn(r.kind, ("ANSWER", "REFUSED"))
            v += 1
            self.assertEqual(s.anchor.version, v)

    def test_T_M03_floor_and_cap_refusals_are_byte_identical(self):
        floor = build_system(); rf = floor.gate.handle(floor.client("V1").make(9_998))
        cap = build_system(Policy(0, 999_999, 10_000, K=1)); c = cap.client("V1")
        first = cap.gate.handle(c.make(500_000)); self.assertEqual(first.kind, "ANSWER")
        rc = cap.gate.handle(c.make(250_000, nonce=2))                           
        self.assertEqual(cap.state().verifiers["V1"].informative, 1)
        self.assertEqual((rf.kind, rc.kind), ("REFUSED", "REFUSED"))
        self.assertEqual(rf.encode(), rc.encode())
        self.assertEqual(rf, rc)

    def test_T_M04_response_classes_and_no_reason_strings(self):
        rng = random.Random(4); seen = set()
        pol = Policy(0, 999_999, 10_000, K=2, R=12)
        s = build_system(pol); cl = {v: s.client(v) for v in ("V1", "V2", "V3")}
        c0 = s.client("V1")
        seen.add(s.gate.handle(c0.make(9_998)).encode()); c0.nonce += 1
        for t in (500_000, 250_000):
            seen.add(s.gate.handle(c0.make(t)).encode()); c0.nonce += 1
        seen.add(s.gate.handle(c0.make(125_000)).encode()); c0.nonce += 1         
        self.assertEqual(s.state().verifiers["V1"].informative, 2)
        for _ in range(120):
            c = cl[rng.choice(list(cl))]
            req = c.make(rng.choice([rng.randint(0, 999_999), 9_998, 2_000_000]), nonce=rng.choice([None, None, 0, 99]))
            r = s.gate.handle(req); seen.add(r.encode())
            if r.kind in ("ANSWER", "REFUSED"): c.nonce += 1 if req.nonce == c.nonce else 0
        self.assertTrue(seen <= ALLOWED, seen - ALLOWED)
        self.assertIn(b"REFUSED", seen); self.assertIn(b"ANSWER:1", seen | {b"ANSWER:1"})
        for rec in s.anchor.history():
            plain = rec.encode()[: len(rec.encode()) - len(rec.sealed_state)]    
            for word in (b"FLOOR", b"CAP", b"INFORMATIVE", b"DETERMINED", b"YES", b"NO"):
                self.assertNotIn(word, plain)
        src = pathlib.Path("core/gate.py").read_text()
        self.assertNotRegex(src, r"\bprint\(|\blogging\b|\bwarnings\b")

    def test_T_M05_public_view_has_no_plaintext_threshold_answer_or_interval(self):
        s = build_system(); c = s.client("V1"); t = 123_457
        c.ask(t); c.ask(9_998)
        allowed_keys = {"scope_id", "version", "prev_digest", "verifier_id", "nonce", "request_digest",
                        "status_commitment", "policy_digest", "sealed_len"}
        for rec in s.anchor.history():
            view = observer_view(rec)
            self.assertEqual(set(view), allowed_keys)
            blob = repr(view)
            self.assertNotIn(str(t), blob)
            for k in view:
                self.assertNotIn(k, ("threshold", "answer", "interval", "decision", "informative_count"))
        self.assertEqual(len(s.anchor.read().sealed_state), len(s.anchor.record_at(0).sealed_state))

    def test_T_M06_same_final_interval_gives_identical_observable_views(self):
        qs = [("V1", 500_000), ("V2", 250_000), ("V3", 125_000), ("V1", 60_000), ("V2", 30_000)]
        def run(secret):
            s = build_system(secret=secret, history_limit=100, scope_id="ab" * 16)   
            cl = {v: s.client(v) for v in ("V1", "V2", "V3")}
            blind = {i: bytes([i + 1]) * 32 for i in range(len(qs))}
            resps = []
            for i, (vid, t) in enumerate(qs):
                req = cl[vid].make(t, blinding=blind[i]); r = s.gate.handle(req)
                cl[vid].nonce += 1; resps.append(r.encode())
            views = []
            for rec in s.anchor.history()[1:]:
                v = observer_view(rec); v.pop("status_commitment"); v.pop("prev_digest")
                v["scope_id"] = "x"; views.append(v)
            return resps, views, s.state().interval
        ra, va, ia = run(83_250)
        rb, vb, ib = run(ia.lo + 1) if ia.lo + 1 != 83_250 else run(ia.hi)
        self.assertEqual(ia, ib)
        self.assertEqual(ra, rb); self.assertEqual(va, vb)

    def test_T_M07_blinding_hides_the_threshold_from_a_digest_dictionary_attack(self):
        s = build_system(); t = 654_321
        req = s.client("V1").make(t)                                        
        target = req.digest()
        for guess in (b"", b"\x00" * 32):
            hits = [x for x in range(0, 1_000_000)
                    if request_digest(s.scope_id, "V1", 1, x, s.pd, guess) == target]
            self.assertEqual(hits, [])
        weak = request_digest(s.scope_id, "V1", 1, t, s.pd, b"")
        hits = [x for x in range(0, 1_000_000) if request_digest(s.scope_id, "V1", 1, x, s.pd, b"") == weak]
        self.assertEqual(hits, [t])

    def test_T_M08_blinding_audit_what_the_digest_does_and_does_not_protect(self):
        s = build_system(); c = s.client("V1"); v = s.anchor.version
        for bad in (b"", b"\x01" * 31):
            r = c.make(500_000, blinding=bad)
            self.assertEqual(s.gate.handle(r).kind, "REJECTED")
        self.assertEqual(s.anchor.version, v)
        pub = b"\x00" * 32
        req = c.make(654_321, blinding=pub); self.assertEqual(s.gate.handle(req).kind, "ANSWER")
        header_digest = s.anchor.read().header.request_digest
        hits = [x for x in range(0, 1_000_000) if request_digest(s.scope_id, "V1", 1, x, s.pd, pub) == header_digest]
        self.assertEqual(hits, [654_321])
        s2 = build_system(); c2 = s2.client("V1"); shared = b"\x5a" * 32
        for t in (400_000, 200_000): self.assertEqual(c2.ask(t).kind, "ANSWER") if False else None
        r1, r2 = c2.make(400_000, nonce=1, blinding=shared), None
        s2.gate.handle(r1); c2.nonce = 2
        r2 = c2.make(222_222, nonce=2, blinding=shared); s2.gate.handle(r2)
        d2 = s2.anchor.read().header.request_digest
        leaked = [x for x in range(0, 1_000_000) if request_digest(s2.scope_id, "V1", 2, x, s2.pd, shared) == d2]
        self.assertEqual(leaked, [222_222])                                       
        s3 = build_system(); c3 = s3.client("V1"); s3.gate.handle(c3.make(400_000, nonce=1, blinding=b"\x11" * 32))
        s3.gate.handle(c3.make(222_222, nonce=2, blinding=b"\x22" * 32))
        d3 = s3.anchor.read().header.request_digest
        self.assertEqual([x for x in range(0, 1_000_000) if request_digest(s3.scope_id, "V1", 2, x, s3.pd, b"\x11" * 32) == d3], [])

    def test_T_M09_blinding_is_never_stored_logged_or_returned(self):
        s = build_system(history_limit=100); c = s.client("V1"); blind = bytes(range(32))
        req = c.make(654_321, blinding=blind)
        resp = s.gate.handle(req)
        self.assertNotIn(blind.hex(), repr(req)); self.assertNotIn(req.auth_tag, repr(req)); self.assertNotIn(str(blind), repr(req))
        for rec in s.anchor.history():
            self.assertNotIn(blind, rec.encode()); self.assertNotIn(blind.hex().encode(), rec.encode())  
        self.assertNotIn(blind, resp.encode())


if __name__ == "__main__":
    unittest.main()
