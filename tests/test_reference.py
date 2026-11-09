import itertools, random, unittest
from fractions import Fraction
from core.policy import Interval, Kind, Policy, advance, decide
from harness.system import build_system
from tests.reference_model import ref_decide, ref_simulate


def kind_name(d):
    return d.kind.value


class ReferenceModel(unittest.TestCase):
    def test_T_X01_exhaustive_decision_vs_reference(self):
        lo, hi, W = 0, 49, 5
        pol = Policy(lo, hi, W)
        n = 0
        for a in range(lo, hi + 1):
            for b in range(a, hi + 1):
                F = set(range(a, b + 1))
                for t in range(-3, 53):
                    d = decide(pol, Interval(a, b), t)
                    kind, forced = ref_decide(F, t, W)
                    self.assertEqual(d.kind.value, kind, (a, b, t))
                    if kind == "DETERMINED":
                        self.assertEqual(d.forced_answer, forced, (a, b, t))
                    n += 1
        polk = Policy(lo, hi, W, K=2)
        for a, b, t, c in itertools.product(range(0, 50, 7), range(20, 50, 6), range(-2, 52, 3), range(0, 4)):
            if a > b: continue
            F = set(range(a, b + 1))
            self.assertEqual(decide(polk, Interval(a, b), t, c).kind.value, ref_decide(F, t, W, 2, c)[0])
        self.assertGreater(n, 70_000)

    def test_T_X02_reachable_states_respect_floor(self):
        lo, hi, W = 0, 63, 8
        pol = Policy(lo, hi, W)
        seen, frontier = {Interval(lo, hi)}, [Interval(lo, hi)]
        while frontier:
            iv = frontier.pop()
            self.assertGreaterEqual(iv.size, W, iv)
            for t in range(-2, 66):
                d = decide(pol, iv, t)
                if d.kind is Kind.INFORMATIVE:
                    for ans in (True, False):
                        nxt = advance(iv, t, ans)
                        if nxt not in seen:
                            seen.add(nxt); frontier.append(nxt)
        self.assertGreater(len(seen), 100)
        self.assertTrue(all(s.size >= W for s in seen))

    def _transcripts(self, pol, thresholds, depth, verifiers):
        lo, hi = pol.lo, pol.hi
        for seq in itertools.product(thresholds, repeat=depth):
            qs = [(verifiers[i % len(verifiers)], t) for i, t in enumerate(seq)]
            by_transcript, finals = {}, {}
            for v in range(lo, hi + 1):
                s = build_system(pol, secret=v, verifier_ids=tuple(verifiers))
                cl = {x: s.client(x) for x in verifiers}
                tr = tuple(cl[vid].ask(t).encode() for vid, t in qs)
                _, F = ref_simulate(lo, hi, pol.W, None, v, qs)
                by_transcript.setdefault(tr, set()).add(v)
                finals[v] = (tr, F)
            yield by_transcript, finals

    def test_T_X03_transcript_indistinguishability_gate_level(self):
        """ALL sequences of length 1, 2 and 3 over ALL 17 behaviourally distinct thresholds (-1..15) of D=[0,15], W=2,
        two verifiers alternating (caps disabled, so verifier identity cannot change a decision). Length >= 4 is NOT covered."""
        pol = Policy(0, 15, 2)
        runs = 0
        for depth in (1, 2, 3):
            for by_tr, finals in self._transcripts(pol, list(range(-1, 16)), depth, ["V1", "V2"]):
                for v, (tr, F) in finals.items():
                    self.assertEqual(by_tr[tr], F, (v, tr))
                    runs += 1
        self.assertGreater(runs, 80_000)

    def test_T_X04_guessing_bound_exhaustive_tiny_domain(self):
        lo, hi, W = 0, 15, 2
        pol = Policy(lo, hi, W); N = hi - lo + 1
        def leaves(strategy):
            out = []
            for secret in range(lo, hi + 1):
                iv, n = Interval(lo, hi), 0
                while n < 40:
                    t = strategy(iv)
                    d = decide(pol, iv, t)
                    if d.kind is not Kind.INFORMATIVE:
                        alt = [x for x in range(iv.lo, iv.hi) if decide(pol, iv, x).kind is Kind.INFORMATIVE]
                        if not alt: break
                        t = alt[len(alt) // 2]
                    iv = advance(iv, t, secret > t); n += 1
                out.append(iv)
            return out
        for strat in (lambda iv: (iv.lo + iv.hi) // 2, lambda iv: iv.lo + 1):
            L = leaves(strat)
            self.assertTrue(all(i.size >= W for i in L))
            distinct = set(L)
            self.assertEqual(sum(i.size for i in distinct), N)           
            success = Fraction(len(distinct), N)                         
            self.assertLessEqual(success, Fraction(1, W))

    def test_T_X05_randomized_vs_reference(self):
        rng = random.Random(20260101)
        lo, hi, W = 0, 9_999, 1_000                                      
        pol = Policy(lo, hi, W)
        for _ in range(400):
            secret = rng.randint(lo, hi)
            qs = [("V1", rng.randint(-50, hi + 50)) for _ in range(12)]
            tr, F = ref_simulate(lo, hi, W, None, secret, qs)
            iv, got = Interval(lo, hi), []
            for _, t in qs:
                d = decide(pol, iv, t)
                if d.kind is Kind.REFUSED: got.append(("REFUSED",))
                elif d.kind is Kind.DETERMINED: got.append(("ANSWER", d.forced_answer))
                else:
                    a = secret > t; iv = advance(iv, t, a); got.append(("ANSWER", a))
            self.assertEqual(got, tr)
            self.assertEqual((iv.lo, iv.hi), (min(F), max(F)))
            self.assertEqual(iv.size, len(F))
        P = Policy(0, 999_999, 10_000)
        for _ in range(60_000):
            a = rng.randint(0, 999_999); b = rng.randint(a, 999_999); t = rng.randint(-10, 1_000_010)
            yes, no = range(max(a, t + 1), b + 1), range(a, min(b, t) + 1)
            exp = ("D" if (len(yes) == 0 or len(no) == 0) else "R" if (len(yes) < 10_000 or len(no) < 10_000) else "I")
            d = decide(P, Interval(a, b), t)
            self.assertEqual({"DETERMINED": "D", "REFUSED": "R", "INFORMATIVE": "I"}[d.kind.value], exp, (a, b, t))


if __name__ == "__main__":
    unittest.main()
