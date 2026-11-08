import ast, pathlib, unittest
from core.policy import Interval, Kind, Policy, Reason, advance, branches, decide, quota_exceeded

P = Policy(0, 999_999, 10_000)
FULL = Interval(0, 999_999)


def kr(pol, iv, t, count=0):
    d = decide(pol, iv, t, count)
    return d.kind, d.reason, d.forced_answer


class PolicyBoundaries(unittest.TestCase):
    def test_T_P01_lower_boundary(self):
        exp = {-1: (Kind.DETERMINED, Reason.NONE, True), 0: (Kind.REFUSED, Reason.FLOOR, None),
               9_997: (Kind.REFUSED, Reason.FLOOR, None), 9_998: (Kind.REFUSED, Reason.FLOOR, None),
               9_999: (Kind.INFORMATIVE, Reason.NONE, None), 10_000: (Kind.INFORMATIVE, Reason.NONE, None)}
        for t, e in exp.items():
            self.assertEqual(kr(P, FULL, t), e, f"t={t}")
        yes, no = branches(FULL, 9_998); self.assertEqual(no.size, 9_999)
        yes, no = branches(FULL, 9_999); self.assertEqual(no.size, 10_000)

    def test_T_P02_upper_boundary(self):
        exp = {989_998: Kind.INFORMATIVE, 989_999: Kind.INFORMATIVE, 990_000: Kind.REFUSED,
               990_001: Kind.REFUSED, 999_998: Kind.REFUSED, 999_999: Kind.DETERMINED, 1_000_000: Kind.DETERMINED}
        for t, k in exp.items():
            self.assertEqual(decide(P, FULL, t).kind, k, f"t={t}")
        self.assertEqual(decide(P, FULL, 999_999).forced_answer, False)
        self.assertEqual(branches(FULL, 989_999)[0].size, 10_000)
        self.assertEqual(branches(FULL, 990_000)[0].size, 9_999)

    def test_T_P03_interior_exact_floor_and_one_below(self):
        a = 100_000; iv = Interval(a, a + 19_999)
        self.assertEqual(iv.size, 20_000)
        self.assertEqual(decide(P, iv, a + 9_998).kind, Kind.REFUSED)       
        self.assertEqual(decide(P, iv, a + 9_999).kind, Kind.INFORMATIVE)   
        self.assertEqual(decide(P, iv, a + 10_000).kind, Kind.REFUSED)     
        self.assertEqual(branches(iv, a + 9_999)[0].size, 10_000)
        self.assertEqual(branches(iv, a + 9_999)[1].size, 10_000)

    def test_T_P04_interval_exactly_at_floor(self):
        a = 50_000; iv = Interval(a, a + 9_999)
        self.assertEqual(iv.size, 10_000)
        for t in range(a, a + 9_999):
            self.assertEqual(decide(P, iv, t).kind, Kind.REFUSED, t)
        self.assertEqual(decide(P, iv, a - 1).kind, Kind.DETERMINED)
        self.assertEqual(decide(P, iv, a + 9_999).kind, Kind.DETERMINED)

    def test_T_P05_repeated_and_implied_queries_are_determined(self):
        iv = advance(FULL, 500_000, False)                 
        self.assertEqual(iv, Interval(0, 500_000))
        d = decide(P, iv, 500_000); self.assertEqual((d.kind, d.forced_answer), (Kind.DETERMINED, False))
        d = decide(P, iv, 700_000); self.assertEqual((d.kind, d.forced_answer), (Kind.DETERMINED, False))
        self.assertEqual(advance(iv, 700_000, False), iv)   
        with self.assertRaises(ValueError):
            advance(iv, 700_000, True)                      

    def test_T_P06_invalid_policies(self):
        for bad in (dict(lo=0, hi=19_998, W=10_000), dict(lo=0, hi=999, W=0), dict(lo=5, hi=1, W=1),
                    dict(lo=0, hi=999, W=10, K=0), dict(lo=0, hi=999, W=10, R=0), dict(lo=0, hi=999.0, W=10)):
            with self.assertRaises(ValueError):
                Policy(**bad)
        Policy(0, 19_999, 10_000)                         

    def test_T_P07_integers_only_and_static_scan(self):
        for bad in (5.0, True):
            with self.assertRaises(TypeError):
                decide(P, FULL, bad)
        src = pathlib.Path("core/policy.py").read_text()
        tree = ast.parse(src)
        floats = [n for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, float)]
        self.assertEqual(floats, [])
        imports = set()
        for n in ast.walk(tree):
            if isinstance(n, ast.Import): imports |= {a.name.split(".")[0] for a in n.names}
            if isinstance(n, ast.ImportFrom): imports.add(n.module.split(".")[0])
        self.assertEqual(imports, {"dataclasses", "enum", "typing"})
        self.assertNotIn("secret", src.lower().replace("secret is never an input", ""))

    def test_T_P08_caps_only_add_restrictions(self):
        Pk = Policy(0, 999_999, 10_000, K=2, R=3)
        self.assertEqual(kr(Pk, FULL, 500_000, 0)[0], Kind.INFORMATIVE)
        self.assertEqual(kr(Pk, FULL, 500_000, 2), (Kind.REFUSED, Reason.CAP, None))
        self.assertEqual(decide(Pk, FULL, 1_500_000, 2).kind, Kind.DETERMINED)   
        # a cap never allows what the floor refuses
        for count in (0, 1, 2, 5):
            self.assertEqual(decide(Pk, FULL, 9_998, count).kind, Kind.REFUSED)
            self.assertEqual(decide(Pk, FULL, 9_998, count).reason, Reason.FLOOR)
        self.assertFalse(quota_exceeded(Pk, 2)); self.assertTrue(quota_exceeded(Pk, 3))
        self.assertFalse(quota_exceeded(P, 10**9))         


if __name__ == "__main__":
    unittest.main()
