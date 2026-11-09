import ast, pathlib, random, unittest
from fractions import Fraction
from core.policy import Interval
from harness.system import DEMO_POLICY, FIXTURE_SECRET, build_system
from harness.attackers import adaptive_attack, make_query_fn

P = DEMO_POLICY
SRC_DIRS = ("core", "testdoubles", "harness")


def py_files(dirs):
    for d in dirs:
        yield from sorted(pathlib.Path(d).glob("*.py"))


def imports_of(path):
    tree = ast.parse(path.read_text()); out = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Import): out |= {a.name for a in n.names}
        if isinstance(n, ast.ImportFrom): out.add(n.module or "")
    return out


class Limitations(unittest.TestCase):
    def test_T_R01_reissuance_resets_budget_documented_limitation(self):
        s1, s2 = build_system(), build_system()               
        self.assertNotEqual(s1.scope_id, s2.scope_id)
        c1, c2 = s1.client("V1"), s2.client("V1")
        a, b = P.lo, P.hi
        for _ in range(200):
            if a == b: break
            t = (a + b) // 2
            r = c1.ask(t)
            if r.kind != "ANSWER":
                r = c2.ask(t)
            if r.kind != "ANSWER":
                for tt in (a + 1, b - 2, (a + b) // 2 + 1, (a + b) // 2 - 1, a, b - 1):
                    if a <= tt < b:
                        r = c1.ask(tt)
                        if r.kind != "ANSWER": r = c2.ask(tt)
                        if r.kind == "ANSWER": t = tt; break
            if r.kind != "ANSWER": break
            a, b = (t + 1, b) if r.answer else (a, t)
        self.assertLess(b - a + 1, P.W)                       
        self.assertTrue(a <= FIXTURE_SECRET <= b)
        self.assertGreaterEqual(s1.state().interval.size, P.W)  
        self.assertGreaterEqual(s2.state().interval.size, P.W)

    def test_T_R02_anchor_reverting_committed_state_breaks_the_floor_assumption_A4(self):
        s = build_system(); rng = random.Random(2)
        q = make_query_fn(s, ["V1"], rng)
        (a, b), _ = adaptive_attack(q, P.lo, P.hi, P.W, rng, "binary")
        self.assertGreaterEqual(b - a + 1, P.W)                 
        s.anchor._violate_revert_to(0)                           
        c = s.client("V1")
        for _ in range(60):
            if a == b: break
            t = (a + b) // 2
            r = c.ask(t)
            if r.kind != "ANSWER": break
            a, b = (t + 1, b) if r.answer else (a, t)
        self.assertLess(b - a + 1, P.W)                          

    def test_T_R03_non_uniform_prior_defeats_the_entropy_claim_but_not_the_count_claim(self):
        iv = Interval(78_125, 93_749)                           
        self.assertGreaterEqual(iv.size, P.W)
        spike = Fraction(9, 10)                                 
        guess = spike + (1 - spike) / iv.size                    
        self.assertGreater(guess, 100 * Fraction(1, P.W))        
        self.assertEqual(iv.size, 15_625)                        

    def test_T_L01_layering_and_import_boundaries(self):
        for f in py_files(("core",)):
            bad = {m for m in imports_of(f) if m.split(".")[0] in ("testdoubles", "harness", "tests", "integrations")}
            self.assertEqual(bad, set(), f)
        self.assertEqual({m.split(".")[0] for m in imports_of(pathlib.Path("core/policy.py"))},
                         {"dataclasses", "enum", "typing"})
        for f in list(py_files(SRC_DIRS)) + list(pathlib.Path("tests").glob("*.py")):
            if f.name in ("test_near_anchor.py", "test_near_app.py", "test_deploy_demo.py"):   
                continue
            self.assertFalse(any(m.split(".")[0] == "integrations" for m in imports_of(f)), f)

    def test_T_L03_integrations_boundary_stdlib_only(self):
        """Phase 4E adapter: may use stdlib + core + integrations only; no third-party or crypto packages; never
        imports testdoubles/harness/tests; no key material handling (the signer is an external binary)."""
        allowed_std = {"abc", "base64", "enum", "hashlib", "json", "os", "re", "subprocess", "tempfile", "time",
                       "urllib", "dataclasses", "typing"}
        files = list(py_files(("integrations",)))
        self.assertTrue(files)
        for f in files:
            mods = {m.split(".")[0] for m in imports_of(f)}
            self.assertEqual(mods - allowed_std - {"core", "integrations", ""}, set(), f)
            self.assertEqual(mods & {"testdoubles", "harness", "tests", "cryptography", "nacl", "Crypto", "hmac"}, set(), f)
            self.assertNotIn("private_key", f.read_text().replace("sign-with-plaintext-private-key", ""), f)

    def test_T_L02_offline_and_zero_cost_static_scan(self):
        forbidden = {"socket", "http", "urllib", "requests", "subprocess", "ssl", "ftplib", "smtplib", "asyncio",
                     "sqlite3", "pickle", "ctypes", "cryptography", "nacl", "Crypto"}
        for f in py_files(SRC_DIRS):
            mods = {m.split(".")[0] for m in imports_of(f)}
            self.assertEqual(mods & forbidden, set(), f)
            text = f.read_text()
            self.assertNotIn("environ", text, f); self.assertNotIn("getenv", text, f)
            self.assertNotIn("open(", text, f)                   
        crypto_ok = {"hashlib", "hmac", "secrets"}               
        used = set()
        for f in py_files(SRC_DIRS):
            used |= {m for m in imports_of(f) if m in crypto_ok}
        self.assertTrue(used <= crypto_ok)


if __name__ == "__main__":
    unittest.main()
