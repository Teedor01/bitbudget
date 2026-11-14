import re, shutil, subprocess, sys, tempfile, unittest, pathlib

CLAIMS = {
    "C-1  feasible-set floor":                    ["P01", "P02", "P03", "P04", "X02", "A02", "A03", "A04", "A05"],
    "C-2  decision purity (secret-independent)":  ["P07", "X01", "X03"],
    "C-3  floor holds over decisions too":        ["X03", "A09", "M06"],
    "C-4  guessing-advantage bound (metric+A1)":  ["X04", "R03"],
    "C-6  baseline leaks exact value; gate stops": ["A01", "A02"],
    "C-7  linear history (test double only)":     ["S04", "S08"],
    "C-8  release-after-commit (test double)":    ["S05", "S09"],
    "C-9  idempotent retries / crash recovery":   ["S01", "S02", "S03", "S05", "S09", "S10", "S11"],
    "C-13 metadata uniformity (structural)":      ["M01", "M02", "M03", "M04", "M05", "M06", "M07"],
    "C-14 caps never weaken the floor; exhaustion limited": ["P08", "S15", "S16", "S20", "S21", "S22", "A06", "A07", "A08"],
    "C-15 scope: reissuance resets budget":       ["R01"],
    "C-20 layering / offline / $0":               ["L01", "L02", "L03"],
    "C-21 client policy for stale-read REJECTED": ["H01", "H02", "H03", "H04", "H05", "H06", "H07", "H08", "H09", "H10"],
    "C-22 blinding: scope of protection (narrowed)": ["M07", "M08", "M09"],
}
NOT_DEMONSTRATED = ["C-10 rollback resistance", "C-11 confidentiality", "C-12 attestation",
                    "C-17 OutLayer integration", "C-18 payments", "C-26 web app live mode run on NEAR testnet"]
# Evidence produced OUTSIDE this checker (needs a Rust toolchain); recorded in NEAR_EVIDENCE.md, never re-run here.
EXTERNAL = ["C-23 anchor contract compiles, 11 Rust unit tests pass, wasm executes in the nearcore VM crate",
            "C-24 anchor contract + adapter on NEAR testnet: deployed, live self-test 10/10 (owner-reported single run)",
            "C-25 web app live NEAR mode wiring (22 cases against the contract model; not a browser; never run on testnet)"]

MUTATIONS = [  # id, file, old, new, tests expected to catch it
    ("T-MUT01", "core/policy.py", "if yes.size < policy.W or no.size < policy.W:", "if yes.size <= policy.W or no.size <= policy.W:", ["T_P01", "T_P02", "T_P03", "T_P04"]),
    ("T-MUT02", "core/gate.py", "dec = decide(self.policy, iv, req.threshold, vs.informative)",
     "dec = decide(self.policy, iv, req.threshold, vs.informative)\n        if dec.kind is Kind.INFORMATIVE and self.secret % 2 == 0:\n            dec = Decision(Kind.REFUSED, Reason.FLOOR, None)", ["T_X03", "T_A09", "T_M06"]),
    ("T-MUT03", "core/gate.py", "if result is CasResult.CONFLICT:\n            return Response.retry()", "if result is CasResult.CONFLICT:\n            return resp", ["T_S04", "T_S08"]),
    ("T-MUT04", "testdoubles/local_anchor.py", "if cur.header.version != expected_version or cur.digest() != expected_digest:\n            return CasResult.CONFLICT", "if False:\n            return CasResult.CONFLICT", ["T_S04", "T_S07", "T_S08"]),
    ("T-MUT05", "core/policy.py", "if yes.size < policy.W or no.size < policy.W:", "if policy.K is None and (yes.size < policy.W or no.size < policy.W):", ["T_S15", "T_S16", "T_S20", "T_S21", "T_S22"]),  # T_P08 deliberately NOT run here
    ("T-MUT06", "core/gate.py", "if req.scope_id != self.scope_id or req.policy_digest != self.pd:\n            return Response.rejected()", "if False:\n            return Response.rejected()", ["T_S12"]),
    ("T-MUT07", "core/gate.py", 'resp, code = Response.refused(), "REFUSED"', 'resp, code = (Response.refused() if dec.reason is Reason.FLOOR else Response("REFUSED_CAP")), "REFUSED"', ["T_M03", "T_M04"]),
    ("T-MUT08", "core/policy.py", "return self.hi - self.lo + 1", "return self.hi - self.lo", ["T_P03", "T_X01"]),
    ("T-MUT09", "core/gate.py", "return self._replay(vs) if d == vs.last_digest else Response.rejected()", "return self._replay(vs)", ["T_S02", "T_S18"]),
    ("T-MUT10", "core/gate.py", "return self._resolve_unknown(rec, new_rec, resp)", "return resp", ["T_S05"]),
    ("T-MUT11", "core/gate.py", "if quota_exceeded(self.policy, vs.requests):\n            return Response.rejected()", "if False:\n            return Response.rejected()", ["T_S15", "T_S18", "T_A08"]),
    ("T-MUT13", "core/policy.py", "if yes.size < policy.W or no.size < policy.W:", "if yes.size < (policy.W if policy.K is None else policy.W // 2) or no.size < (policy.W if policy.K is None else policy.W // 2):", ["T_S20", "T_S21", "T_S22"]),
    ("T-MUT14", "core/policy.py", "if yes.size < policy.W or no.size < policy.W:", "if policy.R is None and (yes.size < policy.W or no.size < policy.W):", ["T_S20", "T_S21", "T_S22"]),
    ("T-MUT15", "core/gate.py", "or len(req.blinding) < MIN_BLINDING_BYTES:", "or False:", ["T_M08", "T_H10"]),
    ("T-MUT16", "harness/client_policy.py", 'if resp.kind in ("ANSWER", "REFUSED"):', 'if resp.kind in ("ANSWER", "REFUSED", "REJECTED"):', ["T_H01", "T_H02", "T_H03"]),
    ("T-MUT17", "core/gate.py", "if req.nonce != vs.last_nonce + 1:", "if req.nonce < vs.last_nonce + 1:", ["T_S03", "T_H02", "T_S18"]),
    ("T-MUT18", "harness/client_policy.py", "if any(n == req.nonce and dd != d for n, dd in mine):", "if False:", ["T_H05"]),
    ("T-MUT19", "harness/client_policy.py", "if self.pending is None or not complete or any(n == self.pending.nonce for n, _ in mine):", "if self.pending is None:", ["T_H08", "T_H09"]),
    ("T-MUT12", "core/gate.py", "new_iv, informative = iv, vs.informative", "new_iv, informative = iv, vs.informative\n        if dec.kind is Kind.REFUSED:\n            return Response.refused()", ["T_M02", "T_S19"]),
]


APP_MUTATIONS = [   # id, file, old, new, expected failing APP tests (any one kills it)
    ("APP-MUT01 verifier response leaks the auditor view", "app/service.py", '"response": e["verifier_view"]["response"], "answer": e["verifier_view"]["answer"]}', '"response": e["verifier_view"]["response"], "answer": e["verifier_view"]["answer"], "auditor_view": e["auditor_view"]}', ["APP02", "APP04", "APP17"]),
    ("APP-MUT02 owner token not checked", "app/service.py", "if not isinstance(token, str) or not hmac.compare_digest(token.encode(), s.owner_token.encode()):", "if False:", ["APP18", "APP21", "APP07"]),
    ("APP-MUT03 Host header not checked", "app/server.py", 'if allowed_hosts and (self.headers.get("Host") or "").lower() not in allowed_hosts:', "if False:", ["APP21"]),
    ("APP-MUT04 Content-Type not checked", "app/server.py", 'if ctype != "application/json":', "if False:", ["APP21"]),
    ("APP-MUT05 CSP loses form-action", "app/server.py", "form-action 'self'; ", "", ["APP11", "APP24"]),
    ("APP-MUT06 story session registered globally", "app/service.py", "steps, first_refusal = [], None", 'self._sessions["demo"] = s; steps, first_refusal = [], None', ["APP20"]),
    ("APP-MUT07 story thresholds changed", "app/service.py", "62_500, 93_750", "70_000, 93_750", ["APP19", "APP23"]),
    ("APP-MUT08 verifier call carries the owner token", "web/app.js", '{ verifier_id: $("verifier").value, threshold: t });', '{ verifier_id: $("verifier").value, threshold: t }, ownerToken);', ["APP22"]),
    ("APP-MUT09 verifier panel text mentions the feasible range", "web/index.html", "A verifier sees only YES, NO or REFUSED.", "A verifier sees the feasible range.", ["APP22"]),
    ("APP-MUT10 create form does not preventDefault", "web/app.js", '$("create-form").addEventListener("submit", (ev) => {\n    ev.preventDefault();', '$("create-form").addEventListener("submit", (ev) => {', ["APP23"]),
    ("APP-MUT11 no in-flight guard", "web/app.js", "if (busy) return;", "", ["APP23"]),
    ("APP-MUT12 session-gone state not reset", "web/app.js", 'session = null; ownerToken = null;\n    $("owner-view").hidden = true;', 'session = null; ownerToken = null;\n    ', ["APP23"]),
    ("APP-MUT13 network error message lost", "web/app.js", 'throw new Error("Cannot reach the local server. Is it still running?");', "throw e;", ["APP23"]),
    ("APP-MUT14 notice overwritten after create", "web/app.js", "session = s.session_id; ownerToken = s.owner_token;", 'session = s.session_id; ownerToken = s.owner_token; $("notice").textContent = s.notice;', ["APP25"]),
    ("APP-MUT15 focus styles removed", "web/style.css", "button:focus-visible, input:focus-visible, select:focus-visible, summary:focus-visible { outline:2px solid var(--accent); outline-offset:2px; }", "", ["APP24"]),
    ("APP-MUT16 story shows wrong candidate count", "web/app.js", 'fmtCount(size) + " candidates left"', 'fmtCount(size + 1) + " candidates left"', ["APP23"]),
    ("APP-MUT17 engine floor off-by-one", "core/policy.py", "if yes.size < policy.W or no.size < policy.W:", "if yes.size <= policy.W or no.size <= policy.W:", ["APP02", "APP08", "APP03"]),
]


def run_app_mutations():
    root = pathlib.Path(".").resolve(); allkilled = True
    print("APPLICATION MUTATION CHECKS (each must make an application test fail):")
    for mid, f, old, new, expect in APP_MUTATIONS:
        old, new = old.replace("\\n", "\n"), new.replace("\\n", "\n")
        tmp = pathlib.Path(tempfile.mkdtemp())
        try:
            for d in ("core", "testdoubles", "harness", "tests", "app", "web"):
                shutil.copytree(root / d, tmp / d, ignore=shutil.ignore_patterns("__pycache__"))
            src = (tmp / f).read_text(); assert src.count(old) == 1, (mid, "pattern not unique/absent", src.count(old))
            (tmp / f).write_text(src.replace(old, new))
            r = subprocess.run([sys.executable, "-m", "unittest", "tests.test_app"], cwd=tmp, capture_output=True, text=True, timeout=300)
            failed = sorted(set(re.findall(r"^(?:FAIL|ERROR): test_(APP\d+)", r.stderr, re.M)))
            killed = bool(failed); allkilled &= killed
            print(f"  {'KILLED' if killed else 'SURVIVED (test gap!)':20} {mid}: {failed}")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    return allkilled


def ids(name):
    m = re.search(r"T_([A-Z]+\d+)", name)
    return m.group(1) if m else None


class Collect(unittest.TextTestResult):
    passed, failed = None, None
    def startTestRun(self):
        Collect.passed, Collect.failed = set(), set()
    def addSuccess(self, t):
        super().addSuccess(t); Collect.passed.add(ids(t._testMethodName))
    def addFailure(self, t, e):
        super().addFailure(t, e); Collect.failed.add(ids(t._testMethodName))
    def addError(self, t, e):
        super().addError(t, e); Collect.failed.add(ids(t._testMethodName))


def run_all():
    suite = unittest.defaultTestLoader.discover("tests", top_level_dir=".")
    res = unittest.TextTestRunner(resultclass=Collect, verbosity=0).run(suite)
    print(f"\nTests run: {res.testsRun}  failures: {len(res.failures)}  errors: {len(res.errors)}")
    ok = True
    print("\nCLAIM EVIDENCE (a claim is supported only if ALL its tests ran and passed):")
    for claim, tests in CLAIMS.items():
        bad = [t for t in tests if t in Collect.failed]
        missing = [t for t in tests if t not in Collect.passed and t not in Collect.failed]
        status = "SUPPORTED (locally)" if not bad and not missing else "BLOCKED"
        ok &= status.startswith("SUPPORTED")
        print(f"  {status:20} {claim}   tests: {','.join(tests)}" + (f"   FAILED: {bad}" if bad else "") + (f"   NOT RUN: {missing}" if missing else ""))
    for c in NOT_DEMONSTRATED:
        print(f"  {'NOT DEMONSTRATED':20} {c}   (no local test can establish it)")
    for c in EXTERNAL:
        print(f"  {'EXTERNAL EVIDENCE':20} {c}   (not re-run by this checker; see NEAR_EVIDENCE.md)")
    return ok and res.wasSuccessful()


def run_mutations():
    root = pathlib.Path(".").resolve(); allkilled = True
    print("MUTATION CHECKS (each mutation must make a mapped test fail):")
    for mid, f, old, new, expect in MUTATIONS:
        tmp = pathlib.Path(tempfile.mkdtemp())
        try:
            for d in ("core", "testdoubles", "harness", "tests", "app", "web"):
                shutil.copytree(root / d, tmp / d, ignore=shutil.ignore_patterns("__pycache__"))
            src = (tmp / f).read_text()
            assert src.count(old) == 1, (mid, "pattern not unique/absent", src.count(old))
            (tmp / f).write_text(src.replace(old, new))
            cmd = [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-t", "."]
            for e in expect: cmd += ["-k", e]
            r = subprocess.run(cmd, cwd=tmp, capture_output=True, text=True, timeout=900)
            failed = sorted({ids(m) for m in re.findall(r"^(?:FAIL|ERROR): (test_\w+)", r.stderr, re.M)})
            killed = bool(failed)
            allkilled &= killed
            print(f"  {mid}: {'KILLED' if killed else 'SURVIVED (test gap!)'}  mutated {f}  failing tests: {failed}")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    return allkilled


def killmatrix():
    """For the floor-vs-caps mutations, run each candidate test ALONE and show which ones kill it."""
    root = pathlib.Path(".").resolve(); cands = ["P08", "X01", "S15", "S16", "S20", "S21", "S22"]; ok = True
    print("KILL MATRIX (each test run alone against the mutated copy; K = killed, . = survived):")
    print("  mutation   " + "  ".join(f"{c:>4}" for c in cands))
    for mid, f, old, new, _ in MUTATIONS:
        if mid not in ("T-MUT05", "T-MUT13", "T-MUT14"):
            continue
        tmp = pathlib.Path(tempfile.mkdtemp()); row = []
        try:
            for d in ("core", "testdoubles", "harness", "tests"):
                shutil.copytree(root / d, tmp / d, ignore=shutil.ignore_patterns("__pycache__"))
            src = (tmp / f).read_text(); assert src.count(old) == 1
            (tmp / f).write_text(src.replace(old, new))
            for c in cands:
                r = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-t", ".", "-k", "T_" + c],
                                   cwd=tmp, capture_output=True, text=True, timeout=900)
                row.append("K" if r.returncode != 0 else ".")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        print(f"  {mid}   " + "  ".join(f"{x:>4}" for x in row))
        ok &= any(x == "K" for c, x in zip(cands, row) if c != "P08")      # must be killed by a non-P08 test
    return ok


def docs_check():
    """Consistency between tests, claims checker and documents."""
    root = pathlib.Path("."); bad = []
    test_ids = set()
    for f in sorted((root / "tests").glob("test_*.py")):
        test_ids |= set(re.findall(r"def test_T_([A-Z]+\d+)", f.read_text()))
    mut_ids = {m[0].replace("T-", "") for m in MUTATIONS}
    docs = {n: (root / n).read_text() for n in ("TEST_PLAN.md", "CLAIMS_MATRIX.md", "SECURITY_SPEC.md",
                                                  "IMPLEMENTATION_PLAN.md", "README.md", "HARDENING_REPORT.md")}
    def expand(text):
        out = set()
        for m in re.finditer(r"T-([A-Z]+)(\d+)(?:\.\.(?:T-)?([A-Z]*)(\d+))?", text):
            p, a, p2, b = m.group(1), int(m.group(2)), m.group(3) or m.group(1), m.group(4)
            if b is None: out.add(f"{p}{a:02d}")
            elif p2 == p: out |= {f"{p}{i:02d}" for i in range(a, int(b) + 1)}
        return out
    referenced = set().union(*(expand(t) for t in docs.values()))
    for r in sorted(referenced):
        if r not in test_ids and r not in mut_ids:
            bad.append(f"documents reference T-{r} but no such test or mutation exists")
    for t in sorted(test_ids):
        if t not in expand(docs["TEST_PLAN.md"]):
            bad.append(f"test T-{t} exists but is not described in TEST_PLAN.md")
    for t in sorted(mut_ids):
        if t not in expand(docs["TEST_PLAN.md"]):
            bad.append(f"mutation T-{t} not described in TEST_PLAN.md")
    for claim, tests in CLAIMS.items():
        for t in tests:
            if t not in test_ids: bad.append(f"{claim}: maps to missing test T-{t}")
    matrix_ids = set(re.findall(r"^\| (C-\d+) \|", docs["CLAIMS_MATRIX.md"], re.M))
    checker_ids = {k.split()[0] for k in CLAIMS} | {k.split()[0] for k in NOT_DEMONSTRATED} | {k.split()[0] for k in EXTERNAL} | {"C-5", "C-16", "C-19"}
    for c in sorted(matrix_ids ^ checker_ids): bad.append(f"claim {c} differs between CLAIMS_MATRIX.md and claims_check.py")
    n_total = unittest.defaultTestLoader.discover("tests", top_level_dir=".").countTestCases()
    n_tests = len(test_ids)                      # engine tests carry T-IDs; application tests are APPnn
    n_app = n_total - n_tests
    for name in ("CLAIMS_MATRIX.md", "README.md", "HARDENING_REPORT.md", "APPLICATION.md", "UI_AUDIT.md"):
        if name not in docs and (root / name).exists(): docs[name] = (root / name).read_text()
        for m in re.finditer(r"(\d+) tests", docs.get(name, "")):
            if int(m.group(1)) not in (n_tests, n_total): bad.append(f"{name} says {m.group(1)} tests; suite has {n_tests} engine + {n_app} application = {n_total}")
    print(f"DOCS CONSISTENCY: {n_total} tests ({n_tests} engine + {n_app} application), {len(test_ids)} test IDs, {len(mut_ids)} mutation IDs, {len(matrix_ids)} claims")
    for b in bad: print("  PROBLEM:", b)
    print("  OK" if not bad else f"  {len(bad)} problem(s)")
    return not bad


if __name__ == "__main__":
    ok = (run_app_mutations() if "--appmutations" in sys.argv else run_mutations() if "--mutations" in sys.argv else killmatrix() if "--killmatrix" in sys.argv
          else docs_check() if "--docs" in sys.argv else run_all())
    sys.exit(0 if ok else 1)
