import html.parser, http.client, json, pathlib, random, re, shutil, subprocess, threading, unittest

import app.service as service_mod
from app.server import CSP, make_server
from app.service import ApiError, Service
from core.policy import Interval, Policy, decide, advance
from harness.system import build_system

ROOT = pathlib.Path(__file__).resolve().parent.parent
VERIFIER_KEYS = {"verifier_id", "threshold", "response", "answer"}
AUDITOR_WORDS = ("feasible", "auditor", "reason", "anchor", "committed", "consistent", "policy_decision", "secret", "owner", "candidates")


def mk(income=83_250, **kw):
    svc = Service(); r = svc.create_session({"income_usd": income, **kw}); return svc, r["session_id"], r["owner_token"]


def last(svc, sid, tok):
    return svc.owner_view(sid, tok)["log"][-1]


class ServiceLayer(unittest.TestCase):
    def test_APP01_create_session_validates_input(self):
        svc = Service()
        for bad in ({}, {"income_usd": "5"}, {"income_usd": 5.5}, {"income_usd": True}, {"income_usd": -1},
                    {"income_usd": 1_000_000}, {"income_usd": 5, "K": 0}, {"income_usd": 5, "R": "x"}):
            with self.assertRaises(ApiError) as cm: svc.create_session(bad)
            self.assertEqual(cm.exception.status, 400, bad)
        ok = svc.create_session({"income_usd": 0}); self.assertEqual(ok["policy"]["floor"], 10_000)
        self.assertIn("SIMULATION", ok["notice"]); self.assertGreaterEqual(len(ok["owner_token"]), 20)

    def test_APP02_boundary_decisions_come_from_the_real_policy(self):
        svc, sid, tok = mk()
        r = svc.query(sid, {"verifier_id": "V1", "threshold": 9_998})
        self.assertEqual(r, {"verifier_id": "V1", "threshold": 9_998, "response": "REFUSED", "answer": None})
        a = last(svc, sid, tok)["auditor_view"]
        self.assertEqual((a["policy_decision"], a["reason"], a["feasible_after"]["size"]), ("REFUSED", "FLOOR", 1_000_000))
        r = svc.query(sid, {"verifier_id": "V1", "threshold": 9_999})                  
        self.assertEqual((r["response"], r["answer"]), ("ANSWER", True))
        a = last(svc, sid, tok)["auditor_view"]
        self.assertEqual((a["policy_decision"], a["feasible_after"]["lo"], a["feasible_after"]["size"]), ("INFORMATIVE", 10_000, 990_000))
        for t, ans in ((1_000_000, False), (-1, True)):
            r = svc.query(sid, {"verifier_id": "V2", "threshold": t})
            self.assertEqual((last(svc, sid, tok)["auditor_view"]["policy_decision"], r["answer"]), ("DETERMINED", ans))
        r = svc.query(sid, {"verifier_id": "V3", "threshold": 990_000})
        self.assertEqual((r["response"], last(svc, sid, tok)["auditor_view"]["reason"]), ("REFUSED", "FLOOR"))
        self.assertTrue(all(x["auditor_view"]["committed"] for x in svc.owner_view(sid, tok)["log"]))   

    def test_APP03_every_query_matches_the_engine_and_floor_always_holds(self):
        rng = random.Random(31)
        for K, R in ((None, None), (3, 40), (2, None)):
            svc, sid, tok = mk(rng.randint(0, 999_999), K=K, R=R)
            for _ in range(250):
                t = rng.choice([rng.randint(-5, 1_000_005), 9_998, 9_999, 990_000, 989_999])
                svc.query(sid, {"verifier_id": rng.choice(["V1", "V2", "V3"]), "threshold": t})
                e = last(svc, sid, tok)
                self.assertTrue(e["auditor_view"]["consistent_with_policy"], e)
                self.assertGreaterEqual(e["auditor_view"]["feasible_after"]["size"], 10_000)
            v = svc.owner_view(sid, tok); self.assertTrue(v["floor_holds"])
            self.assertEqual(v["anchor_version"], sum(1 for x in v["log"] if x["auditor_view"]["committed"]))

    def test_APP04_verifier_response_is_only_the_response_and_refusals_are_identical(self):
        svc, sid, tok = mk(K=1)
        a = svc.query(sid, {"verifier_id": "V1", "threshold": 9_998})                 
        svc.query(sid, {"verifier_id": "V2", "threshold": 500_000})
        b = svc.query(sid, {"verifier_id": "V2", "threshold": 250_000})               
        log = svc.owner_view(sid, tok)["log"]
        self.assertEqual((log[0]["auditor_view"]["reason"], log[2]["auditor_view"]["reason"]), ("FLOOR", "CAP"))
        self.assertEqual((a["response"], a["answer"]), (b["response"], b["answer"]))   
        for r in (a, b): self.assertEqual(set(r), VERIFIER_KEYS)

    def test_APP05_quota_rejection_is_not_committed(self):
        svc, sid, tok = mk(R=2)
        for t in (500_000, 250_000): svc.query(sid, {"verifier_id": "V1", "threshold": t})
        r = svc.query(sid, {"verifier_id": "V1", "threshold": 125_000}); a = last(svc, sid, tok)["auditor_view"]
        self.assertEqual((r["response"], a["policy_decision"], a["committed"], a["consistent_with_policy"]), ("REJECTED", "QUOTA_EXHAUSTED", False, True))
        self.assertEqual(svc.query(sid, {"verifier_id": "V2", "threshold": 125_000})["response"], "ANSWER")

    def test_APP06_attack_demo_floor_holds_and_shadow_session_is_untouched(self):
        for income in (0, 5_000, 83_250, 500_000, 989_999, 999_999):
            svc, sid, tok = mk(income)
            before = svc.owner_view(sid, tok)
            for strategy in ("binary", "squeeze"):
                r = svc.attack(sid, tok, {"strategy": strategy})
                self.assertTrue(r["baseline_stateless"]["secret_recovered"]); self.assertLessEqual(r["baseline_stateless"]["queries"], 20)
                g = r["gated"]
                self.assertTrue(g["floor_held"], (income, strategy)); self.assertFalse(g["secret_recovered"])
                self.assertEqual(g["attacker_feasible"], {k: g["gate_feasible"][k] for k in ("lo", "hi", "size")})
            after = svc.owner_view(sid, tok)
            for k in ("anchor_version", "feasible", "log", "verifiers", "transitions"): self.assertEqual(before[k], after[k], k)
        svc, sid, tok = mk()
        with self.assertRaises(ApiError): svc.attack(sid, tok, {"strategy": "nope"})

    def test_APP07_sessions_are_isolated_and_unknown_session_is_404(self):
        svc = Service(); a = svc.create_session({"income_usd": 100}); b = svc.create_session({"income_usd": 900_000})
        svc.query(a["session_id"], {"verifier_id": "V1", "threshold": 500_000})
        self.assertEqual(svc.owner_view(b["session_id"], b["owner_token"])["feasible"]["size"], 1_000_000)
        self.assertLess(svc.owner_view(a["session_id"], a["owner_token"])["feasible"]["size"], 1_000_000)
        with self.assertRaises(ApiError) as cm: svc.owner_view("missing", "x")
        self.assertEqual(cm.exception.status, 404)
        with self.assertRaises(ApiError) as cm: svc.owner_view(a["session_id"], b["owner_token"])      
        self.assertEqual(cm.exception.status, 403)

    def test_APP14_service_uses_the_real_engine_and_labels_the_simulation(self):
        import core.policy
        self.assertIs(service_mod.decide, core.policy.decide)
        svc, sid, tok = mk(); s = svc._sessions[sid]
        self.assertEqual(type(s.system.gate).__module__, "core.gate"); self.assertEqual(type(s.system.anchor).__name__, "LocalTestAnchor")
        self.assertIn("test-double anchor", service_mod.SIMULATION_NOTICE)

    def test_APP15_core_does_not_depend_on_the_application(self):
        for d in ("core", "testdoubles", "harness"):
            for f in (ROOT / d).glob("*.py"):
                self.assertNotRegex(f.read_text(), r"^\s*(from|import)\s+app\b", f)

    def test_APP16_owner_floor_indicator_is_computed_from_state_not_hardcoded(self):
        svc, sid, tok = mk()
        for vid, t in (("V1", 500_000), ("V2", 250_000), ("V3", 125_000), ("V1", 62_499)): svc.query(sid, {"verifier_id": vid, "threshold": t})
        self.assertLess(svc.owner_view(sid, tok)["feasible"]["size"], 100_000); self.assertTrue(svc.owner_view(sid, tok)["floor_holds"])
        svc._sessions[sid].policy = Policy(0, 999_999, 500_000)       
        v = svc.owner_view(sid, tok); self.assertFalse(v["floor_holds"]); self.assertEqual(v["floor"], 500_000)

    # ---- audit findings ----
    def test_APP17_verifier_facing_responses_contain_no_owner_or_auditor_information(self):
        rng = random.Random(8); svc, sid, tok = mk(120_000, K=3, R=30)
        for _ in range(120):
            r = svc.query(sid, {"verifier_id": rng.choice(["V1", "V2", "V3"]), "threshold": rng.choice([rng.randint(-3, 1_000_003), 9_998, 120_000])})
            self.assertEqual(set(r), VERIFIER_KEYS)
            text = json.dumps(r).lower()
            for w in AUDITOR_WORDS: self.assertNotIn(w, text)
            self.assertNotIn(tok, json.dumps(r)); self.assertNotIn("owner_secret", text)
            if r["response"] != "ANSWER": self.assertIsNone(r["answer"])
        created = svc.create_session({"income_usd": 5}); self.assertNotIn("owner_secret_usd", created)

    def test_APP18_owner_endpoints_require_the_owner_token(self):
        svc, sid, tok = mk(120_000)
        for bad in ("", None, "wrong", tok[:-1], tok + "x", 5):
            with self.assertRaises(ApiError) as cm: svc.owner_view(sid, bad)
            self.assertEqual(cm.exception.status, 403, bad)
            with self.assertRaises(ApiError) as cm: svc.attack(sid, bad, {"strategy": "binary"})
            self.assertEqual(cm.exception.status, 403, bad)
        self.assertEqual(svc.owner_view(sid, tok)["owner_secret_usd"], 120_000)
        self.assertIn("compare_digest", (ROOT / "app/service.py").read_text())

    def test_APP19_story_is_deterministic_and_every_number_comes_from_the_engine(self):
        svc = Service(); s1, s2 = svc.demo_story(), svc.demo_story()
        self.assertEqual(s1, s2)                                                        
        steps = s1["bit_budget"]["steps"]
        self.assertEqual([x["candidates_after"] for x in steps], [500_001, 250_001, 125_001, 62_500, 31_250, 15_625, 15_625, 15_625])
        self.assertEqual([x["verifier_sees"] for x in steps], ["NO", "NO", "NO", "YES", "YES", "YES", "REFUSED", "REFUSED"])
        self.assertEqual(s1["bit_budget"]["first_refusal_step"], 7); self.assertTrue(s1["bit_budget"]["floor_held"]); self.assertFalse(s1["bit_budget"]["secret_recovered"])
        pol, iv, secret = Policy(0, 999_999, 10_000), Interval(0, 999_999), s1["secret_usd"]
        for x in steps:
            d = decide(pol, iv, x["threshold"]); self.assertEqual(x["candidates_before"], iv.size)
            if d.kind.value == "INFORMATIVE": iv = advance(iv, x["threshold"], secret > x["threshold"])
            self.assertEqual(x["candidates_after"], iv.size); self.assertTrue(x["consistent_with_policy"])
            self.assertEqual(x["verifier_sees"] == "REFUSED", d.kind.value == "REFUSED")
        u = s1["unrestricted"]
        self.assertEqual((u["queries"], u["recovered_usd"], u["secret_recovered"], len(u["steps"])), (20, 120_000, True, 20))
        self.assertEqual(u["steps"][-1]["candidates"], 1); self.assertEqual(u["steps"][0]["candidates"], 500_000)
        self.assertEqual(s1["domain_size"], 1_000_000)

    def test_APP20_story_and_attack_share_no_state_with_user_sessions(self):
        svc, sid, tok = mk(777); before = svc.owner_view(sid, tok); n = len(svc._sessions)
        svc.demo_story(); svc.attack(sid, tok, {"strategy": "binary"}); svc.demo_story()
        self.assertEqual(len(svc._sessions), n)                                          
        self.assertEqual(before, svc.owner_view(sid, tok))
        a, b = Service().demo_story(), Service().demo_story(); self.assertEqual(a, b)    


class HttpCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = make_server("127.0.0.1", 0); cls.port = cls.srv.server_address[1]
        cls.t = threading.Thread(target=cls.srv.serve_forever, daemon=True); cls.t.start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown(); cls.srv.server_close(); cls.t.join(5)

    def call(self, method, path, body=None, raw=None, headers=None, ctype="application/json"):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        data = raw if raw is not None else (None if body is None else json.dumps(body).encode())
        h = {} if ctype is None else {"Content-Type": ctype}; h.update(headers or {})
        c.request(method, path, body=data, headers=h)
        r = c.getresponse(); payload = r.read(); c.close(); return r.status, r.getheader("Content-Type"), payload, r

    def j(self, method, path, body=None, **kw):
        st, ct, payload, r = self.call(method, path, body, **kw); return st, json.loads(payload)

    def new_session(self, income=83_250, **kw):
        st, d = self.j("POST", "/api/sessions", {"income_usd": income, **kw}); self.assertEqual(st, 201); return d["session_id"], d["owner_token"]


class HttpBackend(HttpCase):
    def test_APP08_full_vertical_slice_over_http(self):
        sid, tok = self.new_session(); own = {"X-Owner-Token": tok}
        st, r = self.j("POST", f"/api/sessions/{sid}/query", {"verifier_id": "V1", "threshold": 9_998})
        self.assertEqual((st, r), (200, {"verifier_id": "V1", "threshold": 9_998, "response": "REFUSED", "answer": None}))
        st, r = self.j("POST", f"/api/sessions/{sid}/query", {"verifier_id": "V2", "threshold": 9_999})
        self.assertEqual((st, r["response"], r["answer"]), (200, "ANSWER", True))
        st, v = self.j("GET", f"/api/sessions/{sid}", headers=own)
        self.assertEqual((st, v["owner_secret_usd"], v["anchor_version"], v["floor_holds"]), (200, 83_250, 2, True))
        e = v["log"][-1]; b = e["auditor_view"]["feasible_before"]              
        self.assertEqual(decide(Policy(0, 999_999, 10_000), Interval(b["lo"], b["hi"]), 9_999).kind.value, e["auditor_view"]["policy_decision"])
        self.assertEqual((len(v["transitions"]), len(v["log"])), (2, 2))
        st, ct, payload, resp = self.call("GET", f"/api/sessions/{sid}", headers=own)
        self.assertTrue(ct.startswith("application/json")); self.assertEqual(resp.getheader("Cache-Control"), "no-store")
        st, a = self.j("POST", f"/api/sessions/{sid}/attack", {"strategy": "squeeze"}, headers=own)
        self.assertEqual(st, 200); self.assertTrue(a["gated"]["floor_held"]); self.assertEqual(a["baseline_stateless"]["queries"], 20)
        st, story = self.j("GET", "/api/demo-story"); self.assertEqual((st, story["bit_budget"]["final_candidates"]), (200, 15_625))

    def test_APP09_http_error_handling(self):
        sid, tok = self.new_session()
        cases = [("POST", "/api/sessions", {"raw": b"{not json"}, 400), ("POST", "/api/sessions", {"raw": b"[1,2]"}, 400),
                 ("POST", "/api/sessions", {"body": {"income_usd": "x"}}, 400),
                 ("POST", f"/api/sessions/{sid}/query", {"body": {"verifier_id": "V1", "threshold": "5"}}, 400),
                 ("POST", f"/api/sessions/{sid}/query", {"body": {"verifier_id": "V1", "threshold": 5.5}}, 400),
                 ("POST", f"/api/sessions/{sid}/query", {"body": {"verifier_id": "V1", "threshold": 10 ** 13}}, 400),
                 ("POST", f"/api/sessions/{sid}/query", {"body": {"verifier_id": "VX", "threshold": 5}}, 400),
                 ("POST", "/api/sessions/nope/query", {"body": {"verifier_id": "V1", "threshold": 5}}, 404),
                 ("GET", "/api/sessions/bad%20id!", {}, 404), ("GET", "/nope", {}, 404), ("GET", "/api/sessions", {}, 404),
                 ("POST", "/api/sessions", {"raw": b"x" * 6000}, 413)]
        for method, path, kw, want in cases:
            st, ct, payload, _ = self.call(method, path, kw.get("body"), raw=kw.get("raw"))
            self.assertEqual(st, want, (method, path, payload[:80])); self.assertIn("error", json.loads(payload))

    def test_APP10_concurrent_http_clients_keep_one_consistent_history(self):
        sid, tok = self.new_session(); res = {}
        def worker(vid, seed):
            rng = random.Random(seed)
            res[vid] = [self.j("POST", f"/api/sessions/{sid}/query", {"verifier_id": vid, "threshold": rng.randint(0, 999_999)}) for _ in range(40)]
        ts = [threading.Thread(target=worker, args=(v, i)) for i, v in enumerate(("V1", "V2", "V3"))]
        [t.start() for t in ts]; [t.join() for t in ts]
        self.assertTrue(all(st == 200 and set(e) == VERIFIER_KEYS for v in res.values() for st, e in v))
        st, v = self.j("GET", f"/api/sessions/{sid}", headers={"X-Owner-Token": tok})
        self.assertTrue(v["floor_holds"]); self.assertEqual(len(v["log"]), 120)
        self.assertTrue(all(e["auditor_view"]["consistent_with_policy"] for e in v["log"]))
        self.assertEqual(v["anchor_version"], sum(1 for e in v["log"] if e["auditor_view"]["committed"]))

    def test_APP11_static_files_headers_and_offline_frontend(self):
        st, ct, html_, r = self.call("GET", "/", ctype=None); self.assertEqual(st, 200); self.assertTrue(ct.startswith("text/html"))
        self.assertEqual(r.getheader("Content-Security-Policy"), CSP)
        for part in ("default-src 'self'", "form-action 'self'", "frame-ancestors 'none'", "base-uri 'none'"): self.assertIn(part, CSP)
        self.assertNotIn("unsafe-inline", CSP); self.assertNotIn("unsafe-eval", CSP)
        for needed in (b'id="income"', b'id="ask"', b'id="threshold"', b'id="verdict"', b'Local simulation', b'does not encrypt', b'in-memory test double', b'mock'):
            self.assertIn(needed, html_)
        self.assertEqual(re.findall(r'(?:src|href)="(?:https?:)?//', html_.decode()), [])
        for path, ctype in (("/app.js", "javascript"), ("/style.css", "text/css")):
            st, ct, body, _ = self.call("GET", path, ctype=None); self.assertEqual(st, 200); self.assertIn(ctype, ct); self.assertGreater(len(body), 500)

    def test_APP21_http_hardening_content_type_host_and_owner_token(self):
        sid, tok = self.new_session()
        st, ct, payload, _ = self.call("POST", "/api/sessions", raw=b'{"income_usd": 5}', ctype="text/plain")
        self.assertEqual(st, 415)
        st, ct, payload, _ = self.call("POST", "/api/sessions", raw=b'{"income_usd": 5}', ctype=None); self.assertEqual(st, 415)
        st, ct, payload, _ = self.call("GET", "/", ctype=None, headers={"Host": "evil.example"}); self.assertEqual(st, 403)
        st, ct, payload, _ = self.call("GET", f"/api/sessions/{sid}", headers={"X-Owner-Token": tok, "Host": "evil.example:80"}, ctype=None); self.assertEqual(st, 403)
        for h in ({}, {"X-Owner-Token": "wrong"}):
            st, ct, payload, _ = self.call("GET", f"/api/sessions/{sid}", headers=h, ctype=None); self.assertEqual(st, 403)
            self.assertNotIn(b"owner_secret", payload)
            st, ct, payload, _ = self.call("POST", f"/api/sessions/{sid}/attack", {"strategy": "binary"}, headers=h); self.assertEqual(st, 403)
            self.assertNotIn(b"recovered", payload)
        st, v = self.j("GET", f"/api/sessions/{sid}", headers={"X-Owner-Token": tok}, ctype=None); self.assertEqual(st, 200)


class _Tree(html.parser.HTMLParser):
    VOID = {"meta", "link", "input", "br", "hr", "img"}
    def __init__(self):
        super().__init__(); self.stack, self.els = [], []
    def handle_starttag(self, tag, attrs):
        a = dict(attrs); node = {"tag": tag, "attrs": a, "id": a.get("id"), "anc": [n["id"] for n in self.stack if n["id"]], "anc_tags": [n["tag"] for n in self.stack]}
        self.els.append(node)
        if tag not in self.VOID: self.stack.append(node)
    def handle_endtag(self, tag):
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i]["tag"] == tag: del self.stack[i:]; break


class StaticFrontendAudit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = (ROOT / "web/index.html").read_text(); cls.js = (ROOT / "web/app.js").read_text(); cls.css = (ROOT / "web/style.css").read_text()
        p = _Tree(); p.feed(cls.html); cls.els = p.els
        cls.ids = [e["id"] for e in cls.els if e["id"]]
        cls.by_id = {e["id"]: e for e in cls.els if e["id"]}

    def test_APP13_ids_forms_buttons_and_listeners_are_wired_correctly(self):
        self.assertEqual(len(self.ids), len(set(self.ids)), "duplicate ids")
        used = set(re.findall(r'\$\("([A-Za-z0-9_-]+)"\)', self.js))
        self.assertGreater(len(used), 30); self.assertEqual(used - set(self.ids), set())
        self.assertNotIn("getElementById(", self.js.replace("const $ = (id) => document.getElementById(id);", ""))
        for m in re.finditer(r'\$\("([A-Za-z0-9_-]+)"\)\.addEventListener\("(\w+)"', self.js):
            el_, ev = m.groups(); self.assertIn(ev, ("submit", "click")); self.assertIn(el_, self.ids)
            if ev == "submit": self.assertEqual(self.by_id[el_]["tag"], "form")
        for e in self.els:
            if e["tag"] == "button": self.assertIn(e["attrs"].get("type"), ("button", "submit"), e)
            if e["tag"] == "form":
                self.assertIn("novalidate", e["attrs"]); self.assertTrue(e["id"])
                subs = [b for b in self.els if b["tag"] == "button" and e["id"] in b["anc"] and b["attrs"].get("type") == "submit"]
                self.assertEqual(len(subs), 1, e["id"])
            if e["tag"] in ("input", "select"):
                self.assertIn("label", e["anc_tags"], f"{e['id']} has no wrapping label")
        for form_id, ev in (("create-form", "submit"), ("ask-form", "submit")):
            self.assertIn(f'$("{form_id}").addEventListener("{ev}"', self.js)
        self.assertEqual(subprocess.run(["node", "--check", "web/app.js"], cwd=ROOT).returncode, 0) if shutil.which("node") else None

    def test_APP22_verifier_ui_is_structurally_separated_from_owner_and_auditor_information(self):
        in_verifier = {e["id"] for e in self.els if e["id"] and "verifier-panel" in e["anc"]} | {"verifier-panel"}
        in_auditor = {e["id"] for e in self.els if e["id"] and "auditor-panel" in e["anc"]} | {"auditor-panel"}
        in_owner = {e["id"] for e in self.els if e["id"] and "owner-panel" in e["anc"]} | {"owner-panel"}
        self.assertEqual(in_verifier & in_auditor, set()); self.assertEqual(in_verifier & in_owner, set())
        auditor_only = {"secret", "sid", "flo", "fhi", "fsize", "floor", "ver", "adv", "vtable", "log", "r-decision", "r-range", "r-commit",
                        "r-consistent", "bar", "barfill", "steps", "attack", "attack-gated", "attack-base", "attack-result"}
        self.assertTrue(auditor_only <= in_auditor, auditor_only - in_auditor)
        vtext = " ".join(re.findall(r">([^<]+)<", self.html[self.html.index('id="verifier-panel"'):self.html.index('id="auditor-panel"')])).lower()
        for w in ("secret", "feasible", "candidates", "floor", "anchor", "policy"): self.assertNotIn(w, vtext)
        blk = self.js[self.js.index("==VERIFIER-UI=="):self.js.index("==END-VERIFIER-UI==")].lower()
        for w in ("auditor", "feasible", "owner", "secret", "token", "reason", "candidates", "floor", "refreshowner"): self.assertNotIn(w, blk)
        ask_call = re.search(r'api\("/api/sessions/" \+ session \+ "/query"[^;]*;', self.js).group(0)
        self.assertNotIn("Token", ask_call)                                             

    def test_APP24_initial_page_state_csp_compatibility_and_no_external_resources(self):
        self.assertIn("disabled", self.by_id["ask"]["attrs"]); self.assertIn("disabled", self.by_id["attack"]["attrs"])
        for hidden in ("story-open", "story-gated", "owner-view", "attack-result"): self.assertIn("hidden", self.by_id[hidden]["attrs"], hidden)
        self.assertNotIn("hidden", self.by_id["auditor-empty"]["attrs"]); self.assertNotIn("hidden", self.by_id["verifier-hint"]["attrs"])
        self.assertTrue(re.search(r'id="story-status"[^>]*>[^<]+<', self.html))
        for e in self.els:
            self.assertFalse([k for k in e["attrs"] if k.startswith("on")], e); self.assertNotIn("style", e["attrs"], e)
            for k in ("src", "href"):
                if k in e["attrs"]: self.assertTrue(e["attrs"][k].startswith("/"), e)
        self.assertEqual([e for e in self.els if e["tag"] in ("style", "iframe", "object", "embed")], [])
        self.assertEqual([e for e in self.els if e["tag"] == "script" and "src" not in e["attrs"]], [])
        for bad in ("innerHTML", "outerHTML", "eval(", "new Function", "document.write", 'setAttribute("style"', "cssText", "localStorage", "XMLHttpRequest", "http://", "https://"):
            self.assertNotIn(bad, self.js, bad)
        for cls in ("verdict", "yes", "no", "refused", "track", "fillbar", "floorline", "steps", "sees", "head", "cols", "tracks", "big", "big2", "seq", "col",
                    "panel", "panels", "scroll", "story-grid", "error", "hint", "notice", "bar", "fill"):
            self.assertRegex(self.css, r"\." + re.escape(cls) + r"\b", cls)
        self.assertIn(":focus-visible", self.css)
        for state in ("story-status", "owner-error", "ask-error", "attack-error", "verdict"):                       
            self.assertIn(state, self.ids)

    def test_APP25_honest_labels_on_the_first_screen(self):
        head = re.search(r'<p class="notice".*?</p>', self.html, re.S).group(0).lower()
        for phrase in ("local simulation", "only on this computer", "in-memory test double", "no blockchain", "does not encrypt", "mock", "no real income verification", "us dollars"):
            self.assertIn(phrase, head)
        self.assertNotIn("production", head); self.assertNotIn("secure", head); self.assertNotIn("private by", head)
        self.assertNotRegex(self.js, r'\$\("notice"\)\.textContent\s*=')                


@unittest.skipUnless(shutil.which("node"), "node is required to execute the frontend logic")
class FrontendLogic(unittest.TestCase):
    def node(self, expr):
        out = subprocess.run(["node", "-e", f"const m=require('./web/app.js'); console.log(JSON.stringify({expr}))"], cwd=ROOT, capture_output=True, text=True, timeout=30)
        self.assertEqual(out.returncode, 0, out.stderr); return json.loads(out.stdout)

    def test_APP12_frontend_pure_logic_executed_under_node(self):
        self.assertEqual(self.node("[m.fmtUsd(83250), m.fmtUsd(-5), m.fmtUsd(NaN), m.fmtCount(1000000), m.fmtCount('x')]"), ["$83,250", "-$5", "?", "1,000,000", "?"])
        self.assertEqual(self.node("m.barGeometry(0,999999,0,999999)"), {"leftPct": 0, "widthPct": 100})
        g = self.node("m.barGeometry(78125,93749,0,999999)"); self.assertAlmostEqual(g["leftPct"], 7.8125, 3); self.assertAlmostEqual(g["widthPct"], 1.5625, 3)
        self.assertEqual(self.node("[m.shareOf(500001,1000000), m.shareOf(10000,1000000), m.shareOf(5,0), m.shareOf(2e9,1e6)]"), [50.0001, 1, 0, 100])
        self.assertEqual(self.node("[m.verdictText('ANSWER',true),m.verdictText('ANSWER',false),m.verdictText('REFUSED',null),m.verdictText('REJECTED',null)]"), ["YES", "NO", "REFUSED", "REJECTED"])
        d = self.node("[m.describeVerdict('ANSWER',true,500000), m.describeVerdict('ANSWER',false,5), m.describeVerdict('REFUSED',null,5), m.describeVerdict('RETRY',null,5)]")
        self.assertEqual(d[:2], ["YES: income is above $500,000", "NO: income is at or below $5"]); self.assertEqual(d[2], "REFUSED: no answer was given")
        for w in ("floor", "reason", "candidate", "feasible", "policy"): self.assertNotIn(w, " ".join(d).lower())     # refusal text reveals nothing
        self.assertEqual(self.node("['12','-5',' 7 ','1.5','','1e3','abc','9007199254740993'].map(m.parseIntegerField)"), [12, -5, 7, None, None, None, None, None])


@unittest.skipUnless(shutil.which("node"), "node is required to run the fake-DOM end-to-end script")
class FakeDomEndToEnd(HttpCase):
    """Runs the REAL app.js against the REAL server with a minimal fake DOM. This is NOT a browser."""
    def test_APP23_real_handlers_against_real_server_with_fake_dom(self):
        r = subprocess.run(["node", "tests/e2e_fake_dom.js", f"http://127.0.0.1:{self.port}"], cwd=ROOT, capture_output=True, text=True, timeout=90)
        self.assertEqual(r.returncode, 0, r.stderr); d = json.loads(r.stdout)
        i = d["initial"]
        self.assertEqual((i["askDisabled"], i["attackDisabled"], i["ownerViewHidden"], i["auditorEmptyHidden"], i["resultText"]), (True, True, True, False, ""))
        self.assertTrue(i["loadingDisabledCreate"]); self.assertFalse(i["createDisabledAfterStory"])               # in-flight guard releases
        s = d["story"]; self.assertEqual(s["status"], ""); self.assertEqual(len(s["steps"]), 9)
        self.assertIn("20 questions", s["openHeadline"]); self.assertIn("$120,000", s["openHeadline"])
        self.assertTrue(s["openSeq"].startswith("1,000,000 \u2192 500,000")); self.assertTrue(s["openSeq"].endswith("\u2192 1"))
        for frag in ("500,001", "250,001", "125,001", "62,500", "31,250", "15,625"): self.assertTrue(any(frag in x for x in s["steps"]), frag)
        self.assertEqual([("REFUSED" in x) for x in s["steps"]], [False] * 7 + [True, True])
        self.assertIn("15,625 candidates remain (floor 10,000)", s["summary"]); self.assertEqual(s["floorLeft"], "1%"); self.assertEqual(s["firstBarWidth"], "100%")
        c = d["createInvalid"]; self.assertTrue(c["prevented"]); self.assertIn("between 0 and 999,999", c["error"]); self.assertTrue(c["ownerViewHidden"])
        c = d["created"]; self.assertEqual((c["prevented"], c["secret"], c["fsize"], c["askDisabled"], c["attackDisabled"], c["hintHidden"], c["focused"]), (True, "$120,000", "1,000,000", False, False, True, "threshold"))
        r1 = d["refused"]; self.assertEqual(r1["v"]["verdict"], "REFUSED: no answer was given"); self.assertEqual(r1["v"]["log"], [["1", "V2", "$9,998", "REFUSED"]])
        self.assertEqual((r1["decision"], r1["fsize"]), ("REFUSED (reason: FLOOR)", "1,000,000"))
        a = d["answered"]; self.assertEqual((a["v"]["verdict"], a["fsize"], a["decision"], a["consistent"]), ("NO: income is at or below $500,000", "500,001", "INFORMATIVE", "yes"))
        self.assertEqual(a["v"]["log"][0], ["2", "V1", "$500,000", "NO"])
        self.assertEqual(d["doubleSubmit"]["added"], 1); self.assertEqual((d["badThreshold"]["added"], d["badThreshold"]["error"]), (0, "Threshold must be a whole number."))
        self.assertEqual(d["quick"]["threshold"], "9999")
        at = d["attack"]; self.assertFalse(at["resultHidden"]); self.assertIn("held", at["gated"]); self.assertIn("secret recovered: no", at["gated"]); self.assertGreater(at["steps"], 5)
        self.assertEqual(at["ownerFsizeAfter"], d["doubleSubmit"] and at["ownerFsizeAfter"])
        self.assertIn("Cannot reach the local server", d["networkDown"]["error"]); self.assertFalse(d["networkDown"]["askDisabledAfter"])
        g = d["sessionGone"]; self.assertEqual((g["ownerViewHidden"], g["auditorEmptyHidden"], g["askDisabled"], g["attackDisabled"], g["hintHidden"], g["vlogRows"]), (True, False, True, True, False, 0))
        self.assertIn("Session no longer exists", g["hint"])
        self.assertIn("Could not load the demo", d["storyError"]["status"]); self.assertEqual((d["storyRecovered"]["status"], d["storyRecovered"]["steps"]), ("", 9))
        verifier_side = json.dumps([d["refused"]["v"], d["answered"]["v"]]).lower()
        for w in ("floor", "feasible", "candidates", "anchor", "informative", "determined", "120,000", "token", "reason"): self.assertNotIn(w, verifier_side)


if __name__ == "__main__":
    unittest.main()
