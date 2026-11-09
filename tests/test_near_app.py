import http.client
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest

from app.near_mode import LiveConfig, NearModeError, _LiveSession, build_live_system
from app.server import build_service, make_server, parse_args
from app.service import ApiError, Service
from core.records import Record, make_genesis, policy_digest
from harness.system import DEMO_POLICY
from integrations.codec import record_to_json
from integrations.near_rpc import NearRpc, NearRpcUnavailable
from integrations.record_store import DirRecordStore
from testdoubles.test_sealer import UnsealedTestSealer
from tests.test_near_anchor import CONTRACT, Clock, ContractModel

ROOT = pathlib.Path(__file__).resolve().parent.parent
VERIFIERS = ("V1", "V2", "V3")
VERIFIER_KEYS = {"verifier_id", "threshold", "response", "answer"}
SECRET_THRESHOLD = 499_999       


class HookModel(ContractModel):
    """Runs `before_send` once, just before the next transaction is applied (to model a competing writer)."""
    before_send = None

    def send_cas(self, args):
        hook, self.before_send = self.before_send, None
        if hook:
            hook()
        return super().send_cas(args)


class SequencedModel(ContractModel):
    """Per-transaction sender behaviour, consumed in order: e.g. ["normal", "lost", "normal"]."""
    script = []

    def send_cas(self, args):
        if self.script:
            self.sender_mode = self.script.pop(0)
        return super().send_cas(args)


class Counting:
    """Transport wrapper that counts RPC calls and can fail chosen ones (1-based)."""
    def __init__(self):
        self.n, self.fail_on, self.inner = 0, set(), None

    def wrap(self, inner):
        self.inner = inner
        return self

    def __call__(self, url, body, timeout):
        self.n += 1
        if self.n in self.fail_on:
            raise NearRpcUnavailable("injected failure")
        return self.inner(url, body, timeout)


class Env:
    """MODEL-BASED fixture: temp store + ContractModel chain. Never the real testnet or the real bbstore."""
    def __init__(self, model_cls=ContractModel, rpc_wrap=None, **cfg_kw):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = os.path.join(self.tmp.name, "store")
        self.genesis = make_genesis("scope-app-model", DEMO_POLICY, VERIFIERS, UnsealedTestSealer())
        self.store = DirRecordStore(self.dir)
        self.store.put(self.genesis)
        with open(os.path.join(self.dir, "config.json"), "w") as f:
            json.dump({"scope_id": "scope-app-model", "policy_digest": policy_digest(DEMO_POLICY)}, f)
        self.model = model_cls(self.genesis, writer="gate.testnet", caller="gate.testnet")
        self.clk = Clock()
        transport = rpc_wrap(self.model.transport) if rpc_wrap else self.model.transport
        self.rpc = NearRpc("http://x", transport=transport)
        self.cfg = LiveConfig(store=self.dir, contract=CONTRACT, writer="gate.testnet", confirm_timeout=10.0, **cfg_kw)

    def system(self):
        return build_live_system(self.cfg, rpc=self.rpc, sender=self.model, sleep=self.clk.sleep, clock=self.clk.now)

    def live(self):
        return _LiveSession(self.system())

    def service(self):
        lv = self.live()
        return Service(live=lv), lv

    def close(self):
        self.tmp.cleanup()


class EnvCase(unittest.TestCase):
    def env(self, **kw):
        e = Env(**kw)
        self.addCleanup(e.close)
        return e


def q(svc, vid="V1", t=SECRET_THRESHOLD):
    return svc.query("live", {"verifier_id": vid, "threshold": t})


class LiveService(EnvCase):
    """MODEL-BASED."""
    def test_APPN01_successful_write_goes_through_the_real_gate_and_the_nearanchor(self):
        env = self.env(); svc, live = env.service()
        r = q(svc)
        self.assertEqual(r, {"verifier_id": "V1", "threshold": SECRET_THRESHOLD, "response": "ANSWER", "answer": False})
        self.assertEqual((env.model.version, len(env.model.sent)), (1, 1))
        v = svc.owner_view("live", live.owner_token)
        a = v["log"][-1]["auditor_view"]
        self.assertEqual((a["committed"], a["consistent_with_policy"], v["anchor_version"]), (True, True, 1))
        self.assertEqual((v["live"]["mode"], v["live"]["contract"], v["live"]["signing_account"]), ("near-testnet", CONTRACT, "gate.testnet"))
        r = q(svc, "V2", 9_998)                                  
        self.assertEqual((r["response"], r["answer"], env.model.version), ("REFUSED", None, 2))

    def test_APPN02_verifier_response_carries_only_the_verifier_view(self):
        env = self.env(); svc, live = env.service()
        r = q(svc)
        self.assertEqual(set(r), VERIFIER_KEYS)
        blob = json.dumps(r)
        for w in ("feasible", "auditor", "anchor", "committed", "secret", "owner", "sealed", live.owner_token):
            self.assertNotIn(w, blob)

    def test_APPN03_lost_response_releases_nothing_then_identical_request_is_resent(self):
        env = self.env(); svc, live = env.service(); env.model.sender_mode = "lost"
        r = q(svc)
        self.assertEqual((r["response"], r["answer"]), ("RETRY", None))
        self.assertIn("Resend the same threshold", r["detail"])
        self.assertEqual((env.model.version, len(env.model.sent)), (0, 1))
        self.assertEqual(svc.owner_view("live", live.owner_token)["live"]["unconfirmed_requests"], {"V1": SECRET_THRESHOLD})
        env.model.sender_mode = "normal"
        r = q(svc)
        self.assertEqual((r["response"], r["answer"]), ("ANSWER", False))
        self.assertEqual((env.model.version, len(env.model.sent)), (1, 2))
        h0, h1 = (json.loads(a["header"]) for a in env.model.sent)
        self.assertEqual((h0["nonce"], h0["request_digest"]), (h1["nonce"], h1["request_digest"]))   
        self.assertNotEqual(env.model.sent[0]["new_digest"], env.model.sent[1]["new_digest"])        
        self.assertEqual(svc.owner_view("live", live.owner_token)["live"]["unconfirmed_requests"], {})

    def test_APPN04_no_blind_retries_one_broadcast_per_api_call(self):
        env = self.env(); svc, live = env.service(); env.model.sender_mode = "lost"
        for n in (1, 2, 3):
            self.assertEqual(q(svc)["response"], "RETRY")
            self.assertEqual(len(env.model.sent), n)             
        self.assertEqual(env.model.version, 0)

    def test_APPN05_a_different_threshold_is_refused_while_a_request_is_unconfirmed(self):
        env = self.env(); svc, live = env.service(); env.model.sender_mode = "lost"
        self.assertEqual(q(svc)["response"], "RETRY")
        with self.assertRaises(ApiError) as cm:
            q(svc, "V1", 249_999)
        self.assertEqual(cm.exception.status, 409); self.assertIn(str(SECRET_THRESHOLD), cm.exception.message)
        env.model.sender_mode = "normal"
        self.assertEqual(q(svc, "V2", 249_999)["response"], "ANSWER")       
        self.assertEqual(len(env.model.sent), 2)                             

    def test_APPN06_late_landing_transaction_is_replayed_without_a_second_write(self):
        env = self.env(); svc, live = env.service(); env.model.sender_mode = "delayed"
        self.assertEqual(q(svc)["response"], "RETRY")
        self.assertEqual(env.model.flush(), ["COMMITTED"])
        env.model.sender_mode = "normal"
        r = q(svc)
        self.assertEqual((r["response"], r["answer"], len(env.model.sent), env.model.version), ("ANSWER", False, 1, 1))

    def test_APPN07_signer_reports_failure_but_chain_shows_commit_one_broadcast(self):
        env = self.env(); svc, live = env.service(); env.model.sender_mode = "applied_but_fails"
        r = q(svc)
        self.assertEqual((r["response"], r["answer"], len(env.model.sent), env.model.version), ("ANSWER", False, 1, 1))

    def test_APPN08_answer_is_withheld_if_the_chain_cannot_confirm_after_the_gate_answers(self):
        ct = Counting(); env = self.env(rpc_wrap=ct.wrap); svc, live = env.service()     
        marks, orig = [], live.system.gate.handle
        def spy(req):
            r = orig(req); marks.append(ct.n); return r
        live.system.gate.handle = spy
        q(svc); g = marks[0]
        ct2 = Counting(); env2 = self.env(rpc_wrap=ct2.wrap); svc2, live2 = env2.service()
        ct2.fail_on = {g + 1}                                   
        r = q(svc2)
        self.assertEqual((r["response"], r["answer"]), ("RETRY", None))
        self.assertEqual((env2.model.version, len(env2.model.sent)), (1, 1))     
        r = q(svc2)                                               
        self.assertEqual((r["response"], r["answer"], len(env2.model.sent), env2.model.version), ("ANSWER", False, 1, 1))

    def test_APPN09_chain_read_failure_after_a_confirmed_answer_does_not_retract_it(self):
        ct = Counting(); env = self.env(rpc_wrap=ct.wrap); svc, live = env.service()
        marks, orig = [], live.system.gate.handle
        def spy(req):
            r = orig(req); marks.append(ct.n); return r
        live.system.gate.handle = spy
        q(svc); g = marks[0]
        ct2 = Counting(); env2 = self.env(rpc_wrap=ct2.wrap); svc2, live2 = env2.service()
        ct2.fail_on = {g + 2}                                   
        r = q(svc2)
        self.assertEqual((r["response"], r["answer"]), ("ANSWER", False))
        a = svc2.owner_view("live", live2.owner_token)["log"][-1]["auditor_view"]
        self.assertEqual((a["committed"], a["feasible_after"]["size"], a["consistent_with_policy"]), (None, None, True))

    def test_APPN10_rpc_failure_is_a_safe_503_with_nothing_sent_and_no_internals(self):
        env = self.env(); svc, live = env.service(); env.model.rpc_down = True
        with self.assertRaises(ApiError) as cm:
            q(svc)
        self.assertEqual(cm.exception.status, 503)
        for leak in ("urlopen", "Errno", "http://", "Traceback", "down"):
            self.assertNotIn(leak, cm.exception.message)
        self.assertEqual(env.model.sent, [])
        c = svc.chain_head()                                       
        self.assertIsNone(c["head"]); self.assertIn("could not be read", c["error"])
        env.model.rpc_down = False; live._chain_cache = (0.0, None)
        self.assertEqual(svc.chain_head()["head"]["version"], 0)
        self.assertEqual(q(svc)["response"], "ANSWER")             

    def test_APPN10b_public_chain_head_is_never_stale_right_after_a_write(self):
        env = self.env(); svc, live = env.service()
        self.assertEqual(svc.chain_head()["head"]["version"], 0)       
        q(svc)
        self.assertEqual(svc.chain_head()["head"]["version"], 1)       
        env.model.sender_mode = "lost"; q(svc, "V2")
        self.assertEqual(svc.chain_head()["head"]["version"], 1)      

    def test_APPN11_integrity_failure_halts_the_session_fail_closed(self):
        env = self.env(); svc, live = env.service()
        g = env.genesis
        bad = Record(g.header, b"tampered" + g.sealed_state[8:])
        with open(os.path.join(env.dir, g.digest() + ".json"), "w") as f:     
            json.dump(record_to_json(bad), f)
        with self.assertRaises(ApiError) as cm:
            q(svc)
        self.assertEqual(cm.exception.status, 503); self.assertIn("halted", cm.exception.message)
        self.assertNotIn("tampered", cm.exception.message)
        with self.assertRaises(ApiError) as cm2:
            q(svc, "V2")                                           
        self.assertEqual(cm2.exception.status, 503); self.assertIn("halted", cm2.exception.message)
        self.assertEqual(env.model.sent, [])
        self.assertTrue(live.halted)
        env.store.put(g)                                           
        self.assertEqual(live.system.anchor.read().digest(), g.digest())
        with self.assertRaises(ApiError) as cm3:
            q(svc, "V3")                                          
        self.assertEqual(cm3.exception.status, 503); self.assertEqual(env.model.sent, [])

    def test_APPN12_stale_cas_withholds_the_answer_then_succeeds_on_resend(self):
        env = self.env(model_cls=HookModel); svc, live = env.service()
        other = env.system()                                       
        env.model.before_send = lambda: other.gate.handle(other.client("V2").make(SECRET_THRESHOLD))
        r = q(svc)
        self.assertEqual((r["response"], r["answer"]), ("RETRY", None))        
        self.assertEqual(env.model.version, 1)                                
        r = q(svc)                                                
        self.assertEqual((r["response"], r["answer"], env.model.version), ("ANSWER", False, 2))
        v = svc.owner_view("live", live.owner_token)
        self.assertEqual(v["verifiers"]["V1"]["committed_requests"], 1)        
        self.assertTrue(all(x["auditor_view"]["consistent_with_policy"] is not False for x in v["log"]))


class LiveStartup(EnvCase):
    """MODEL-BASED. Startup validation: fail closed, say why, send nothing."""
    def test_APPN13_missing_or_inconsistent_store_refuses_to_start(self):
        env = self.env()
        os.remove(os.path.join(env.dir, "config.json"))
        with self.assertRaises(NearModeError) as cm: env.system()
        self.assertIn("store is missing", str(cm.exception))
        env = self.env()
        os.remove(os.path.join(env.dir, env.genesis.digest() + ".json"))      
        with self.assertRaises(NearModeError) as cm: env.system()
        self.assertIn("record", str(cm.exception))
        env = self.env(); env.model.scope = "some-other-scope"
        with self.assertRaises(NearModeError) as cm: env.system()
        self.assertIn("integrity", str(cm.exception))
        env = self.env()
        with open(os.path.join(env.dir, "config.json"), "w") as f:
            json.dump({"scope_id": "scope-app-model", "policy_digest": "f" * 64}, f)
        with self.assertRaises(NearModeError) as cm: env.system()
        self.assertIn("policy digest", str(cm.exception))
        self.assertEqual(env.model.sent, [])

    def test_APPN14_unreachable_or_old_network_and_bad_arguments_refuse_to_start(self):
        env = self.env(); env.model.rpc_down = True
        with self.assertRaises(NearModeError) as cm: env.system()
        self.assertIn("preflight", str(cm.exception))
        env = self.env(); env.model.protocol = 87
        with self.assertRaises(NearModeError) as cm: env.system()
        self.assertIn("protocol_version", str(cm.exception))
        for kw in ({"network": "mainnet"}, {"contract": "Bad Account!"}, {"writer": "x"}, {"deploy_tx": "not-a-tx"}):
            env = self.env()
            for k, v in kw.items(): setattr(env.cfg, k, v)
            with self.assertRaises(NearModeError): env.system()
            self.assertEqual(env.model.sent, [])

    def test_APPN15_cli_refuses_non_loopback_hosts_and_missing_arguments(self):
        base = ["--anchor", "near", "--store", "x", "--contract", "a.testnet", "--writer", "b.testnet"]
        with self.assertRaises(SystemExit) as cm: build_service(parse_args(base + ["--host", "0.0.0.0"]))
        self.assertIn("non-loopback", str(cm.exception))
        with self.assertRaises(SystemExit) as cm: build_service(parse_args(["--anchor", "near"]))
        self.assertIn("--store", str(cm.exception))
        with self.assertRaises(SystemExit) as cm: build_service(parse_args(base[:2] + ["--store", "/nonexistent", "--contract", "a.testnet", "--writer", "b.testnet"]))
        self.assertIn("cannot start live NEAR mode", str(cm.exception))


class LiveHttp(EnvCase):
    """MODEL-BASED. The real HTTP server in live mode over the contract model."""
    def start(self, **kw):
        env = self.env(**kw); svc, live = env.service()
        srv = make_server("127.0.0.1", 0, svc); port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True); t.start()
        self.addCleanup(lambda: (srv.shutdown(), srv.server_close(), t.join(5)))
        return env, svc, live, port

    def call(self, port, method, path, body=None, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        h = {"Content-Type": "application/json"} if method == "POST" else {}
        h.update(headers or {})
        c.request(method, path, body=None if body is None else json.dumps(body).encode(), headers=h)
        r = c.getresponse(); payload = r.read(); c.close()
        return r.status, json.loads(payload)

    def test_APPN16_public_endpoints_need_no_credentials_and_expose_only_public_chain_data(self):
        env, svc, live, port = self.start()
        st, m = self.call(port, "GET", "/api/mode")
        self.assertEqual((st, m["mode"], m["contract"], m["signing_account"]), (200, "near-testnet", CONTRACT, "gate.testnet"))
        self.assertIn("cannot submit authorized writes", m["signing_note"])
        self.assertTrue(m["notice"].startswith("LIVE NEAR TESTNET MODE")); self.assertIn("not production", m["notice"])
        self.assertEqual(m["explorer"]["contract"], "https://testnet.nearblocks.io/address/" + CONTRACT)
        st, c = self.call(port, "GET", "/api/chain")
        self.assertEqual(st, 200)
        self.assertEqual(set(c["head"]), {"version", "digest", "scope_id", "policy_digest", "writer"})
        self.assertEqual((c["head"]["version"], c["head"]["digest"]), (0, env.genesis.digest()))
        self.assertIn(CONTRACT, c["verify_with"]); self.assertIn("e30=", c["verify_with"])
        for body in (json.dumps(m), json.dumps(c)):
            for private in (live.owner_token, env.dir, "owner_secret", "sealed_state", "sealed_state_b64", "blinding", "key-V1", "feasible"):
                self.assertNotIn(private, body)

    def test_APPN17_live_mode_has_one_fixed_session_and_no_attack_demo(self):
        env, svc, live, port = self.start(); tok = {"X-Owner-Token": live.owner_token}
        st, r = self.call(port, "POST", "/api/sessions", {"income_usd": 5}); self.assertEqual(st, 409)
        st, r = self.call(port, "POST", "/api/sessions/live/attack", {"strategy": "binary"}, headers=tok); self.assertEqual(st, 409)
        self.assertNotIn("recovered", json.dumps(r))
        st, r = self.call(port, "POST", "/api/sessions/live/query", {"verifier_id": "V1", "threshold": SECRET_THRESHOLD})
        self.assertEqual((st, set(r), r["answer"]), (200, VERIFIER_KEYS, False))             # no token needed, no extras
        st, r = self.call(port, "GET", "/api/sessions/live"); self.assertEqual(st, 403)
        self.assertNotIn("owner_secret", json.dumps(r))
        st, r = self.call(port, "GET", "/api/sessions/live", headers=tok)
        self.assertEqual((st, r["live"]["contract"], r["anchor_version"]), (200, CONTRACT, 1))

    def test_APPN18_http_errors_in_live_mode_are_safe(self):
        env, svc, live, port = self.start(); env.model.rpc_down = True
        st, r = self.call(port, "POST", "/api/sessions/live/query", {"verifier_id": "V1", "threshold": 5})
        self.assertEqual(st, 503); self.assertEqual(set(r), {"error"})
        self.assertNotIn("Traceback", json.dumps(r)); self.assertEqual(env.model.sent, [])
        st, r = self.call(port, "GET", "/api/chain"); self.assertEqual((st, r["head"]), (200, None))

    @unittest.skipUnless(shutil.which("node"), "node is required")
    def test_APPN19_live_ui_logic_executed_in_a_fake_dom_against_the_live_server_over_the_model(self):
        """The real web/app.js and the real server in live mode; the chain is the MODEL. NOT a browser, NOT NEAR."""
        env, svc, live, port = self.start(model_cls=SequencedModel)
        env.model.script = ["normal", "lost", "normal"]
        r = subprocess.run(["node", "tests/e2e_fake_dom_near.js", f"http://127.0.0.1:{port}", live.owner_token],
                           cwd=ROOT, capture_output=True, text=True, timeout=90)
        self.assertEqual(r.returncode, 0, r.stderr); d = json.loads(r.stdout)
        L = d["live"]
        self.assertEqual((L["title"], L["noticeHidden"], L["createHidden"], L["tokenFormHidden"], L["chainShown"], L["attackHidden"], L["askDisabled"], L["ownerViewHidden"]),
                         ("Bit Budget: LIVE NEAR TESTNET", True, True, False, True, True, False, True))
        self.assertTrue(L["banner"].startswith("LIVE NEAR TESTNET MODE")); self.assertIn("visitors cannot sign", L["banner"])
        self.assertIn("signing account", L["hint"])
        c = d["chain0"]
        self.assertEqual((c["contract"], c["signer"], c["version"], c["digestLen"]), (CONTRACT + " (testnet)", "gate.testnet", "0", 64))
        self.assertEqual(c["links"], ["https://testnet.nearblocks.io/address/" + CONTRACT, "https://testnet.nearblocks.io/address/gate.testnet"])
        self.assertIn("read-only", c["status"]); self.assertTrue(c["verify"].startswith("curl -s"))
        self.assertEqual((d["ask1"]["verdict"], d["ask1"]["version"]), ("NO: income is at or below $499,999", "1"))
        a2 = d["ask2"]
        self.assertTrue(a2["verdict"].startswith("RETRY")); self.assertIn("not confirmed on the NEAR testnet chain", a2["verdict"])
        self.assertEqual(a2["version"], "1"); self.assertEqual(len(a2["log"]), 2)           
        self.assertEqual(a2["log"][0][3], "RETRY")
        self.assertEqual((d["ask3"]["verdict"], d["ask3"]["version"]), ("NO: income is at or below $249,999", "2"))
        self.assertEqual((d["noToken"]["ownerViewHidden"], d["badToken"]["ownerViewHidden"]), (True, True))
        self.assertEqual(d["badToken"]["error"], "That token was not accepted.")
        g = d["goodToken"]
        self.assertEqual((g["ownerViewHidden"], g["sid"], g["ver"]), (False, "live", "2"))
        self.assertEqual(env.model.version, 2)


class LocalModeUnchanged(unittest.TestCase):
    def test_APPN20_default_mode_is_local_and_loads_no_near_code(self):
        svc = Service()
        self.assertEqual(svc.mode_info()["mode"], "local"); self.assertIsNone(svc.live)
        with self.assertRaises(ApiError) as cm: svc.chain_head()
        self.assertEqual(cm.exception.status, 404)
        self.assertIsInstance(build_service(parse_args([])), Service)
        out = subprocess.run([sys.executable, "-c", "import app.server, sys; build = app.server.build_service(app.server.parse_args([])); "
                              "print('integrations' in sys.modules, 'app.near_mode' in sys.modules, build.live is None)"],
                             cwd=ROOT, capture_output=True, text=True, timeout=60)
        self.assertEqual(out.stdout.split(), ["False", "False", "True"], out.stderr)

    def test_APPN21_local_server_serves_local_mode_and_no_chain_view(self):
        srv = make_server("127.0.0.1", 0); port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True); t.start()
        self.addCleanup(lambda: (srv.shutdown(), srv.server_close(), t.join(5)))
        def get(path):
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=10); c.request("GET", path)
            r = c.getresponse(); body = r.read(); c.close(); return r.status, json.loads(body)
        st, m = get("/api/mode"); self.assertEqual((st, m["mode"]), (200, "local")); self.assertIn("LOCAL SIMULATION", m["notice"])
        st, r = get("/api/chain"); self.assertEqual(st, 404)


if __name__ == "__main__":
    unittest.main()
