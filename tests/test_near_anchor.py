import base64
import io
import json
import os
import subprocess
import tempfile
import unittest

from core.interfaces import AnchorUnavailable, CasResult, GateConfigError
from core.records import Header, Record
from harness.system import WRITER_KEY, build_system
from core.gate import Gate
from integrations.codec import record_from_json, record_to_json
from integrations.near_anchor import (AnchorIntegrityError, NearAnchor, NearCliSender, SenderNotSent, TxSender,
                                      preflight)
from integrations.near_rpc import NearRpc, NearRpcError, NearRpcUnavailable
from integrations.record_store import DirRecordStore, MemoryRecordStore

CONTRACT = "anchor.testnet"


class ContractModel(TxSender):
    """Semantic model of the Rust contract + an RPC transport + a TxSender, with fault knobs."""
    def __init__(self, genesis, writer="gate.testnet", caller="gate.testnet"):
        self.writer, self.caller = writer, caller
        self.scope, self.pd = genesis.header.scope_id, genesis.header.policy_digest
        self.version, self.digest = 0, genesis.digest()
        self.sent, self.logs = [], []            
        self.rpc_down = False
        self.protocol = 88
        self.stale_head = None                   
        self.stale_reads = 0
        self.sender_mode = "normal"               
        self.pending = []                         

    # --- contract semantics (mirrors lib.rs) ---
    def _cas(self, a):
        if self.caller != self.writer:
            return "UNAUTHORIZED"
        hex64 = lambda s: isinstance(s, str) and len(s) == 64 and set(s) <= set("0123456789abcdef")
        if not hex64(a["expected_digest"]) or not hex64(a["new_digest"]) or len(a["header"]) > 1024:
            return "MALFORMED"
        if a["expected_version"] != self.version or a["expected_digest"] != self.digest:
            return "CONFLICT"
        self.version, self.digest = self.version + 1, a["new_digest"]
        self.logs.append(a["header"])
        return "COMMITTED"

    def flush(self):
        """Land every in-flight transaction (in order). Returns the contract's verdicts."""
        out, self.pending = [self._cas(a) for a in self.pending], []
        return out

    # --- TxSender ---
    def send_cas(self, args):
        self.sent.append(args)
        m = self.sender_mode
        if m == "not_sent":
            raise SenderNotSent("signer missing")
        if m == "lost":
            return True                           
        if m == "fails_unapplied":
            return False
        if m == "delayed":
            self.pending.append(args)
            return False                          
        self._cas(args)
        return m != "applied_but_fails"

    # --- RPC transport ---
    def transport(self, url, body, timeout):
        if self.rpc_down:
            raise NearRpcUnavailable("down")
        req = json.loads(body)
        if req["method"] == "status":
            return json.dumps({"jsonrpc": "2.0", "id": "x", "result": {"chain_id": "testnet", "protocol_version": self.protocol}}).encode()
        assert req["method"] == "query" and req["params"]["request_type"] == "call_function"
        assert req["params"]["account_id"] == CONTRACT and req["params"]["finality"] == "final"
        v, d = self.version, self.digest
        if self.stale_reads > 0 and self.stale_head:
            self.stale_reads -= 1
            v, d = self.stale_head
        head = {"version": v, "digest": d, "scope_id": self.scope, "policy_digest": self.pd, "writer": self.writer}
        return json.dumps({"jsonrpc": "2.0", "id": "x", "result": {"result": list(json.dumps(head).encode())}}).encode()


class AsCaller(TxSender):
    """Sends model transactions signed by `who` (the model's `caller` is what the contract sees as predecessor)."""
    def __init__(self, model, who): self.m, self.who = model, who
    def send_cas(self, args):
        old, self.m.caller = self.m.caller, self.who
        try: return self.m.send_cas(args)
        finally: self.m.caller = old


class Clock:
    def __init__(self): self.t = 0.0
    def now(self): return self.t
    def sleep(self, s): self.t += s


def make(**kw):
    sysobj = build_system()
    genesis = sysobj.anchor.record_at(0)
    model = ContractModel(genesis)
    store = MemoryRecordStore()
    store.put(genesis)
    clk = Clock()
    anchor = NearAnchor(NearRpc("http://x", transport=model.transport), CONTRACT, model, store, WRITER_KEY,
                        genesis.header.scope_id, genesis.header.policy_digest, confirm_timeout=10.0,
                        poll_interval=2.0, sleep=clk.sleep, clock=clk.now, **kw)
    gate = Gate(sysobj.policy, sysobj.scope_id, sysobj.secret, anchor, sysobj.sealer, sysobj.auth, WRITER_KEY)
    return sysobj, genesis, model, store, anchor, gate, clk


def next_record(genesis, anchor_prev, sysobj, version=1):
    h = genesis.header
    hdr = Header(h.scope_id, version, anchor_prev.digest(), "V1", version, "1" * 64, "2" * 64, h.policy_digest)
    return Record(hdr, genesis.sealed_state)


class CodecStoreTests(unittest.TestCase):
    def test_roundtrip(self):
        g = build_system().anchor.record_at(0)
        self.assertEqual(record_from_json(record_to_json(g)).digest(), g.digest())

    def test_rejects_extra_header_field_and_bad_base64(self):
        o = record_to_json(build_system().anchor.record_at(0))
        bad = json.loads(json.dumps(o)); bad["header"]["extra"] = 1
        with self.assertRaises(ValueError): record_from_json(bad)
        bad2 = json.loads(json.dumps(o)); bad2["sealed_state_b64"] = "!!notb64"
        with self.assertRaises(Exception): record_from_json(bad2)

    def test_dir_store_roundtrip_missing_and_bad_digest(self):
        g = build_system().anchor.record_at(0)
        with tempfile.TemporaryDirectory() as d:
            s = DirRecordStore(os.path.join(d, "r"))
            self.assertIsNone(s.get("0" * 64))
            dg = s.put(g)
            self.assertEqual(s.get(dg).digest(), g.digest())
            with self.assertRaises(ValueError): s.get("../etc/passwd")


class RpcTests(unittest.TestCase):
    def rpc(self, reply=None, exc=None):
        seen = []
        def t(url, body, timeout):
            seen.append(json.loads(body))
            if exc: raise exc
            return reply if isinstance(reply, bytes) else json.dumps(reply).encode()
        return NearRpc("http://x", transport=t), seen

    def test_request_shape_and_decode(self):
        r, seen = self.rpc({"result": {"result": list(b'{"a":1}')}})
        self.assertEqual(r.view_function("c.testnet", "get_head"), {"a": 1})
        p = seen[0]["params"]
        self.assertEqual((seen[0]["method"], p["request_type"], p["finality"], p["method_name"]),
                         ("query", "call_function", "final", "get_head"))
        self.assertEqual(json.loads(base64.b64decode(p["args_base64"])), {})

    def test_error_paths(self):
        with self.assertRaises(NearRpcError): self.rpc({"error": {"name": "X"}})[0].view_function("c", "m")
        with self.assertRaises(NearRpcError): self.rpc({"result": {"error": "no such contract"}})[0].view_function("c", "m")
        with self.assertRaises(NearRpcUnavailable): self.rpc(b"<html>")[0].view_function("c", "m")
        with self.assertRaises(NearRpcUnavailable): self.rpc({"foo": 1})[0].view_function("c", "m")
        with self.assertRaises(NearRpcUnavailable): self.rpc({"result": {"result": [300]}})[0].view_function("c", "m")
        with self.assertRaises(NearRpcUnavailable): self.rpc(None, exc=NearRpcUnavailable("t"))[0].view_function("c", "m")


class SenderTests(unittest.TestCase):
    def test_argv_is_a_list_with_expected_tokens(self):
        s = NearCliSender(CONTRACT, "gate.testnet")
        a = s.argv({"expected_version": 0})
        self.assertIsInstance(a, list)
        for tok in ("as-transaction", "cas", "json-args", "sign-as", "gate.testnet", "sign-with-keychain", "send"):
            self.assertIn(tok, a)
        self.assertNotIn("sign-with-plaintext-private-key", a)       

    def test_last_invocation_is_recorded_for_diagnostics(self):
        s = NearCliSender(CONTRACT, "g.testnet", runner=lambda *a, **k: subprocess.CompletedProcess(a, 3, b"", b"keychain unavailable"))
        self.assertFalse(s.send_cas({}))
        self.assertEqual(s.last, (3, "keychain unavailable"))

    def test_sign_modes(self):
        a = NearCliSender(CONTRACT, "g.testnet", sign_with="legacy-keychain").argv({})
        self.assertIn("sign-with-legacy-keychain", a); self.assertNotIn("sign-with-keychain", a)
        with self.assertRaises(ValueError): NearCliSender(CONTRACT, "g.testnet", sign_with="plaintext-private-key")

    def test_outcomes(self):
        mk = lambda f: NearCliSender(CONTRACT, "g.testnet", runner=f)
        self.assertTrue(mk(lambda *a, **k: subprocess.CompletedProcess(a, 0)).send_cas({}))
        self.assertFalse(mk(lambda *a, **k: subprocess.CompletedProcess(a, 1)).send_cas({}))
        def boom(*a, **k): raise subprocess.TimeoutExpired("near", 1)
        self.assertFalse(mk(boom).send_cas({}))
        def missing(*a, **k): raise FileNotFoundError("near")
        with self.assertRaises(SenderNotSent): mk(missing).send_cas({})


class AnchorReadTests(unittest.TestCase):
    def test_reads_genesis(self):
        _, g, _, _, a, _, _ = make()
        self.assertEqual(a.read().digest(), g.digest())

    def test_rpc_down_is_unavailable(self):
        _, _, m, _, a, _, _ = make(); m.rpc_down = True
        with self.assertRaises(AnchorUnavailable): a.read()

    def test_missing_blob_is_unavailable(self):
        _, _, m, s, a, _, _ = make(); s._d.clear()
        with self.assertRaises(AnchorUnavailable): a.read()

    def test_tampered_blob_is_integrity_error(self):
        _, g, _, s, a, _, _ = make()
        s._d[g.digest()] = Record(g.header, b"tampered" + g.sealed_state[8:])
        with self.assertRaises(AnchorIntegrityError): a.read()

    def test_foreign_scope_or_policy_is_integrity_error(self):
        _, _, m, _, a, _, _ = make(); m.scope = "other"
        with self.assertRaises(AnchorIntegrityError): a.read()
        _, _, m, _, a, _, _ = make(); m.pd = "f" * 64
        with self.assertRaises(AnchorIntegrityError): a.read()

    def test_malformed_head_is_integrity_error(self):
        _, _, m, _, a, _, _ = make(); m.digest = "nothex"
        with self.assertRaises(AnchorIntegrityError): a.read()


class AnchorViewHelpersTests(unittest.TestCase):
    """version/history: read-only helpers used by the live app mode."""
    def test_version_tracks_the_chain_head(self):
        sysobj, g, m, s, a, gate, clk = make()
        self.assertEqual(a.version, 0)
        from harness.system import Client
        Client(sysobj, "V1").ask(499_999, gate=gate)
        self.assertEqual(a.version, 1)

    def test_history_follows_prev_digest_oldest_first_and_honours_the_limit(self):
        sysobj, g, m, s, a, gate, clk = make()
        from harness.system import Client
        c = Client(sysobj, "V1")
        for t in (499_999, 249_999):
            c.ask(t, gate=gate)
        self.assertEqual([r.header.version for r in a.history()], [0, 1, 2])
        self.assertEqual([r.header.version for r in a.history(2)], [1, 2])      
        m.rpc_down = True
        with self.assertRaises(AnchorUnavailable): a.history()                    


class AnchorCasTests(unittest.TestCase):
    def setUp(self):
        self.sysobj, self.g, self.m, self.s, self.a, self.gate, self.clk = make()
        self.n1 = next_record(self.g, self.g, self.sysobj)

    def cas(self, **kw):
        return self.a.compare_and_swap(kw.get("key", WRITER_KEY), 0, self.g.digest(), kw.get("rec", self.n1))

    def test_committed(self):
        self.assertIs(self.cas(), CasResult.COMMITTED)
        self.assertEqual((self.m.version, self.m.digest), (1, self.n1.digest()))

    def test_wrong_writer_key_unauthorized_and_nothing_sent(self):
        self.assertIs(self.cas(key="x"), CasResult.UNAUTHORIZED); self.assertEqual(self.m.sent, [])

    def test_malformed_local_checks_send_nothing(self):
        bad = next_record(self.g, self.g, self.sysobj, version=2)
        self.assertIs(self.cas(rec=bad), CasResult.MALFORMED); self.assertEqual(self.m.sent, [])

    def test_conflict_when_another_record_won(self):
        other = next_record(self.g, self.g, self.sysobj)
        other = Record(Header(*(list(vars(other.header).values())[:3] + ["V2"] + list(vars(other.header).values())[4:])), other.sealed_state)
        self.m._cas({"expected_version": 0, "expected_digest": self.g.digest(), "new_digest": other.digest(), "header": "{}"})
        self.assertIs(self.cas(), CasResult.CONFLICT)

    def test_not_sent_raises_unavailable(self):
        self.m.sender_mode = "not_sent"
        with self.assertRaises(AnchorUnavailable): self.cas()

    def test_applied_but_sender_reports_failure_is_resolved_by_reread(self):
        self.m.sender_mode = "applied_but_fails"
        self.assertIs(self.cas(), CasResult.COMMITTED)

    def test_lost_transaction_is_unknown_after_timeout(self):
        self.m.sender_mode = "lost"
        self.assertIs(self.cas(), CasResult.UNKNOWN); self.assertGreaterEqual(self.clk.t, 10.0)
        self.assertEqual(len(self.m.sent), 1)                         

    def test_stale_head_is_polled_until_fresh(self):
        self.m.stale_head, self.m.stale_reads = (0, self.g.digest()), 2
        self.assertIs(self.cas(), CasResult.COMMITTED)

    def test_rpc_down_after_send_is_unknown(self):
        orig = self.m.send_cas
        def send(args): r = orig(args); self.m.rpc_down = True; return r
        self.m.send_cas = send; self.a.sender = self.m
        self.assertIs(self.cas(), CasResult.UNKNOWN)

    def test_head_beyond_new_version_is_unknown_not_committed(self):
        self.m.sender_mode = "lost"
        self.m.version, self.m.digest = 5, "a" * 64
        self.assertIs(self.cas(), CasResult.UNKNOWN)


class GateOverNearAnchorTests(unittest.TestCase):
    def client(self, sysobj, gate): 
        from harness.system import Client
        c = Client(sysobj, "V1"); return lambda t: c.ask(t, gate=gate)

    def test_gate_answers_and_refuses_like_local(self):
        sysobj, _, m, _, _, gate, _ = make()
        ask = self.client(sysobj, gate)
        r = ask(499_999)
        self.assertEqual((r.kind, r.answer), ("ANSWER", False))      
        self.assertEqual(m.version, 1)

    def test_unknown_applied_still_releases_correct_answer(self):
        sysobj, _, m, _, _, gate, _ = make(); m.sender_mode = "applied_but_fails"
        r = self.client(sysobj, gate)(499_999)
        self.assertEqual((r.kind, r.answer), ("ANSWER", False))

    def test_lost_tx_gives_retry_then_replay_is_safe(self):
        sysobj, _, m, _, _, gate, _ = make(); m.sender_mode = "lost"
        c = self.client(sysobj, gate)
        self.assertEqual(c(499_999).kind, "RETRY")
        self.assertEqual(m.version, 0)                                
        m.sender_mode = "normal"
        self.assertEqual(c(499_999).kind, "ANSWER")

    def test_rpc_down_gives_retry_not_answer(self):
        sysobj, _, m, _, _, gate, _ = make(); m.rpc_down = True
        self.assertEqual(self.client(sysobj, gate)(499_999).kind, "RETRY")

    def test_integrity_error_propagates_as_gate_config_error(self):
        sysobj, g, m, s, _, gate, _ = make(); s._d[g.digest()] = Record(g.header, b"x" * len(g.sealed_state))
        with self.assertRaises(GateConfigError): self.client(sysobj, gate)(499_999)

    def test_nothing_private_goes_on_chain(self):
        sysobj, g, m, s, _, gate, _ = make()
        ask = self.client(sysobj, gate)
        for t in (499_999, 249_999, 124_999):
            ask(t)
        blob = json.dumps({"sent": m.sent, "logs": m.logs})
        for rec in s._d.values():
            self.assertNotIn(base64.b64encode(rec.sealed_state).decode(), blob)
        self.assertNotIn('"lo"', blob); self.assertNotIn('"hi"', blob)
        self.assertNotIn("blinding", blob); self.assertNotIn("auth_tag", blob)
        for a in m.sent:
            self.assertEqual(set(a), {"expected_version", "expected_digest", "new_digest", "header"})
            self.assertEqual(set(json.loads(a["header"])), {"scope_id", "version", "prev_digest", "verifier_id",
                             "nonce", "request_digest", "status_commitment", "policy_digest"})


class StatusAndPreflightTests(unittest.TestCase):
    def rpc(self, result=None, error=None):
        body = {"jsonrpc": "2.0", "id": "x"}
        body.update({"error": error} if error else {"result": result})
        seen = []
        def t(url, b, timeout): seen.append(json.loads(b)); return json.dumps(body).encode()
        return NearRpc("http://x", transport=t), seen

    def test_status_request_and_ok(self):
        r, seen = self.rpc({"chain_id": "testnet", "protocol_version": 88})
        self.assertEqual(preflight(r), [])
        self.assertEqual((seen[0]["method"], seen[0]["params"]), ("status", []))

    def test_old_protocol_and_wrong_chain_are_reported(self):
        p = preflight(self.rpc({"chain_id": "testnet", "protocol_version": 87})[0])
        self.assertEqual(len(p), 1); self.assertIn("88", p[0])
        self.assertEqual(len(preflight(self.rpc({"chain_id": "mainnet", "protocol_version": 99})[0])), 1)

    def test_unreadable_status_is_a_problem_not_a_pass(self):
        self.assertEqual(len(preflight(self.rpc(None, error={"name": "X"})[0])), 1)
        self.assertEqual(len(preflight(self.rpc({"chain_id": "testnet"})[0])), 1)
        self.assertEqual(len(preflight(self.rpc({"chain_id": "testnet", "protocol_version": True})[0])), 1)

    def test_view_account(self):
        r, seen = self.rpc({"amount": "1", "code_hash": "x", "storage_usage": 5})
        self.assertEqual(r.view_account("a.testnet")["storage_usage"], 5)
        self.assertEqual(seen[0]["params"]["request_type"], "view_account")
        with self.assertRaises(NearRpcError): self.rpc({"error": "no such account"})[0].view_account("a.testnet")


def one_shot_client(sysobj, gate):
    """Client that does NOT auto-retry, so each call is exactly one Gate.handle round."""
    from harness.system import Client
    c = Client(sysobj, "V1")
    return lambda t: c.ask(t, gate=gate, retries=1)


class NeverBlindlyResubmitTests(unittest.TestCase):
    """An uncertain write is never re-sent by the adapter. The only second attempt is a NEW transition built by the
    Gate from a fresh read after the client retries; the contract's compare-and-swap lets at most one of them land."""
    def test_every_ambiguous_signer_outcome_sends_exactly_once(self):
        for mode in ("lost", "fails_unapplied", "applied_but_fails", "delayed"):
            sysobj, g, m, s, a, gate, clk = make(); m.sender_mode = mode
            a.compare_and_swap(WRITER_KEY, 0, g.digest(), next_record(g, g, sysobj))
            self.assertEqual(len(m.sent), 1, mode)

    def test_late_landing_tx_then_identical_retry_replays_without_new_write(self):
        from harness.system import Client
        sysobj, g, m, s, a, gate, clk = make(); m.sender_mode = "delayed"
        req = Client(sysobj, "V1").make(499_999)                     
        self.assertEqual(gate.handle(req).kind, "RETRY")              
        self.assertEqual((len(m.sent), m.version), (1, 0))
        self.assertEqual(m.flush(), ["COMMITTED"])                    
        m.sender_mode = "normal"
        r = gate.handle(req)
        self.assertEqual((r.kind, r.answer), ("ANSWER", False))
        self.assertEqual((len(m.sent), m.version), (1, 1))            

    def test_retry_before_late_landing_is_second_transition_and_only_one_lands(self):
        from harness.system import Client
        sysobj, g, m, s, a, gate, clk = make(); m.sender_mode = "delayed"
        req = Client(sysobj, "V1").make(499_999)
        self.assertEqual(gate.handle(req).kind, "RETRY")              
        m.sender_mode = "normal"
        self.assertEqual(gate.handle(req).kind, "ANSWER")             
        self.assertEqual(m.flush(), ["CONFLICT"])                    
        self.assertEqual(m.version, 1)                               
        self.assertEqual(len(m.sent), 2)
        self.assertNotEqual(m.sent[0]["new_digest"], m.sent[1]["new_digest"])
        self.assertEqual(gate.handle(req).answer, False)             

    def test_auto_retrying_client_while_tx_in_flight_still_lands_at_most_one(self):
        sysobj, g, m, s, a, gate, clk = make(); m.sender_mode = "delayed"
        from harness.system import Client
        r = Client(sysobj, "V1").ask(499_999, gate=gate, retries=5)   
        self.assertEqual(r.kind, "RETRY"); self.assertEqual(len(m.sent), 5)
        self.assertEqual(len({x["new_digest"] for x in m.sent}), 5)
        self.assertEqual(sorted(m.flush()), ["COMMITTED"] + ["CONFLICT"] * 4)
        self.assertEqual(m.version, 1)

    def test_cli_sender_timeout_is_ambiguous_not_failure_and_never_retried(self):
        calls = []
        def run(*a, **k): calls.append(a); raise subprocess.TimeoutExpired("near", 1)
        s = NearCliSender(CONTRACT, "g.testnet", runner=run)
        self.assertFalse(s.send_cas({}))
        self.assertEqual(len(calls), 1)


class LiveScriptLogicTests(unittest.TestCase):
    """Runs scripts/near_live_check.py's selftest scenarios against ContractModel. This tests the SCRIPT'S LOGIC
    (nonces, stale-record construction, expected verdicts); it says nothing about the real network."""
    def run_selftest(self, other=True, protocol=88):
        import types, io
        from scripts import near_live_check as nlc
        from core.records import make_genesis, policy_digest
        from harness.system import DEMO_POLICY
        from testdoubles.test_sealer import UnsealedTestSealer
        with tempfile.TemporaryDirectory() as d:
            genesis = make_genesis("scope-live", DEMO_POLICY, nlc.VERIFIERS, UnsealedTestSealer())
            DirRecordStore(d).put(genesis)
            with open(os.path.join(d, "config.json"), "w") as f:
                json.dump({"scope_id": "scope-live", "policy_digest": policy_digest(DEMO_POLICY)}, f)
            m = ContractModel(genesis, writer="gate.testnet", caller="gate.testnet"); m.protocol = protocol
            clk = Clock()
            a = types.SimpleNamespace(store=d, contract=CONTRACT, writer="gate.testnet", network="testnet", rpc="http://x",
                                      confirm_timeout=10.0, other_signer="mallory.testnet" if other else None)
            lines = []
            ok = nlc.run_selftest(a, lambda: NearRpc("http://x", transport=m.transport),
                                  lambda acct: AsCaller(m, acct), sleep=clk.sleep, clock=clk.now, out=lambda *x: lines.append(" ".join(map(str, x))))
            return ok, lines, m

    def test_all_scenarios_pass_against_model(self):
        ok, lines, m = self.run_selftest()
        self.assertTrue(ok, "\n".join(lines))
        self.assertTrue(any("stale CAS is CONFLICT" in l and l.startswith("PASS") for l in lines))
        self.assertTrue(any("unauthorized" in l and l.startswith("PASS") for l in lines))
        self.assertEqual(m.version, 3)               

    def test_init_refuses_to_overwrite_an_existing_genesis(self):
        import types
        from scripts import near_live_check as nlc
        with tempfile.TemporaryDirectory() as d:
            a = types.SimpleNamespace(store=os.path.join(d, "s"), writer="gate.testnet")
            import contextlib
            with contextlib.redirect_stdout(io.StringIO()) as buf: nlc.cmd_init(a)
            first = json.loads(buf.getvalue())
            with self.assertRaises(SystemExit): nlc.cmd_init(a)
            with open(os.path.join(a.store, "config.json")) as f:
                self.assertEqual(json.load(f)["scope_id"], first["scope_id"])

    def test_old_protocol_aborts_before_any_write(self):
        ok, lines, m = self.run_selftest(protocol=87)
        self.assertFalse(ok); self.assertEqual((m.version, m.sent), (0, []))

    def test_without_other_signer_the_unauthorized_scenario_is_skipped_visibly(self):
        ok, lines, m = self.run_selftest(other=False)
        self.assertTrue(ok); self.assertTrue(any(l.startswith("SKIP unauthorized") for l in lines))


if __name__ == "__main__":
    unittest.main()
