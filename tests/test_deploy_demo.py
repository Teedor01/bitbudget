import json
import os
import pathlib
import subprocess
import tempfile
import unittest
from unittest import mock

from integrations.near_rpc import NearRpc, NearRpcUnavailable
from scripts import deploy_demo as dd

YOCTO = 10 ** 24


class Clock:
    def __init__(self): self.t = 0.0
    def now(self): return self.t
    def sleep(self, s): self.t += s


class FakeChain:
    """In-memory model: accounts, their code_hash, the contract head, and the near CLI's effects and failure modes.
    mode[kind] in: ok | timeout_applied | timeout_lost | fail_applied | fail_lost | missing | wrong_code | bad_init"""
    def __init__(self, balance_near=2.0, protocol=88):
        self.accounts, self.heads, self.calls, self.rpc_calls = {}, {}, [], 0
        self.balance, self.protocol, self.rpc_down, self.unreadable_after_cli = balance_near, protocol, False, False
        self.mode = {"create": "ok", "deploy": "ok"}
        self.version_text = "near-cli-rs 0.30.1"

    # ---- RPC ----
    def transport(self, url, body, timeout):
        self.rpc_calls += 1
        if self.rpc_down or (self.unreadable_after_cli and self.calls):
            raise NearRpcUnavailable("down")
        req = json.loads(body)
        wrap = lambda r: json.dumps({"jsonrpc": "2.0", "id": "x", "result": r}).encode()
        if req["method"] == "status":
            return wrap({"chain_id": "testnet", "protocol_version": self.protocol})
        p = req["params"]
        if p["request_type"] == "view_account":
            a = self.accounts.get(p["account_id"])
            if a is None:
                return wrap({"error": "account %s does not exist while viewing" % p["account_id"], "logs": []})
            return wrap({"amount": str(a["amount"]), "code_hash": a["code_hash"], "storage_usage": 100})
        head = self.heads.get(p["account_id"])
        if head is None:
            return wrap({"error": "contract code is not deployed", "logs": []})
        return wrap({"result": list(json.dumps(head).encode()), "logs": []})

    def rpc(self):
        return NearRpc("http://x", transport=self.transport)

    # ---- near CLI ----
    def runner(self, argv, capture_output=True, text=True, timeout=0, check=False):
        argv = list(argv)
        if argv[-1] == "--help":
            return subprocess.CompletedProcess(argv, 0, "usage", "")
        if argv[1:2] == ["--version"]:
            return subprocess.CompletedProcess(argv, 0, self.version_text, "")
        self.calls.append(argv)
        kind = "create" if argv[1:3] == ["account", "create-account"] else "deploy"
        mode = self.mode[kind]
        if mode == "missing":
            raise FileNotFoundError("near")
        if mode in ("ok", "timeout_applied", "fail_applied", "wrong_code", "bad_init"):
            self._apply(kind, argv, mode)
        if mode.startswith("timeout"):
            raise subprocess.TimeoutExpired(argv, timeout)
        failed = mode.startswith("fail")
        return subprocess.CompletedProcess(argv, 1 if failed else 0, "" if failed else "transaction ok", "error" if failed else "")

    def _apply(self, kind, argv, mode):
        if kind == "create":
            self.accounts[argv[4]] = {"amount": int(self.balance * YOCTO), "code_hash": dd.ZERO_CODE_HASH}
            return
        acct, wasm = argv[3], pathlib.Path(argv[5]).read_bytes()
        init = json.loads(argv[argv.index("json-args") + 1])
        self.accounts[acct]["code_hash"] = "OTHERHASHOTHERHASHOTHERHASH" if mode == "wrong_code" else dd.code_hash_of(wasm)
        self.heads[acct] = {"version": 1 if mode == "bad_init" else 0, "digest": init["genesis_digest"], "scope_id": init["scope_id"],
                            "policy_digest": init["policy_digest"], "writer": init["writer"]}


class Case(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.store = os.path.join(self.tmp.name, "bbstore-demo-test")
        self.chain, self.clk = FakeChain(), Clock()

    def run_stage(self, stage, *extra, store=None, chain=None):
        chain = chain or self.chain
        lines = []
        code = dd.main([stage, "--store", store or self.store, *extra], out=lines.append, rpc=chain.rpc(),
                       runner=chain.runner, sleep=self.clk.sleep, clock=self.clk.now)
        return code, "\n".join(lines)

    def prepared(self):
        code, text = self.run_stage("prepare"); self.assertEqual(code, 0, text)

    def go(self, stage):
        return self.run_stage(stage, "--execute", "--confirm", "bbdemo-teedor.testnet")

    def plan_json(self):
        with open(os.path.join(self.store, dd.PLAN_FILE)) as f:
            return json.load(f)


class Guards(Case):
    def test_DD01_evidence_account_and_store_are_refused_everywhere_with_no_network_or_cli_use(self):
        for stage in dd.STAGES:
            for extra, expect in ((["--contract", "bbanchor-teedor.testnet"], "evidence deployment"),
                                  (["--store", os.path.join(self.tmp.name, "bbstore")], "evidence store")):
                chain = FakeChain()
                code, text = self.run_stage(stage, *extra, store=self.store if "--store" not in extra else None, chain=chain) \
                    if "--store" not in extra else (dd.main([stage, *extra], out=lambda s: None, rpc=chain.rpc(), runner=chain.runner), "")
                self.assertEqual(code, 1, (stage, extra)); self.assertEqual((chain.calls, chain.rpc_calls), ([], 0), (stage, extra))

    def test_DD02_bad_ids_and_contract_equal_to_writer_are_refused(self):
        for extra in (["--contract", "Bad Account!"], ["--writer", "x"], ["--contract", "teedor.testnet"]):
            code, text = self.run_stage("plan", *extra)
            self.assertEqual(code, 1, extra); self.assertIn("REFUSED", text)

    def test_DD03_a_tampered_wasm_is_refused_before_anything_is_sent(self):
        bad = os.path.join(self.tmp.name, "tampered.wasm")
        data = bytearray(pathlib.Path(dd.WASM_PATH).read_bytes()); data[100] ^= 1
        pathlib.Path(bad).write_bytes(bytes(data))
        with mock.patch.object(dd, "WASM_PATH", bad):
            for stage in ("plan", "create-account", "deploy", "verify"):
                chain = FakeChain()
                code, text = self.run_stage(stage, chain=chain)
                self.assertEqual(code, 1, stage); self.assertIn("hash mismatch", text); self.assertEqual((chain.calls, chain.rpc_calls), ([], 0))

    def test_DD04_code_hash_encoding_matches_known_vectors_and_the_dist_wasm(self):
        self.assertEqual(dd.b58encode(bytes(32)), dd.ZERO_CODE_HASH)
        self.assertEqual(dd.b58encode(__import__("hashlib").sha256(b"").digest()), "GKot5hBsd81kMupNCXHaqbhv3huEbxAFMLnpcX2hniwn")
        self.assertEqual(dd.code_hash_of(pathlib.Path(dd.WASM_PATH).read_bytes()), "2P2vzhQ2U5xNwqZGT1UT4pk6zLXXo73vGJCfTQ5SQTSn")

    def test_DD05_required_balance_is_computed_from_the_wasm(self):
        n = len(pathlib.Path(dd.WASM_PATH).read_bytes())
        self.assertEqual(dd.near(dd.required_yocto(n)), "1.0999 NEAR")
        self.assertGreater(dd.required_yocto(n), (n + 864) * 10 ** 19)


class PlanSyntaxPrepare(Case):
    def test_DD06_plan_is_offline_and_states_the_stop_rules(self):
        code, text = self.run_stage("plan")
        self.assertEqual((code, self.chain.calls, self.chain.rpc_calls), (0, [], 0))
        for needle in ("never touched", "2P2vzhQ2U5xNwqZGT1UT4pk6zLXXo73vGJCfTQ5SQTSn", "1.0999 NEAR", "selftest", "nothing is retried",
                       "sponsor-by-faucet-service", "sign-with-keychain"):
            self.assertIn(needle, text)
        self.assertFalse(os.path.exists(self.store))

    def test_DD07_syntax_only_asks_the_binary_to_parse_and_warns_on_a_different_version(self):
        code, text = self.run_stage("syntax")
        self.assertEqual((code, self.chain.calls, self.chain.rpc_calls), (0, [], 0)); self.assertIn("PASSED", text)
        self.chain.version_text = "near-cli-rs 0.31.0"
        code, text = self.run_stage("syntax"); self.assertIn("Do NOT upgrade", text)

    def test_DD08_prepare_makes_a_fresh_scope_and_never_overwrites(self):
        sibling = os.path.join(self.tmp.name, "bbstore"); os.makedirs(sibling); pathlib.Path(sibling, "keep.txt").write_text("evidence")
        self.prepared()
        p = self.plan_json(); ia = p["init_args"]
        self.assertNotEqual(ia["scope_id"], dd.EVIDENCE_SCOPE_ID); self.assertNotEqual(ia["genesis_digest"], dd.EVIDENCE_GENESIS_DIGEST)
        self.assertEqual((p["contract"], p["writer"], ia["writer"]), ("bbdemo-teedor.testnet", "teedor.testnet", "teedor.testnet"))
        self.assertTrue(os.path.exists(os.path.join(self.store, ia["genesis_digest"] + ".json")))
        before = pathlib.Path(self.store, dd.PLAN_FILE).read_text()
        code, text = self.run_stage("prepare")                         # second prepare: refused, nothing changes
        self.assertEqual(code, 1); self.assertIn("fresh", text)
        self.assertEqual(pathlib.Path(self.store, dd.PLAN_FILE).read_text(), before)
        self.assertEqual(pathlib.Path(sibling, "keep.txt").read_text(), "evidence")
        self.assertEqual((self.chain.calls, self.chain.rpc_calls), ([], 0))
        other = os.path.join(self.tmp.name, "other-demo")
        self.run_stage("prepare", store=other)
        with open(os.path.join(other, dd.PLAN_FILE)) as f:
            self.assertNotEqual(json.load(f)["init_args"]["scope_id"], ia["scope_id"])

    def test_DD09_prepare_refuses_a_directory_that_already_has_content(self):
        os.makedirs(self.store); pathlib.Path(self.store, "x").write_text("1")
        code, text = self.run_stage("prepare"); self.assertEqual(code, 1); self.assertIn("fresh", text)


class CreateAccount(Case):
    def test_DD10_dry_run_and_missing_confirmation_send_nothing(self):
        self.prepared()
        code, text = self.run_stage("create-account")
        self.assertEqual((code, self.chain.calls), (0, [])); self.assertIn("DRY RUN", text); self.assertIn("1.0999 NEAR", text)
        code, text = self.run_stage("create-account", "--execute")
        self.assertEqual((code, self.chain.calls), (1, [])); self.assertIn("--confirm", text)
        code, text = self.run_stage("create-account", "--execute", "--confirm", "wrong.testnet")
        self.assertEqual((code, self.chain.calls), (1, []))

    def test_DD11_refuses_without_a_prepared_store_and_if_the_account_exists(self):
        code, text = self.run_stage("create-account"); self.assertEqual(code, 1); self.assertIn("prepare", text)
        self.prepared(); self.chain.accounts["bbdemo-teedor.testnet"] = {"amount": 5, "code_hash": dd.ZERO_CODE_HASH}
        code, text = self.go("create-account")
        self.assertEqual((code, self.chain.calls), (1, [])); self.assertIn("already exists", text)

    def test_DD12_success_sends_exactly_one_faucet_transaction_as_an_argument_list(self):
        self.prepared()
        code, text = self.go("create-account")
        self.assertEqual(code, 0, text); self.assertEqual(len(self.chain.calls), 1)
        self.assertEqual(self.chain.calls[0], ["near", "account", "create-account", "sponsor-by-faucet-service", "bbdemo-teedor.testnet",
                                               "autogenerate-new-keypair", "save-to-keychain", "network-config", "testnet", "create"])
        self.assertIn("balance 2.0000 NEAR", text); self.assertNotIn("WARNING", text)

    def test_DD13_low_balance_is_flagged(self):
        self.prepared(); self.chain.balance = 0.5
        code, text = self.go("create-account"); self.assertEqual(code, 0); self.assertIn("WARNING", text)

    def test_DD14_ambiguous_creation_stops_and_does_not_retry(self):
        self.prepared(); self.chain.mode["create"] = "timeout_lost"
        code, text = self.go("create-account")
        self.assertEqual(code, 2); self.assertEqual(len(self.chain.calls), 1)
        self.assertIn("STOP", text); self.assertIn("Do not re-run", text); self.assertNotIn("bbdemo-teedor.testnet", self.chain.accounts)

    def test_DD15_the_chain_is_authoritative_when_the_cli_reports_failure_but_the_account_exists(self):
        self.prepared(); self.chain.mode["create"] = "fail_applied"
        code, text = self.go("create-account")
        self.assertEqual((code, len(self.chain.calls)), (0, 1)); self.assertIn("chain is authoritative", text)

    def test_DD16_unreadable_chain_after_sending_is_ambiguous_not_nothing_was_sent(self):
        self.prepared(); self.chain.unreadable_after_cli = True
        code, text = self.go("create-account")
        self.assertEqual((code, len(self.chain.calls)), (2, 1))
        self.assertIn("may have been sent", text); self.assertIn("chain unreadable", text); self.assertNotIn("nothing was sent", text)

    def test_DD17_missing_binary_sends_nothing(self):
        self.prepared(); self.chain.mode["create"] = "missing"
        code, text = self.go("create-account"); self.assertEqual(code, 1); self.assertIn("nothing was sent", text)


class Deploy(Case):
    def ready(self):
        self.prepared(); self.assertEqual(self.go("create-account")[0], 0); self.chain.calls.clear()

    def test_DD18_every_precondition_blocks_with_no_cli_call(self):
        self.prepared()
        code, text = self.go("deploy"); self.assertEqual(code, 1); self.assertIn("create-account", text)       # no account
        self.assertEqual(self.chain.calls, [])
        self.chain.accounts["bbdemo-teedor.testnet"] = {"amount": int(0.3 * YOCTO), "code_hash": dd.ZERO_CODE_HASH}
        code, text = self.go("deploy"); self.assertEqual(code, 1); self.assertIn("below the required", text)   # low balance
        self.chain.accounts["bbdemo-teedor.testnet"] = {"amount": 2 * YOCTO, "code_hash": "SOMECODEHASH"}
        code, text = self.go("deploy"); self.assertEqual(code, 1); self.assertIn("never redeploy", text)       # already a contract
        self.chain.accounts["bbdemo-teedor.testnet"]["code_hash"] = dd.ZERO_CODE_HASH; self.chain.protocol = 87
        code, text = self.go("deploy"); self.assertEqual(code, 1); self.assertIn("protocol_version", text)     # old network
        self.assertEqual(self.chain.calls, [])
        fresh = FakeChain(); code, text = self.run_stage("deploy", "--execute", "--confirm", "bbdemo-teedor.testnet", store=os.path.join(self.tmp.name, "nope"), chain=fresh)
        self.assertEqual((code, fresh.calls), (1, []))                                                           # unprepared store

    def test_DD19_dry_run_and_missing_confirmation_send_nothing(self):
        self.ready()
        code, text = self.run_stage("deploy"); self.assertEqual((code, self.chain.calls), (0, [])); self.assertIn("DRY RUN", text)
        code, text = self.run_stage("deploy", "--execute"); self.assertEqual((code, self.chain.calls), (1, []))

    def test_DD20_success_is_one_atomic_transaction_with_the_init_json_as_a_single_argument(self):
        self.ready()
        code, text = self.go("deploy")
        self.assertEqual(code, 0, text); self.assertEqual(len(self.chain.calls), 1)
        argv, ia = self.chain.calls[0], self.plan_json()["init_args"]
        self.assertEqual(argv[:6], ["near", "contract", "deploy", "bbdemo-teedor.testnet", "use-file", dd.WASM_PATH])
        self.assertEqual(argv[6:9], ["with-init-call", "new", "json-args"])
        self.assertEqual(json.loads(argv[9]), ia); self.assertNotIn(" ", argv[9].replace('": ', ""))          # one compact JSON element
        self.assertEqual(argv[10:], ["prepaid-gas", "100 TeraGas", "attached-deposit", "0 NEAR", "network-config", "testnet", "sign-with-keychain", "send"])
        self.assertIn("CONFIRMED by the chain", text)
        self.assertEqual(self.chain.accounts["bbdemo-teedor.testnet"]["code_hash"], "2P2vzhQ2U5xNwqZGT1UT4pk6zLXXo73vGJCfTQ5SQTSn")

    def test_DD21_applied_despite_a_timeout_is_confirmed_by_the_chain_and_a_second_deploy_is_refused(self):
        self.ready(); self.chain.mode["deploy"] = "timeout_applied"
        code, text = self.go("deploy")
        self.assertEqual((code, len(self.chain.calls)), (0, 1)); self.assertIn("chain is authoritative", text)
        code, text = self.go("deploy")                                  
        self.assertEqual((code, len(self.chain.calls)), (1, 1)); self.assertIn("never redeploy", text)

    def test_DD22_lost_or_failed_deploy_is_ambiguous_stops_and_is_never_retried_by_the_script(self):
        for mode in ("timeout_lost", "fail_lost"):
            self.setUp(); self.ready(); self.chain.mode["deploy"] = mode
            code, text = self.go("deploy")
            self.assertEqual((code, len(self.chain.calls)), (2, 1), mode)
            self.assertIn("STOP", text); self.assertIn("Do NOT re-run", text); self.assertEqual(self.chain.heads, {})

    def test_DD23_unreadable_chain_after_sending_is_reported_as_possibly_sent(self):
        self.ready(); self.chain.unreadable_after_cli = True
        code, text = self.go("deploy")
        self.assertEqual((code, len(self.chain.calls)), (2, 1)); self.assertIn("may have been sent", text); self.assertNotIn("nothing was sent", text)

    def test_DD24_unexpected_code_hash_or_initial_state_stops(self):
        self.ready(); self.chain.mode["deploy"] = "wrong_code"
        code, text = self.go("deploy"); self.assertEqual(code, 1); self.assertIn("expected hash", text)
        self.setUp(); self.ready(); self.chain.mode["deploy"] = "bad_init"
        code, text = self.go("deploy"); self.assertEqual(code, 1); self.assertIn("UNEXPECTED initial state", text)


class Verify(Case):
    def deployed(self):
        self.prepared(); self.assertEqual(self.go("create-account")[0], 0); self.assertEqual(self.go("deploy")[0], 0); self.chain.calls.clear()

    def test_DD25_readback_passes_through_both_independent_paths_and_is_read_only(self):
        self.deployed()
        code, text = self.run_stage("verify")
        self.assertEqual(code, 0, text); self.assertIn("READ-BACK PASSED (11/11)", text)
        for needle in ("Python adapter read", "read-only chain_head reader", "both paths agree", "genesis of THIS store", "code_hash equals the verified wasm"):
            self.assertIn(needle, text)
        self.assertIn("py -m app.server --anchor near --store", text)
        self.assertEqual(self.chain.calls, [])                          

    def test_DD26_any_mismatch_fails_the_readback_and_withholds_the_app_command(self):
        cases = {"code hash": lambda c: c.accounts["bbdemo-teedor.testnet"].update(code_hash="OTHER"),
                 "genesis digest": lambda c: c.heads["bbdemo-teedor.testnet"].update(digest="f" * 64),
                 "scope": lambda c: c.heads["bbdemo-teedor.testnet"].update(scope_id="other"),
                 "writer": lambda c: c.heads["bbdemo-teedor.testnet"].update(writer="mallory.testnet"),
                 "version": lambda c: c.heads["bbdemo-teedor.testnet"].update(version=1)}
        for name, mutate in cases.items():
            self.setUp(); self.deployed(); mutate(self.chain)
            code, text = self.run_stage("verify")
            self.assertEqual(code, 1, name); self.assertIn("READ-BACK FAILED", text, name); self.assertNotIn("app.server", text, name)

    def test_DD27_wrong_expected_version_and_missing_account_fail(self):
        self.deployed()
        code, text = self.run_stage("verify", "--expect-version", "3")
        self.assertEqual(code, 1); self.assertIn("FAIL version is 3", text)
        self.chain.accounts.clear()
        code, text = self.run_stage("verify"); self.assertEqual(code, 1); self.assertIn("FAIL account exists", text)

    def test_DD29_the_two_readback_paths_must_agree_when_the_head_moves_between_reads(self):
        self.deployed()
        orig, state = self.chain.transport, {"n": 0}
        def moving(url, body, timeout):                      
            raw = orig(url, body, timeout)
            if json.loads(body)["method"] == "query" and json.loads(body)["params"]["request_type"] == "call_function":
                state["n"] += 1
                if state["n"] >= 2:
                    obj = json.loads(raw); head = json.loads(bytes(obj["result"]["result"]).decode())
                    head.update(version=1, digest="a" * 64)
                    obj["result"]["result"] = list(json.dumps(head).encode()); return json.dumps(obj).encode()
            return raw
        self.chain.transport = moving
        code, text = self.run_stage("verify")
        self.assertEqual(code, 1); self.assertIn("FAIL both paths agree", text); self.assertNotIn("app.server", text)

    def test_DD28_old_network_fails_the_readback_before_reading_anything_else(self):
        self.deployed(); self.chain.protocol = 80
        code, text = self.run_stage("verify"); self.assertEqual(code, 1); self.assertIn("FAIL testnet preflight", text); self.assertNotIn("app.server", text)


if __name__ == "__main__":
    unittest.main()
