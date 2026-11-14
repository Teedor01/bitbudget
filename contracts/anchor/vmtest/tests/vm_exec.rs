//! Runs contracts/anchor's release wasm in the nearcore VM. Build the wasm first:
//!   cd .. && cargo build --target wasm32-unknown-unknown --release --locked
use std::sync::Arc;

use near_parameters::{RuntimeConfigStore, RuntimeFeesConfig};
use near_primitives_core::code::ContractCode;
use near_primitives_core::types::{Balance, Gas};
use near_primitives_core::version::PROTOCOL_VERSION;
use near_vm_runner::logic::mocks::mock_external::MockedExternal;
use near_vm_runner::internal::VMKindExt;
use near_vm_runner::logic::{ReturnData, VMContext, VMOutcome};

const WASM: &str = "../target/wasm32-unknown-unknown/release/bitbudget_anchor.wasm";
const D0: &str = "0000000000000000000000000000000000000000000000000000000000000001";
const D1: &str = "0000000000000000000000000000000000000000000000000000000000000002";
const D2: &str = "0000000000000000000000000000000000000000000000000000000000000003";
const PD: &str = "00000000000000000000000000000000000000000000000000000000000000aa";

struct Vm {
    ext: MockedExternal,
    cfg: near_parameters::vm::Config,
    storage_usage: u64,
    balance: Balance,
}

impl Vm {
    fn new() -> Self {
        // ANCHOR_WASM overrides the default path (lets CI/local runs test a wasm built in another target dir)
        let path = std::env::var("ANCHOR_WASM").unwrap_or_else(|_| WASM.to_string());
        let wasm = std::fs::read(&path).unwrap_or_else(|e| panic!("cannot read wasm {path}: {e} (build it first)"));
        let store = RuntimeConfigStore::new(None);
        let cfg = store.get_config(PROTOCOL_VERSION).wasm_config.clone();
        let cfg = near_parameters::vm::Config { vm_kind: near_parameters::vm::VMKind::Wasmtime, ..(*cfg).clone() };
        let storage_usage = wasm.len() as u64 + 100;   // code + account overhead, carried forward between calls
        Vm { ext: MockedExternal::with_code(ContractCode::new(wasm, None)), cfg, storage_usage, balance: Balance::from_near(100) }
    }

    fn call(&mut self, who: &str, method: &str, args: serde_json::Value) -> VMOutcome {
        let ctx = VMContext {
            current_account_id: "anchor.testnet".parse().unwrap(),
            signer_account_id: who.parse().unwrap(),
            signer_account_pk: vec![0, 1, 2],
            predecessor_account_id: who.parse().unwrap(),
            refund_to_account_id: who.parse().unwrap(),
            input: std::rc::Rc::from(args.to_string().into_bytes()),
            promise_results: Vec::new().into(),
            block_height: 10,
            block_timestamp: 42,
            epoch_height: 1,
            account_balance: self.balance,
            account_locked_balance: Balance::ZERO,
            storage_usage: self.storage_usage,
            account_contract: near_primitives_core::account::AccountContract::None,
            attached_deposit: Balance::ZERO,
            prepaid_gas: Gas::from_teragas(100),
            random_seed: vec![0, 1, 2],
            view_config: None,
            output_data_receivers: vec![],
        };
        let gas_counter = ctx.make_gas_counter(&self.cfg);
        let rt = near_parameters::vm::VMKind::Wasmtime.runtime(Arc::new(self.cfg.clone())).expect("wasmtime runtime");
        let o = rt.prepare(&self.ext, None, gas_counter, method)
            .run(&mut self.ext, &ctx, Arc::new(RuntimeFeesConfig::test()))
            .expect("vm error");
        if o.aborted.is_none() {
            self.storage_usage = o.storage_usage;
            self.balance = o.balance;
        }
        o
    }

    fn ok(&mut self, who: &str, method: &str, args: serde_json::Value) -> (serde_json::Value, Vec<String>) {
        let o = self.call(who, method, args);
        assert!(o.aborted.is_none(), "{method} aborted: {:?}", o.aborted);
        let v = match o.return_data {
            ReturnData::Value(b) => serde_json::from_slice(&b).expect("json return"),
            ReturnData::None => serde_json::Value::Null,
            _ => panic!("unexpected return data"),
        };
        (v, o.logs)
    }
}

fn init(vm: &mut Vm) {
    vm.ok("gate.testnet", "new", serde_json::json!({
        "writer": "gate.testnet", "scope_id": "s", "policy_digest": PD, "genesis_digest": D0}));
}

fn cas(vm: &mut Vm, who: &str, ev: u64, ed: &str, nd: &str) -> (String, Vec<String>) {
    let (v, logs) = vm.ok(who, "cas", serde_json::json!({
        "expected_version": ev, "expected_digest": ed, "new_digest": nd, "header": "{\"nonce\":1}"}));
    (v.as_str().unwrap().to_string(), logs)
}

#[test]
fn wasm_loads_and_reports_protocol_version() {
    println!("nearcore VM crate PROTOCOL_VERSION = {PROTOCOL_VERSION}");
    let mut vm = Vm::new();
    init(&mut vm);
}

#[test]
fn head_after_init() {
    let mut vm = Vm::new();
    init(&mut vm);
    let (h, _) = vm.ok("anyone.testnet", "get_head", serde_json::json!({}));
    assert_eq!(h["version"], 0);
    assert_eq!(h["digest"], D0);
    assert_eq!(h["scope_id"], "s");
    assert_eq!(h["policy_digest"], PD);
    assert_eq!(h["writer"], "gate.testnet");
}

#[test]
fn committed_then_stale_conflict_then_unauthorized() {
    let mut vm = Vm::new();
    init(&mut vm);
    let (r, logs) = cas(&mut vm, "gate.testnet", 0, D0, D1);
    assert_eq!(r, "COMMITTED");
    assert_eq!(logs.len(), 1);
    assert!(logs[0].starts_with("EVENT_JSON:"));
    // stale compare-and-swap: same expected values again
    let (r, logs) = cas(&mut vm, "gate.testnet", 0, D0, D2);
    assert_eq!(r, "CONFLICT");
    assert!(logs.is_empty());
    // unauthorized writer
    let (r, logs) = cas(&mut vm, "mallory.testnet", 1, D1, D2);
    assert_eq!(r, "UNAUTHORIZED");
    assert!(logs.is_empty());
    let (h, _) = vm.ok("anyone.testnet", "get_head", serde_json::json!({}));
    assert_eq!((h["version"].as_u64(), h["digest"].as_str()), (Some(1), Some(D1)));
    // chain continues from the new head
    let (r, _) = cas(&mut vm, "gate.testnet", 1, D1, D2);
    assert_eq!(r, "COMMITTED");
}

#[test]
fn second_init_is_rejected() {
    let mut vm = Vm::new();
    init(&mut vm);
    let o = vm.call("gate.testnet", "new", serde_json::json!({
        "writer": "gate.testnet", "scope_id": "other", "policy_digest": PD, "genesis_digest": D1}));
    assert!(o.aborted.is_some(), "re-initialisation must abort");
}
