# NEAR_DEPLOY.md: Deploying the Bit Budget Anchor Contract on NEAR Testnet

## Status

I have deployed and initialized the Bit Budget anchor contract on NEAR testnet. I also completed the original network self-test, including the read checks and all 10 integrity and transaction checks. The results are documented in `NEAR_EVIDENCE.md`, section 8.

I later deployed a separate contract for the public demo. The two deployments serve different purposes:

- **Evidence deployment:** `bbanchor-teedor.testnet`, using `bbstore`.
- **Demo deployment:** `bbdemo-teedor.testnet`, using `bbstore-demo`.

I keep these deployments and their stores separate. The demo must never modify the original evidence deployment.

The contract compiles, its 11 Rust unit tests pass, and the compiled WASM has been executed in the nearcore VM crate. I also checked the CLI commands against the actual `near-cli-rs` v0.30.1 binary.

Keep `near-cli-rs` at **v0.30.1**. Do not redeploy over a working contract or run `init` against an existing store. The procedure below documents how I prepared and deployed the contract. It can also serve as a reference for a fresh deployment using new account names and a new store.

**Cost:** $0. The deployment uses NEAR testnet and faucet-funded accounts. It does not require a credit card, paid trial, or real tokens.

---

## 0. Prerequisites

| Requirement | Version / details |
|---|---|
| Python | 3.12 (tested with 3.12.3), standard library only |
| near-cli-rs | **v0.30.1**. `near --version` should print `near-cli-rs 0.30.1`. |
| Network | HTTPS access to the FastNEAR testnet RPC and the faucet service used by `sponsor-by-faucet-service` |
| Rust | Not required for deployment because the compiled contract is included in `contracts/anchor/dist/`. Required only if rebuilding. |
| Rust versions | Rust 1.99.1 or 1.95.0, both checked locally with near-sdk 5.30.0 |
| Rust target | `wasm32-unknown-unknown` |
| Key storage | `keychain` requires a system keychain. On a headless Linux machine, use `legacy-keychain` and the corresponding CLI options. |
| Network protocol | Testnet `protocol_version` must be **88 or higher**. Step 3 checks this. |

The default testnet RPC for near-cli-rs v0.30.1 is:

`https://test.rpc.fastnear.com/`

No RPC configuration change is required.

### Installing near-cli-rs v0.30.1

For Linux x86_64:

```bash
curl -sSL -o near.tgz https://github.com/near/near-cli-rs/releases/download/v0.30.1/near-cli-rs-x86_64-unknown-linux-gnu.tar.gz && tar xzf near.tgz && export PATH="$PWD/near-cli-rs-x86_64-unknown-linux-gnu:$PATH"
```

For other platforms, use the installer from the same release.

For a fresh deployment, I use three unique lowercase account names:

```bash
export SUFFIX=<yourhandle>
export CONTRACT=bbanchor-$SUFFIX.testnet
export WRITER=bbgate-$SUFFIX.testnet
export OTHER=bbother-$SUFFIX.testnet
```

`OTHER` is optional. I only need it for the unauthorized-writer test.

---

## 1. Check the CLI commands

This check does not access the network or sign anything. It verifies that the commands in the deployment procedure are accepted by the installed CLI.

```bash
python3 scripts/check_cli_syntax.py --near "$(command -v near)"
```

Every line should report `OK`.

This confirms that the commands parse. It does not prove that a transaction will succeed.

On Windows, I use `py` instead of `python3` where appropriate.

---

## 2. Verify the contract binary

Before deployment, I verify the compiled WASM against the recorded checksum:

```bash
(cd contracts/anchor/dist && sha256sum -c SHA256SUMS)
```

Expected result:

```text
bitbudget_anchor.wasm: OK
```

The recorded SHA-256 begins with `1480a5e6` and ends with `c2e7`.

I can rebuild the contract with:

```bash
cd contracts/anchor
cargo test --locked
cargo build --locked --target wasm32-unknown-unknown --release
```

The Rust 1.99.1 build is byte-identical across rebuilds and fresh build directories. Rust 1.95.0 produces a 101,808-byte build with a different hash (`cd0e352c...c6df`). A different hash from another Rust version is not automatically a problem.

I also run the VM harness:

```bash
cd vmtest
cargo test --locked
```

---

## 3. Run the read-only preflight

```bash
python3 scripts/near_live_check.py preflight
```

Expected result:

```text
preflight: OK
```

The testnet protocol version must be at least 88 because near-sdk 5.30.0 declares `min_protocol_version = 88`.

If the reported version is lower than 88, I stop. The deployed contract may be rejected with a `PrepareError`. I would need to rebuild against an older compatible near-sdk version and Rust toolchain.

---

## 4. Create the testnet accounts

For a fresh deployment, I create the contract account and writer account through the faucet service:

```bash
near account create-account sponsor-by-faucet-service $CONTRACT autogenerate-new-keypair save-to-keychain network-config testnet create
```

I repeat the command for `$WRITER` and, if needed, `$OTHER`.

Then I check the contract account balance:

```bash
near tokens $CONTRACT view-near-balance network-config testnet now
```

The contract account needs enough NEAR to cover storage. The WASM is 102,890 bytes, and storage staking is calculated at \(10^{19}\) yoctoNEAR per byte, plus the contract state.

I do not assume the faucet will provide a particular amount. Its funding amount and rate limits may vary. If the balance is insufficient, deployment will fail with an account-balance error.

---

## 5. Generate the initial state

I generate the initial state exactly once for each fresh store:

```bash
python3 scripts/near_live_check.py init --store ./bbstore --writer $WRITER > init.json
```

Then I inspect the generated file:

```bash
cat init.json
```

It contains one JSON line with:

- `writer`
- `scope_id`
- `policy_digest`
- `genesis_digest`

The command refuses to initialize a store that already contains state.

The sealed state is stored locally. If I lose the store, I cannot simply recreate it and expect it to match the existing on-chain deployment. A fresh deployment requires a fresh contract account and a fresh store.

---

## 6. Deploy and initialize the contract

I deploy the WASM and initialize the contract in one transaction. The contract account signs and deploys to itself.

```bash
near contract deploy $CONTRACT use-file contracts/anchor/dist/bitbudget_anchor.wasm with-init-call new json-args "$(cat init.json)" prepaid-gas '100 TeraGas' attached-deposit '0 NEAR' network-config testnet sign-with-keychain send
```

The transaction should finish without an error.

With near-cli-rs v0.30.1, `send` waits for the transaction to reach `final` by default.

---

## 7. Read the contract state back

I verify the deployed contract through the Python adapter:

```bash
python3 scripts/near_live_check.py read --store ./bbstore --contract $CONTRACT
```

For a fresh deployment, the expected result is:

```text
chain head: version=0 digest=<genesis_digest>
```

I can also read the contract directly through the CLI:

```bash
near contract call-function as-read-only $CONTRACT get_head json-args '{}' network-config testnet now
```

The read-only call lets me inspect the on-chain head without submitting a transaction.

---

## 8. Run the network self-test

I run the self-test against the evidence deployment:

```bash
python3 scripts/near_live_check.py selftest --store ./bbstore --contract $CONTRACT --writer $WRITER --other-signer $OTHER
```

The self-test checks:

1. Network preflight.
2. Initial chain read.
3. Two successful Gate writes.
4. Whether the chain advances by exactly two versions.
5. A stale compare-and-swap attempt, which must return `CONFLICT` without changing the head.
6. An unauthorized signer, which must not move the head.
7. A transaction that lands even though the signer reports failure. The adapter must re-read the head before releasing the answer, and it must broadcast only once.
8. A failed write, where no answer is released and the head remains unchanged.

The test ends with:

```text
SELFTEST: ALL PASSED (n/n)
```

Each transaction takes time to finalize, so the full test can take a few minutes.

The ambiguous-outcome cases simulate a lost client response through a wrapper. The transactions themselves are real testnet transactions.

I recorded the original successful run in `NEAR_EVIDENCE.md`, section 8.

---

## 9. Optional demo run and evidence recording

For a fresh deployment, I can run the optional three-query demo:

```bash
python3 scripts/near_live_check.py run --store ./bbstore --contract $CONTRACT --writer $WRITER
```

I save the raw outputs from the relevant steps and add them to `NEAR_EVIDENCE.md` under **Real-network results**.

I distinguish between checks that ran locally and checks that actually ran against NEAR testnet. A local test does not count as a successful network deployment.

---

## Failure handling

| Symptom | What it means / what I do |
|---|---|
| `protocol_version < 88` | The network protocol is too old for the current near-sdk build. I stop and investigate compatibility. |
| `PrepareError` or `CompilationError` during deployment | The VM rejected the WASM. I record the exact error and preflight output. |
| Balance or storage-staking error | The contract account needs more testnet NEAR. I fund it before retrying the deployment stage. |
| Self-test write failure with a near-cli-rs exit code | I check signing, keychain access, account balance, and gas. If necessary, I run the printed CLI command manually or switch to `legacy-keychain`. |
| `NEAR unavailable` | The RPC could not be reached. I do not assume the transaction failed without checking the chain. |
| `INTEGRITY/CONFIG ERROR` | The on-chain head does not match the local store. I stop. Possible causes include using the wrong store, reinitializing state, or tampering. |
| `RETRY` from `run` | The write did not become final within the configured confirmation timeout, which defaults to 45 seconds. I read the chain again before deciding what to do. |

---

## Recovery and transaction rules

These rules are covered by `tests/test_near_anchor.py`, particularly `NeverBlindlyResubmitTests`.

I designed the adapter to broadcast a given transition only once.

A timeout, non-zero CLI exit, lost response, or other ambiguous result is not proof that a transaction failed. The adapter resolves the outcome by reading the contract head at `finality=final`. It does not blindly send the same transaction again.

A client retry of an identical request makes the Gate build a fresh transition from a fresh read. The contract accepts at most one transition from a set of transitions that share the same expected head.

The application releases an answer only after the chain shows that exact transition was committed, or when replaying an earlier committed request.

This matters because a transaction can land even when the client does not receive a successful response. Sending it again without checking the chain could create an inconsistent state.

---

## 10. Running the web application in live mode

The web application supports a NEAR-backed mode through:

```text
--anchor near
```

The live mode connects the application to a deployed contract and a local record store.

I keep the following distinction clear:

- The contract stores the current state head: version and digest, along with scope, policy, and writer metadata.
- The full gate state and mock credential remain off-chain.
- The server signs authorized updates using the configured writer account.
- Visitors can read the public chain state, but they cannot submit authorized writes.
- The application checks the chain commit before releasing an answer.
- The adapter checks the correspondence between the local record and the on-chain digest. The contract itself does not inspect the full off-chain record.

The demo uses a separate contract and store. I do not run the public demo against the original evidence deployment because every question or refusal advances the shared state.

### Existing demo deployment

I deployed the public demo using:

| Item | Value |
|---|---|
| Network | NEAR testnet |
| Contract | `bbdemo-teedor.testnet` |
| Writer | `teedor.testnet` |
| Local store | `bbstore-demo` |
| CLI version | `near-cli-rs 0.30.1` |

The demo deployment is separate from `bbanchor-teedor.testnet` and `bbstore`.

I verified the deployed demo contract and used it for a live browser session. The session committed ten transitions and ended at chain version 10.

The final on-chain head was:

```text
version: 10
digest: 841dffaa119725f99eac09412bbd1be0f5488aad3af26617b073377b4973b1c6
```

The final state had 15,625 candidates in the interval `[78,126, 93,750]`. The final request was refused because an informative answer would violate the configured floor of 10,000 candidates.

The persisted records were reconstructed and checked for consecutive versions, digest consistency, previous-digest links, constant scope and policy, and agreement with the reported final chain head. The original in-memory request log and timestamps were not recoverable from the persisted records.

The demo uses a mock credential and an unencrypted test sealer. It is a testnet prototype, not a production confidentiality system.

### Guarded staged deployment procedure

I use `scripts/deploy_demo.py` for a fresh demo deployment. The script was designed to protect the original evidence deployment and store.

It checks the WASM hash before sending anything, runs near-cli-rs through a Python argument list, sends at most one transaction per stage, treats the chain as authoritative after an ambiguous outcome, and does not retry automatically.

It does not create, read, or overwrite `init.json`.

The required contract balance is approximately 1.05 NEAR. The script requires 1.10 NEAR to allow for storage for the 102,890-byte WASM, a 100 TGas allowance, contract state, and a safety margin.

**The following commands are for a fresh deployment only. They are not instructions to redeploy the existing `bbdemo-teedor.testnet` contract.**

Run them from the project root, in order.

First, inspect the plan and CLI syntax:

```powershell
py .\scripts\deploy_demo.py plan
py .\scripts\deploy_demo.py syntax
```

Prepare a fresh scope and store:

```powershell
py .\scripts\deploy_demo.py prepare
```

The script refuses to proceed if `.\bbstore-demo` already contains data.

Inspect the account-creation command:

```powershell
py .\scripts\deploy_demo.py create-account
```

Execute account creation only after confirming the target account:

```powershell
py .\scripts\deploy_demo.py create-account --execute --confirm bbdemo-teedor.testnet
```

Check the deployment preconditions:

```powershell
py .\scripts\deploy_demo.py deploy
```

Execute the deployment only after confirming the target account:

```powershell
py .\scripts\deploy_demo.py deploy --execute --confirm bbdemo-teedor.testnet
```

Then verify the deployment:

```powershell
py .\scripts\deploy_demo.py verify
```

Inspect the current chain state and attempt journal:

```powershell
py .\scripts\deploy_demo.py inspect
```

I can also perform an independent read-only check:

```powershell
py .\scripts\chain_head.py --contract bbdemo-teedor.testnet
```

### Stop rules

The script uses these exit codes:

| Exit code | Meaning |
|---|---|
| `0` | The stage completed. |
| `1` | The stage was refused. Nothing was sent. |
| `2` | The result is ambiguous. I stop and inspect the chain before doing anything else. |

I do not run `near_live_check.py selftest` against the public demo contract because the self-test advances the demo state and consumes its disclosure budget.

I only start the browser demo after the deployment verification passes.

After using the application, I compare its displayed chain version with the independent read:

```powershell
py .\scripts\chain_head.py --contract bbdemo-teedor.testnet
```

I can also check the expected version through:

```powershell
py .\scripts\deploy_demo.py verify --expect-version N
```

Here, `N` is the version I expect to see.

---

## 11. Handling ambiguous deployment results

I added these safeguards after an account-creation attempt timed out.

The CLI output is captured as bytes and decoded safely using UTF-8, the system encoding, and then Latin-1. The script prints the output in ASCII-safe form and withholds key-material lines. Raw CLI output is not written to disk. If a timeout occurs, the partial output is displayed.

A timeout, non-zero exit, crash, or unexpected error is never treated as proof that the operation failed.

The script checks the chain:

- If the account or contract exists, the operation is treated as completed.
- If the result cannot be established, the script returns exit code `2` and stops.

Before sending a transaction, the script records the attempt in:

```text
<store>/attempts_demo.json
```

If an earlier attempt of the same stage remains unresolved, the script refuses another execution unless I explicitly acknowledge the ambiguous attempt.

Even with that acknowledgement, the script checks the chain first. If the account already exists, it will not send another faucet request.

Attempts confirmed as unsent because the binary could not start, and attempts confirmed by the chain, do not block future stages.

If an attempt was made using an older version of the script and has no journal entry, I can record it offline:

```powershell
py .\scripts\deploy_demo.py note-prior-attempt --note "Describe the earlier attempt"
```

For a read-only inspection:

```powershell
py .\scripts\deploy_demo.py inspect
```

The demo contract can also be inspected on NEARBlocks:

https://testnet.nearblocks.io/address/bbdemo-teedor.testnet

### Faucet alternative

If the faucet repeatedly times out, near-cli-rs v0.30.1 also supports a faucet-free account-creation command:

```text
account create-account fund-myself <name> '<amount> NEAR' autogenerate-new-keypair save-to-keychain sign-as <funded account> network-config testnet sign-with-keychain send
```

This spends testnet NEAR from the signing account. I have not implemented or approved this alternative as part of the deployment script. I would make that decision separately before using it.

---

## Final deployment limitations

The current deployment is a NEAR testnet prototype.

The on-chain contract stores a state head and associated metadata. It does not store the secret or the full gate state. The demo sealer does not encrypt the state, and the credential is a mock.

The current implementation does not demonstrate:

- Production confidentiality.
- Encryption of the off-chain state.
- Rollback resistance.
- Attestation.
- Trustless execution.
- Protection against every possible fork or operator compromise.

I do not present the testnet deployment as proof of those properties. The evidence here is limited to the implementation, tests, transaction behavior, and state consistency checks described in this document and `NEAR_EVIDENCE.md`.