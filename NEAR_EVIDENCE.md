# NEAR_EVIDENCE.md

## 1. Evidence summary

I tested Bit Budget's NEAR anchor at several levels. These results are deliberately separated because passing a local model test is not the same as running against NEAR testnet.

| Test | Result |
|---|---|
| Rust contract unit tests | 11/11 passed on Rust 1.99.1 and 1.95.0 |
| Injected contract bugs | 12/12 caught |
| Compiled WASM in nearcore VM | 4/4 passed on both toolchains |
| near-cli-rs v0.30.1 command syntax | 10/10 parsed successfully |
| Python adapter tests | 44/44 passed against the contract model |
| Live-mode application tests | 22/22 passed against the model and fake transports |
| Live-mode injected bugs | 14/14 caught |
| Existing mutation checks | 19/19 engine and 17/17 application mutations caught |
| Original NEAR testnet deployment and self-test | 10/10 passed, owner-reported |
| Separate demo deployment | Deployed and used in a live browser session |

The GitHub Actions workflow has not been run. Its YAML was checked, and its steps were reproduced locally.

## 2. Build details

The contract uses near-sdk 5.30.0, which requires Rust 1.95.0 or newer and NEAR protocol version 88 or higher.

| Toolchain | WASM size | SHA-256 |
|---|---:|---|
| Rust 1.99.1 | 102,890 bytes | `1480a5e6b65f2e28bf5eb980f36d3f56725eacd7106a23dcb15828d30c90c2e7` |
| Rust 1.95.0 | 101,808 bytes | `cd0e352ce5479ba0a3fc61776d892775e7d12dc8887b31f70f8507711554c6df` |

The shipped WASM is the Rust 1.99.1 build. Both builds passed the contract tests and nearcore VM harness.

## 3. What I built

The NEAR integration consists of:

- `NearAnchor`, the Python adapter connecting the Gate to the contract.
- A read-only NEAR JSON-RPC client.
- A signer wrapper using near-cli-rs.
- A local record store for the off-chain state.
- A Rust contract that maintains the current version and digest, with single-writer and compare-and-swap checks.
- A live-mode web application with public chain information and an operator-controlled session.

The contract does not store the secret or full gate state. The local store contains the sealed state, but the test sealer does not encrypt it. The chain exposes public metadata, including verifier identifiers and committed request information.

The adapter checks the relationship between local records and the chain head. The contract does not independently inspect the off-chain records.

## 4. Original NEAR testnet deployment

<badge color="success">10/10 self-test checks passed</badge>

I deployed the original evidence contract to NEAR testnet:

| Item | Value |
|---|---|
| Contract | `bbanchor-teedor.testnet` |
| Writer | `teedor.testnet` |
| Unauthorized test account | `bbother-teedor.testnet` |
| Network | NEAR testnet |
| CLI | near-cli-rs 0.30.1 |
| Deployment transaction | `272ozirtwaNL5JHpAiYF2rmgP4PQ9weuHJqiSQdM85i8` |

The deployment, initialization, reads, and self-test were reported by me after running them on my machine. Raw command transcripts were not archived.

The self-test covered:

- Successful writes and version advancement.
- Rejection of a stale compare-and-swap.
- Rejection of an unauthorized signer.
- A simulated lost response where the adapter re-read the chain before releasing the answer.
- A failed write where no answer was released.

The final chain version was 3, with digest:

`b402ae92e5a631bbf0556fe4ece6ad88b1b94b3dba143c2a018c8db90fb9bd36`

The transaction can be inspected on a NEAR testnet explorer. A current read may show a later version if additional transitions were committed.

## 5. Live application tests

The live-mode application was initially tested against a Python contract model, fake transports, and a temporary store. These tests did not contact NEAR or sign transactions.

They covered:

- One shared accounting domain and one live session.
- One Gate round per API request.
- No blind retries.
- Answer release only after commit confirmation.
- Recovery from late transactions and stale writes.
- RPC and integrity failures.
- Refusal to start with inconsistent configuration.
- Public chain information without exposing the operator token or local state.

Fourteen injected bugs were caught by the application tests.

The application has since been used in a separate live NEAR testnet demo. That browser session is separate from the model-based test results above.

## 6. Separate demo deployment

The public demo uses its own contract and store:

| Item | Value |
|---|---|
| Contract | `bbdemo-teedor.testnet` |
| Writer | `teedor.testnet` |
| Store | `bbstore-demo` |
| Network | NEAR testnet |

The live browser session committed ten transitions across three verifiers:

| Result | Count |
|---|---:|
| Total requests | 10 |
| Informative answers | 6 |
| Determined answers | 3 |
| Refusals | 1 |

The final interval was `[78,126, 93,750]`, containing 15,625 possible values. The last request was refused because an informative answer would violate the 10,000-candidate floor.

The session ended at chain version 10:

`841dffaa119725f99eac09412bbd1be0f5488aad3af26617b073377b4973b1c6`

I reconstructed the persisted transition records and checked their version sequence, digest links, scope, policy, and final head. The original in-memory request log and timestamps were not recoverable.

The demo contract is separate from the original evidence deployment. I do not use the original evidence store for public demo requests.

## 7. OutLayer status

I investigated the six OutLayer conditions listed in `IMPLEMENTATION_PLAN.md`.

| Requirement | Current finding |
|---|---|
| Testnet execution | Documented, not verified |
| Running our own WASM | Requires a Rust port of the Python Gate |
| Independently verifiable attestation | TDX verification is documented; testnet worker support is unverified |
| Persistent state and freshness | Durability is documented; rollback/freshness guarantees are not |
| Atomic operations | SDK operations are documented, not verified |
| $0 execution | NEAR anchor path used faucet-funded testnet accounts; OutLayer costs remain unchecked |

I have not started the OutLayer implementation. The NEAR anchor does not depend on it.

## 8. What this evidence does not prove

I do not claim that Bit Budget is production-ready or that the current deployment provides:

- Encryption or production confidentiality.
- Rollback resistance.
- Attested or trustless execution.
- Protection against every fork, concurrency issue, or network failure.
- Timing or side-channel resistance.
- Payments or OutLayer execution.

The deployed contract is an on-chain anchor for a version and digest. It is not the complete privacy system.

The writer is trusted to commit honest digests because the contract cannot compare them with the off-chain records. Visitors can read the chain, but authorized writes are signed by the operator's account on the operator's machine.

The testnet results demonstrate the specific deployment, transaction, and state-consistency behavior described above. They should not be treated as evidence for properties that have not been tested.