# FEASIBILITY.md  (Phase A go/no-go, 2026-10-26; checkpoint Nov 3, 2026)

Sandbox note: my execution environment cannot reach NEAR/OutLayer domains (egress allowlist), so **nothing below was executed against real infrastructure**. Findings are from official-looking documentation excerpts only.

| Question | Finding | Verdict |
|---|---|---|
| Can we run our own stateful code with TEE attestation? | **NEAR AI Cloud:** docs I found cover attested *inference* (Intel TDX + NVIDIA confidential GPU); no evidence of custom stateful services. **OutLayer** (docs.near.org/primitives/off-chain-compute/outlayer): Rust to WASM runs in an Intel TDX enclave; returns result with attestation of code hash, input hash, output; has persistent encrypted storage with atomic ops incl. `set_if_equals` (compare-and-swap). | OutLayer plausible; **unproven by test**. |
| Worker identity / code measurement | Workers register on NEAR with TDX quote; MRTD + RTMR0-3 measurements; WASM hash bound into attestation. | Documented. |
| Rollback protection of OutLayer storage | Docs say storage is encrypted by the keystore TEE. **Encryption is not freshness.** No rollback/fork guarantee found. | **Assume operator can roll back.** Needs on-chain anchor. |
| Can a contract enforce freshness before release? | Proposed: NEAR contract stores `(seq, head)`, passes it as input via yield/resume, enclave refuses on mismatch, contract does CAS in the callback and only then exposes the (encrypted) answer. | Design only; **not tested**. |
| Is it $0? | OutLayer on NEAR is paid in NEAR tokens; testnet (`outlayer.testnet`, `worker.outlayer.testnet`) is documented. Whether testnet NEAR from a faucet is free and whether testnet workers give *real* TDX attestation: **unverified**. | **Open: user must check pricing/faucet terms first.** |
| NEAR Intents payment | Official quickstart states **there is no testnet**; test swaps use real tokens (a third-party page cites ~$0.10 minimum; 0.2% fee without JWT). | **Violates $0 rule. Payment = labeled simulation only, disabled by default.** |

## Update 2026-11-05
Docs re-read; see NEAR_EVIDENCE.md for E1-E6 and what was built. Update 2026-11-07: the anchor contract now compiles and runs in the nearcore VM crate (Rust 1.99.1 and 1.95.0); near-sdk 5.30.0 needs Rust >= 1.95 and protocol >= 88. Update 2026-11-08: the anchor contract was deployed to NEAR testnet and its live self-test passed 10/10 (owner-reported; NEAR_EVIDENCE.md section 8). OutLayer (E1-E6) is still unverified and not started.

## Hardest unresolved assumption
That OutLayer lets us (1) pin our own WASM hash, (2) read contract-supplied `(seq, head)` as trusted input, and (3) get an attestation a third party can verify, **on testnet, at $0**. If (3) fails, the project must ship as a clearly labeled simulation of attestation and say so.

## Nov 3 pass/fail
PASS = a testnet OutLayer execution of our WASM returns an attestation we verify independently, and a stale-head request is refused by the enclave. FAIL = either is not demonstrable; then ship the core only as a clearly labeled local simulation, or switch to the backup idea (decision for the human; see SECURITY_SPEC section 15).
