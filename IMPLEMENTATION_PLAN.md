# IMPLEMENTATION_PLAN.md  (status after Phase 4A-4D and the hardening pass; spec v0.4)

Standard library only, $0. **Phase 4E (authorized 2026-11-05): stage 1 (NEAR contract anchor) built; contract compiled and tested with a real Rust toolchain and run in the nearcore VM crate (2026-11-07); deployed to NEAR testnet and live self-test passed 10/10 (owner-reported, 2026-11-08); OutLayer (WASM gate) not started; web app has an optional live NEAR mode (`--anchor near`) implemented 2026-11-08 and tested only against the contract model, never run on testnet. See NEAR_EVIDENCE.md.**
Parameters: `D=[0,999999]`, `W=10000`. **K** = per-verifier maximum INFORMATIVE answers (fairness only), **R** = per-verifier maximum committed transitions (resource control only); both `None` (disabled) in the demo.

| Phase | Status | Files |
|---|---|---|
| P0 quarantine | done | `prototype/` + `README_PROTOTYPE.md` (unreviewed, not reused) |
| 4A pure policy + reference model | done | `core/policy.py` (101 lines; stdlib dataclasses/enum/typing only), `tests/reference_model.py`, `tests/test_policy.py`, `tests/test_reference.py` |
| 4B local state machine | done | `core/interfaces.py`, `core/records.py`, `core/gate.py`, `testdoubles/local_anchor.py` (fault injection), `testdoubles/test_sealer.py` (NON-cryptographic), `testdoubles/hmac_auth.py`, `testdoubles/mock_credential.py`, `tests/test_state.py` |
| 4C attack harness | done | `harness/attackers.py`, `harness/system.py`, `harness/audit.py`, `tests/test_attacks.py`, `tests/test_metadata.py`, `demo.py` |
| 4D claims verification + hardening | done | `harness/client_policy.py`, `tests/test_client_policy.py`; code changes: `core/records.py` (`MIN_BLINDING_BYTES`, blinding/tag excluded from `repr`), `core/gate.py` (blinding length check); `HARDENING_REPORT.md`;  `claims_check.py`, `tests/test_limitations.py`, mutation runner, `CLAIMS_MATRIX.md` |
| application vertical slice | done | `app/service.py`, `app/server.py`, `web/index.html`, `web/app.js`, `web/style.css`, `tests/test_app.py`, `APPLICATION.md` |
| 4E stage 1: NEAR contract anchor | **done on testnet** (owner-reported): contract deployed, self-test 10/10; also verified locally (Rust 1.99.1 and 1.95.0, nearcore VM crate) | `integrations/` (adapter, RPC client, record store), `contracts/anchor/` (Rust contract, 11 unit tests, `vmtest/`, `dist/`), `scripts/near_live_check.py`, `scripts/check_cli_syntax.py`, `tests/test_near_anchor.py` (against a Python model), `.github/workflows/contract.yml` (never run on GitHub), `NEAR_DEPLOY.md` (executed once by the owner), T-L01/T-L03 boundary tests |
| 4F web app live NEAR mode | **implemented; model-based tests only (22 cases, 14/14 injected bugs caught); NOT run on testnet** | `app/near_mode.py` (the only `app/` module that imports `integrations/`; loaded lazily), hooks in `app/service.py` and `app/server.py` (`--anchor near`, `/api/mode`, `/api/chain`), `web/` live banner + chain panel + operator-token form, `scripts/chain_head.py`, `tests/test_near_app.py`, `tests/e2e_fake_dom_near.js`. One fixed session, one accounting domain, loopback only |
| 4G separate demo contract `bbdemo-teedor.testnet` (fresh scope, fresh store `bbstore-demo`, independent budget) | **plan approved 2026-11-08; guarded staged script and tests ready; first `create-account` attempt (2026-11-09) was ambiguous, account NOT created per the chain (owner-reported); script defects found and fixed (checkpoint 10); NOT retried** (the evidence deployment and `bbstore` stay untouched) | `scripts/deploy_demo.py` (plan, syntax, prepare, create-account, deploy, verify; one transaction per stage; never retries), `tests/test_deploy_demo.py` (45 cases, 37/37 injected bugs caught; includes real-process decoding/timeout cases), commands in NEAR_DEPLOY.md |
| 4E stage 2: OutLayer (gate as WASM) | **not started** | needs a Rust port of `core/`; entry conditions E1-E6 in NEAR_EVIDENCE.md |

Security-relevant code to inspect: `core/policy.py` (101), `core/gate.py` (105), `core/records.py` (139), `core/interfaces.py` (42), `testdoubles/local_anchor.py` (100).

## Deviations from the earlier plan and spec
1. No mailbox: the last response lives in the sealed per-verifier state and is replayed from it (spec v0.3 already reflects this).
2. Mock credential has no issuer tag; it is `(random scope id, value)`.
3. Quota `R` makes further requests REJECTED without commit (spec v0.3), instead of a committed refusal.
4. T-S14 became a transition-binding audit; T-S17..S19, T-M07, T-MUT11/12 added; T-X03 samples thresholds (depth 3 over 9 thresholds, depth 2 over all 17) and T-X05 compares sets only on a scaled domain.
5. `advantage_bits` is computed only in `demo.py` for display; no decision uses floats.

## Drift decisions (hardening pass; details in HARDENING_REPORT.md section 4)
| Deviation | Decision | Result |
|---|---|---|
| Quota R REJECTED without commit | amend spec (done in v0.3) + explicit limitation | spec section 5/6/16; indistinguishable from stale/auth rejection (T-H03, T-H10) |
| No mailbox; response stored in sealed state | amend spec + explicit limitation | recoverable only via a live Gate, latest request per verifier |
| Mock credential without issuer tag | explicit limitation | authenticity not enforced or claimed (A3, C-19) |
| S15/S16 did not catch MUT05 | tests brought into line | S15 strengthened; S20, S21, S22 added; S16 not cited as evidence |
| Depth-3 indistinguishability not exhaustive | tests brought into line to depth 3; remaining scope documented | T-X03: all sequences of length 1-3 over all 17 thresholds; length ≥ 4 not covered |

## Entry conditions for 4E (all must be verified experimentally; itemised as E1-E6 with evidence in NEAR_EVIDENCE.md; none verified yet; the contract anchor itself does not depend on them)
OutLayer testnet execution available; runs our own WASM; attestation independently verifiable for the code we claim; persistent state and atomic operations behave as specified; all of it within the $0 budget with no paid API, compute, card, trial, or real-token transaction. If any step costs money, ship the local implementation and label the integration unverified. The core policy engine must not be modified to fit infrastructure assumptions.
