# HARDENING_REPORT.md  (bounded Phase 4D hardening pass; spec v0.4)

No NEAR/OutLayer work, no dependencies, no paid services, no cryptographic implementations, no broad refactors. Code changes were limited to: `core/records.py` (blinding length constant; `blinding` and `auth_tag` excluded from `repr`), `core/gate.py` (blinding length check), new `harness/client_policy.py`. Everything else is tests, `claims_check.py` and documents.

## 1. Stale anchor reads
**Policy (implemented, SECURITY_SPEC section 14):** only a released `ANSWER`/`REFUSED` is success; resend the *same* request (same nonce and blinding) so idempotency applies; never skip or reuse a nonce on a guess; on `REJECTED` consult authoritative public headers: exact request committed → retry (it replays); nonce held by a different committed request → `CONFLICT` (no retry); complete history shows a wrong nonce → `INVALID_NONCE` (no retry); otherwise bounded retries then `UNRESOLVED` with the request kept pending; abandon only on complete public evidence of non-commit; unknown commit outcomes are resolved by the Gate rereading the anchor, never by a blind second CAS.
**What the verifier can observe (T-H10):** `REJECTED` is one byte-identical class for bad tag, unadmitted id, lower/higher nonce, conflicting duplicate, short blinding, quota exhausted and stale-induced rejection; `RETRY` is one class for CAS conflict, unavailable anchor and unresolved UNKNOWN. With a public append-only anchor history (unverified for real anchors) it can also read `(verifier_id, nonce, request_digest)` of committed transitions.
**Limitation, stated plainly:** the current format cannot separate a stale-induced `REJECTED` from an auth, scope, quota or genuine nonce rejection, and the Gate cannot know whether its read was stale. One retry does not solve this; ambiguous cases end `UNRESOLVED`.
**Smallest safe protocol change (proposed, not implemented):** `Anchor.confirm_head(version, digest)`; the Gate classifies a nonce mismatch as `REJECTED` only if the head is confirmed current, else `RETRY`. Unverified on any real infrastructure.
**Safety properties checked on every H test** by `CheckedGate`: no response is released unless the exact request is committed on the public history. A stale read can also replay an older committed request; this is information-neutral (T-H07) and differs from what a fresh read would return (`REJECTED`).

## 2. Mutation 5: the invariant and the test gap
**Mutation 5:** the floor check runs only when `K` is `None` (`if policy.K is None and (...)`). **Invariants violated:** INV-1 (floor) whenever `K` is set, and INV-11 (caps may only add refusals; here enabling a cap *removes* a refusal).
**Why T-S15/T-S16 missed it:** T-S15 used thresholds far from the floor and K=2; T-S16 used random thresholds with K ≤ 3, which essentially never reach the floor region (about seven well-aimed halvings are needed). Neither ever aimed at the floor with caps enabled. X01 covered only `K`, never `R`, so it misses the `R` variant (MUT14).
**Fixes and the distinct failure mode of each test:**
| Test | Failure mode it catches |
|---|---|
| T-P08 (existing) | A few fixed policy-level points with K set |
| T-X01 (existing) | Divergence from the independent set model for a sparse K grid (not R) |
| T-S15 (strengthened) | One end-to-end scenario: after caps bind, floor-violating thresholds (5,000-value branch) must still be refused |
| T-S20 (new) | **Exhaustive differential**: for 12 cap variants and >400,000 (interval, t, count) cases, no cap configuration may make any decision more permissive than no caps |
| T-S21 (new) | **Gate-level edge battery under six (K,R) configurations**: floor disabled, bypassed or weakened only when caps are configured |
| T-S22 (new) | **Adaptive squeeze attackers** with generous caps, floor checked after every request |
| T-S16 (unchanged) | Random-traffic regression; **detects none of MUT05/13/14 and is not cited as evidence** |
**Kill matrix** (each test run alone; K = killed): MUT05: P08 K, X01 K, S15 K, S16 ., S20 K, S21 K, S22 K. MUT13 (floor halved when K set): same. MUT14 (floor bypassed when R set): P08 K, X01 ., S15 K, S16 ., S20 K, S21 K, S22 K.

## 3. Threshold commitment and blinding audit
Full trace and table: SECURITY_SPEC section 15. Findings:
- The **verifier** generates the 32-byte blinding; the Gate checks **length only** (it cannot check entropy or secrecy).
- It travels verifier → Gate off-chain; the Gate does not store, log (`repr` excludes it), return or publish it (T-M09). The Anchor sees only the digest and the status commitment.
- **Enumerating all 10^6 thresholds is prevented only by the blinding being secret and high-entropy.** A constant public blinding is accepted and the threshold is recovered from the header digest in about a second (T-M08 b). **A public salt does not prevent dictionary attacks.** Leak of a reused blinding exposes later thresholds under it (T-M08 c). The privacy floor is unaffected.
- **Claim revised (C-22):** the threshold is not stored in plaintext on the Anchor; an observer can recover it from the digest if the verifier's blinding is weak, public or leaked. No protection is claimed against a careless verifier, the Gate, transport, timing or side channels. Commitment hiding of `status_commitment` depends on `γ` staying sealed and is not demonstrated locally. Design option, not implemented: Gate-computed commitments under a Gate-held secret.

## 4. Specification drift
| Deviation | Decision | Action and effect on claims |
|---|---|---|
| Quota `R` rejects without committing | Amend spec (already in v0.3 sections 5-6) + explicit limitation | Spec, plan, tests (T-A08, T-S15, T-S18, MUT11) agree. A quota rejection is indistinguishable from stale/auth rejection (T-H03, T-H10). C-14 wording narrowed |
| No mailbox; last response in sealed per-verifier state | Amend spec + explicit limitation | Responses recoverable only through a live Gate for the latest committed request per verifier (spec section 16). No claim of anchor-delivered responses |
| Mock credential: random scope id and value, no issuer tag | Explicit limitation | Authenticity of the value is not enforced or claimed (A3, C-19). Older THREAT_MODEL text about an issuer tag is superseded |
| T-S15/T-S16 did not independently catch MUT05 | Bring tests into line | S15 strengthened, S20-S22 added, S16 explicitly not cited; C-14 evidence rewritten with the history stated |
| Indistinguishability tests not exhaustive to depth 3 | Bring tests into line, document the rest | T-X03 now covers all sequences of length 1-3 over all 17 thresholds (83,504 runs). Length ≥ 4, other verifier assignments, caps enabled, larger domains are **not** exhaustive; they rest on INV-3 and T-A09 |
The claims matrix was not loosened: C-14 and C-3 got narrower, scoped wording and C-21/C-22 were added with their limitations. `claims_check.py --docs` verifies that tests, claims and documents agree.

## 5. Evidence (all run on the final code)
| Command | Result |
|---|---|
| `python3 claims_check.py` | `Tests run: 138  failures: 0  errors: 0` (re-run 2026-11-07 after the NEAR adapter and contract stages; was 93 at hardening time); 14 claims SUPPORTED (locally), 5 NOT DEMONSTRATED (C-10, C-11, C-12, C-17, C-18) |
| `python3 claims_check.py --mutations` | 19 of 19 mutations KILLED (T-MUT01..T-MUT19), 0 survivors |
| `python3 claims_check.py --killmatrix` | table in section 2 |
| `python3 demo.py` | baseline recovers $83,250 in 20 queries; through the gate the attacker is refused at query 7 with 15,625 candidates (floor 10,000, advantage 6.00 bits ≤ 6.64); sweep of 147 attack runs over 49 secrets and 3 strategies: smallest candidate set reached 10,367 |
| `python3 claims_check.py --docs` | see the final run in the reply (consistency of tests, claims and documents) |
| New targeted tests | T-H01..T-H10, T-S15 (strengthened), T-S20, T-S21, T-S22, T-X03 (expanded), T-M08, T-M09: all pass in the full run |

## 6. What supports each guarantee
- **Mathematical reasoning:** INV-1 (induction); INV-2 (by construction); INV-3 and the guessing bound under a uniform prior (argument plus tiny-domain computation); not differentially private (deterministic exact answers); blinding secrecy is necessary (enumeration argument and positive controls).
- **Tested locally (against test doubles):** the floor on the production domain by boundary tests and adaptive attacks; decision purity; transcript indistinguishability to depth 3 on a tiny domain and by brute-force replay on a scaled domain; idempotency, nonces, crash/unknown/stale/conflict handling; response and record uniformity; cap monotonicity; client policy; layering and offline scan; 19 mutations.
- **Unverified:** rollback resistance, finality, confidentiality, commitment hiding, attestation, real-anchor behavior (including whether a public append-only history exists), NEAR/OutLayer and $0 viability, payments, timing and side channels, production-scale exhaustive indistinguishability, novelty beyond the narrow wording.

## 7. Remaining blockers and open decisions
1. Phase 4E was authorized on 2026-11-05 (U-7 lifted). Stage 1 (NEAR contract anchor) is built, verified locally, and was deployed to NEAR testnet where a live self-test passed 10/10 (owner-reported, 2026-11-08). See NEAR_EVIDENCE.md and NEAR_DEPLOY.md. OutLayer is not started.
2. Whether to adopt `confirm_head` (needs an anchor capability that may not exist) or accept `UNRESOLVED` for ambiguous rejections.
3. Whether the Gate, not the verifier, should compute the header commitment (needs key custody and a reviewed primitive).
4. Whether depth ≥ 4 exhaustive indistinguishability, or caps-enabled exhaustive indistinguishability, is worth the runtime.
5. Sealing, signatures and attestation remain deferred to the integration phase.
