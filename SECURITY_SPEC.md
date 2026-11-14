# SECURITY_SPEC.md

**Bit Budget | Specification v0.4 | October 27, 2026**

This specification defines the local policy and state-transition model. The implementation uses only the Python standard library and costs $0. No NEAR, OutLayer, network, database, LLM, payments, or real credential protocol is involved in this phase.

All monetary examples use whole US dollars. IDs are shared with `IMPLEMENTATION_PLAN.md`, `TEST_PLAN.md`, and `CLAIMS_MATRIX.md`.

## 1. Model and guarantee

The secret is an integer \(v\) in the public domain:

- \(D = [0, 999999]\)
- \(N = 1,000,000\)
- Privacy floor \(W = 10,000\)

Verifiers ask exact threshold questions: **is \(v > t\)?**

Bit Budget maintains a feasible interval \(I=[a,b]\) containing every value consistent with the answers released so far. Its size is \(b-a+1\).

One credential represents one accounting domain, identified by a random 128-bit `scope_id`. The ID is not derived from the secret.

The policy guarantee is that the feasible interval never falls below 10,000 possible values after an answer is released.

## 2. State and trust boundaries

The system has three boundaries: Verifier, Gate, and Anchor.

The Anchor is the authoritative source of state. The Gate reads and processes that state for each request, but its working copy is never authoritative after the request completes. Following a crash or restart, it must recover from the Anchor rather than trust remembered state.

The secret is held by the Gate and provisioned out of band. It must never appear in records, digests, commitments, responses, or logs.

The local Anchor and sealer are test doubles. They do not provide real cryptographic confidentiality, rollback resistance, finality, or availability.

## 3. Adversary and assumptions

The threat model includes colluding adaptive verifiers, dropped or delayed messages, duplicate and reordered requests, stale reads, and unavailable storage or RPC services.

The model assumes:

- A uniform public prior only for the stated guessing-advantage calculation.
- The adversary knows the public domain, policy, and observable transcript.
- The credential is honest, although the current credential is a mock.
- The Anchor provides linearizable compare-and-swap, accepts writes only from the authorized writer, and never reverts committed versions.
- The Gate follows this specification and the underlying primitives are sound.
- One credential is used per person, attribute, and epoch.
- There are no side channels.

The no-reversion assumption is important: **compare-and-swap alone does not provide rollback resistance.**

## 4. Privacy metric

The transcript includes each processed request's verifier ID, nonce, request digest, response class, released response, and observable Anchor metadata.

Under the uniform-prior assumption and the policy invariant, the posterior is uniform over the feasible interval. The min-entropy guessing advantage is:

\[
Adv(T)=\log_2(N/|I|)
\]

Since \(|I|\geq W\):

\[
Adv \leq \log_2(1,000,000/10,000)
=\log_2(100)\approx 6.64\text{ bits}
\]

This is a bound under the stated metric and assumptions. It is not Shannon-entropy loss or differential privacy.

## 5. Decision policy

The policy is `(lo, hi, W, K, R)`. All security decisions use integers, never floating-point values.

`K` optionally limits the number of informative answers per verifier. It is a fairness control, not a privacy guarantee.

`R` optionally limits the number of committed transitions per verifier. It controls resource use, particularly Anchor writes.

Both caps can be disabled. The global feasible-set floor remains the actual privacy guarantee.

For a query threshold `t`, the Gate calculates:

- YES interval: `[max(a, t+1), b]`, if possible.
- NO interval: `[a, min(b, t)]`, if possible.

The decision order is:

1. If one branch is impossible, return `DETERMINED` with the forced answer.
2. If either possible branch contains fewer than `W` values, return `REFUSED`.
3. If the verifier has reached its informative-answer cap `K`, return `REFUSED`.
4. Otherwise, return `INFORMATIVE` and answer using the secret.

If the request quota `R` is exhausted, the request is `REJECTED` without a state transition.

The floor is checked before the allocation cap. Neither cap can permit an answer that the floor would refuse.

A determined answer does not narrow the interval. It is already implied by the previous answers.

## 6. Request and state transitions

A request contains:

`(scope_id, verifier_id, nonce, threshold, policy_digest, blinding, auth_tag)`

The request digest is SHA-256 over a domain-separated, length-prefixed encoding of the request fields, including the blinding value.

Each verifier supplies a random 32-byte blinding value. The Gate checks only that its length is at least 32 bytes. It cannot verify that the value is actually random, secret, or high-entropy.

The blinding matters because the threshold has only one million possible values. Without a secret, high-entropy blinding value, an Anchor observer can enumerate possible thresholds from the request digest.

The authentication tag authenticates the digest. The local implementation uses HMAC as a test double; real signatures are deferred.

The authoritative state contains the scope and policy, feasible interval, and per-verifier nonce, request digest, counters, last response, and other request-binding state.

Each accepted request produces a new state record and an Anchor transition. The Anchor stores public headers including the scope, version, previous record digest, verifier ID, nonce, request digest, status commitment, policy digest, and sealed-state length.

The threshold, answer, decision, interval, and counters are not stored as plaintext fields.

The status commitment binds the decision using a random blinding value kept in the sealed state. Its confidentiality is not demonstrated by the local test sealer.

### Request outcomes

| Situation | Outcome | Commit? |
|---|---|---|
| Informative answer | `ANSWER(bool)` | Yes |
| Determined answer | `ANSWER(bool)` | Yes |
| Floor or allocation refusal | `REFUSED` | Yes |
| Quota exhausted | `REJECTED` | No |
| Invalid authentication, scope, policy, verifier, or blinding | `REJECTED` | No |
| Invalid nonce or conflicting duplicate | `REJECTED` | No |
| Exact duplicate of a committed request | Replay recorded response | No new commit |
| Concurrent transition | `RETRY` | No |
| Anchor unavailable | `RETRY` | No |
| Unresolved transaction outcome | `RETRY` | No |

Refusals and determined answers commit too. This makes accepted requests follow the same transition pattern and binds the nonce, request digest, and response. It also prevents a verifier from reusing the same nonce with different request content.

A refusal does not change the feasible interval or informative-answer count. It updates the requesting verifier's request state.

**No answer is released before its corresponding transition is confirmed committed.**

### Ambiguous outcomes and recovery

The Gate must never blindly repeat a compare-and-swap after an unknown outcome.

It rereads the Anchor. If the expected next version exists and its digest matches the proposed record, the transition committed and the response can be released. Otherwise, or if the reread fails, the Gate returns `RETRY` and releases nothing.

A verifier retries the exact same request. If it was already committed, the Gate returns the recorded response as a replay.

After a crash before commit, the request can be processed normally. After a crash following commit, the same request is resolved through replay.

## 7. Invariants

The implementation and test plan use these central invariants:

- **Floor:** Every released answer leaves at least `W` feasible values.
- **Decision purity:** Decisions depend only on policy, interval, threshold, and transcript-derived counters.
- **Transcript consistency:** Every value remaining in the final feasible interval produces the same transcript under the specified model.
- **Linear history:** Each committed version follows the immediately preceding committed state, conditional on the Anchor's no-reversion assumption.
- **Release after commit:** No uncommitted answer is released.
- **Idempotency:** The same nonce and request replay the committed response; different content with the same nonce is rejected.
- **Fail-closed:** Anchor errors, conflicts, and unresolved outcomes release nothing.
- **Response uniformity:** Floor and cap refusals are byte-identical. No internal refusal reason is exposed.
- **Domain binding:** Requests and state are bound to the scope and policy.
- **Layer separation and allocation monotonicity:** The policy engine remains independent of infrastructure, and optional caps can only restrict access.

## 8. Anchor properties

The Anchor exposes `read()` and `compare_and_swap(...)`.

The local `LocalTestAnchor` supports fault injection. It is a test double, not evidence of production infrastructure guarantees.

| Property | Source or limitation |
|---|---|
| Atomicity | Anchor compare-and-swap |
| Authorization | Writer-key check and verifier authentication |
| Integrity | Gate transition logic and previous-digest linkage |
| Freshness | Latest-state reads and stale-proposal rejection |
| Rollback resistance | Not provided by CAS; requires an Anchor that never reverts committed state |
| Finality | Depends on the real Anchor; not provided by CAS |
| Confidentiality | Requires a real sealer and secure key custody; not demonstrated locally |
| Availability | Not guaranteed; the system fails closed |

Real authenticated encryption, signatures, key management, and attestation remain integration work. No custom cryptography is implemented.

## 9. Failure and credential lifecycle

Anchor errors, conflicts, and unresolved outcomes return `RETRY` without advancing state or releasing an answer. A configuration mismatch causes the Gate to stop without answering.

A stale read may cause a valid request to be rejected or retried, but it must not cause an uncommitted answer to be released.

The current credential is a mock `(scope_id, value)`. There is no issuer protocol or real credential verification.

Reissuing a credential for the same person and attribute creates a new accounting domain and may reset the budget. There is no stable subject identifier or continuity mechanism.

## 10. Observable metadata

An Anchor observer can see accepted activity, timing, writer, version, verifier ID, nonce, request digest, status commitment, and fixed record size.

The observer cannot read the response, threshold, decision, interval, or counters from the defined plaintext fields.

Timing, verifier identity, request counts, activity, and the distinction between accepted and rejected requests remain observable.

The threshold is not stored in plaintext on the Anchor. That does not protect it from the Gate, verifier, transport, timing, or side channels.

Even an observer who learns every decision remains subject to the feasible-set floor under the stated model.

## 11. Guarantees and limitations

The model aims to establish the listed invariants under its assumptions. Under the uniform-prior assumption and the specified min-entropy metric, the guessing-advantage bound is approximately 6.64 bits.

It does not provide differential privacy, protection against non-uniform priors or side information, protection against correlated attributes, timing or side-channel protection, a compromised Gate defense, rollback resistance, finality, confidentiality, attestation, availability, reissuance continuity, Sybil resistance, real credential verification, or payments.

The fixed admitted verifier set is assumed at genesis. There is no registration mechanism.

## 12. Hardening decisions

The hardening pass locked these decisions:

- Requests travel off-chain. Thresholds are not plaintext Anchor fields.
- Verifiers use sequential nonces. Failed authentication and nonce checks do not commit.
- The admitted verifier set is fixed at genesis.
- `K` and `R` are optional integer caps. The floor remains the guarantee.
- No custom cryptography. Local authentication and sealing are test doubles.
- Anchor properties are treated separately. Unknown transaction outcomes are resolved by rereading.
- NEAR and OutLayer integration remains blocked until the required integration checks are experimentally verified.
- Permanent locks caused by sealing-key loss or floor exhaustion are accepted.
- The domain is fixed at `[0, 999999]`, with a floor of `10,000`.
- The earlier prototype remains quarantined in `prototype/`.

## 13. Stale reads and client behavior

The verifier sees only four response classes: `ANSWER(bool)`, `REFUSED`, `REJECTED`, and `RETRY`.

`REJECTED` deliberately combines authentication failures, invalid verifiers, wrong scope or policy, invalid blinding length, nonce errors, conflicting duplicates, quota exhaustion, and some stale-read cases.

`RETRY` covers conflicts, unavailable Anchors, and unresolved transaction outcomes.

A stale read can make a valid higher nonce appear invalid. It can also replay an older committed response. That replay is information-neutral because it returns the response already committed for that exact request.

The client policy is:

1. Only `ANSWER` and `REFUSED` count as success.
2. While a request is unresolved, send no new request and do not guess or skip a nonce.
3. On `RETRY`, resend the exact same request, within a bounded retry limit.
4. On `REJECTED`, consult authoritative public history where available before deciding whether to retry, resynchronize, or report a permanent conflict.
5. With incomplete history, do not assume a nonce was unused or abandon a pending request without evidence.
6. The Gate remains unchanged: strict sequential nonces and no answer without commit.

A proposed `confirm_head(version, digest)` Anchor operation could distinguish stale-induced nonce rejection from a rejection confirmed against the current head. This change is **not implemented** and depends on an unverified Anchor capability.

## 14. Blinding audit

The verifier generates a fresh 32-byte random blinding value per request. It is sent to the Gate off-chain and is not stored in the sealed state, Anchor record, or response. The Gate uses it to recompute the digest and authenticate the request.

Anyone with the request fields and blinding can verify the digest. An Anchor observer can enumerate threshold guesses if the blinding is weak, public, or leaked.

A public salt does not prevent this attack. Reusing a secret blinding value is safe only while it remains secret; if exposed, every digest made with it becomes enumerable. Fresh values limit the impact of a leak.

The privacy floor does not depend on blinding. Weak blinding affects the confidentiality of that request's threshold against an Anchor observer, not the interval guarantee.

The status commitment similarly hides the decision only while its blinding value remains sealed. The local sealer is not cryptographic, so this hiding has not been demonstrated locally.

## 15. Additional limitations and evidence boundaries

There is no response mailbox. A response can only be recovered by replay through a live Gate, and only for the verifier's latest committed request. If the Gate is unavailable or a newer request has committed, an older response may be unrecoverable.

Quota exhaustion rejects without committing. The verifier cannot distinguish that from certain stale or invalid request rejections.

The mock credential has no issuer tag. Authenticity of the secret value is assumed, not enforced.

Transcript indistinguishability was exhaustively tested only for sequences of length 1–3 on a small domain `[0,15]`, with floor `2` and two alternating verifiers. Longer sequences and larger domains rely on the invariant argument and scaled-domain replay tests.

The hardening tests also establish that some random-traffic tests do not detect floor weakening when caps are enabled. The specific tests identified in `HARDENING_REPORT.md` are needed for that check.

**The boundary is deliberate:** this specification defines and tests a local policy and transition model. It does not claim that the deferred infrastructure, cryptographic, credential, or deployment properties have already been delivered.