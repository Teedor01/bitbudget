# THREAT_MODEL.md

**Bit Budget | Threat Model**

All examples use whole US dollars. USD is only the demo unit; the mechanism is unit-agnostic.

## Protected secret

Bit Budget protects one integer attribute \(v\) in the public range `[0, 999999]`.

The current implementation uses a mock credential containing a random `scope_id` and value. There is no real issuer protocol or income verification. The credential's authenticity is assumed, not established.

## Query model

Verifiers ask exact threshold questions:

**Is \(v > t\)?**

Answers are exact because the system is designed for decisions that require an exact threshold result. No noise is added.

## Security guarantee

The guarantee is that the set of values consistent with all released answers never becomes narrower than the configured floor. The demo uses a floor of 10,000 possible values.

This applies to the complete transcript, including decisions and refusals, under the specified model. It is not a claim that an individual verifier learns nothing from a refusal.

Under a uniform public prior, the feasible interval gives a min-entropy guessing-advantage bound of approximately 6.64 bits. This is not differential privacy.

No guarantee is claimed under non-uniform priors, side information, correlated attributes, or side channels.

## Adversary assumptions

The threat model includes:

- Verifiers that collude, adapt queries, and attempt to infer the secret through repeated requests.
- Network failures, including duplicated, delayed, dropped, and reordered requests.
- Stale reads and unavailable Anchor services.
- Gate crashes before or after a state transition.
- An operator or storage environment that may attempt to restore an old state.

The admitted verifier set is fixed at genesis. There is no registration mechanism in the current implementation.

The Anchor is assumed to provide authorized, linearizable compare-and-swap and never revert a committed version. That last property is an assumption, not something CAS itself guarantees.

## Decision rule

The policy engine makes deterministic decisions. It does not use an LLM or consult the secret when deciding whether a query is informative, determined, or refused.

It checks the feasible interval and applies the global floor first.

Two optional integer caps provide additional controls:

- `K`: maximum informative answers per verifier.
- `R`: maximum committed transitions per verifier.

`K` is a fairness control. `R` limits resource use and Anchor writes. Neither cap is the privacy guarantee, and both can be disabled.

A query whose answer is already determined by the interval is answered without narrowing it. A query that would leave fewer than 10,000 possible values is refused.

## State threats and mitigations

| Threat | Current handling | Evidence boundary |
|---|---|---|
| Replay of an accepted request | Same nonce and request digest return the previously committed response | Tested locally |
| Reusing a nonce with different content | Rejected | Tested locally |
| Stale state or conflicting transition | Anchor compare-and-swap prevents a stale proposal from winning | Tested with a local test double |
| Two workers starting from the same version | Only one transition can win the CAS | Tested with a local test double |
| Crash before commit | No answer is released; the request can be processed again | Covered by local tests |
| Crash after commit but before response | Retry resolves to the committed response through replay | Tested locally |
| Unknown transaction outcome | Gate rereads the Anchor and releases nothing unless the proposed transition is confirmed | Tested locally |
| Invalid verifier or authentication | Rejected without a state transition | Tested with local authentication |
| Request digest dictionary attack | A fresh, secret, high-entropy verifier blinding value is required to prevent threshold enumeration from the digest | Conditional; the Gate checks length, not entropy or secrecy |
| Policy and scope mismatch | Requests and state are bound to scope and policy digests | Do not treat this as a fully demonstrated external Anchor guarantee |

The local sealer and Anchor are test doubles. They do not establish real encryption, rollback resistance, finality, or production confidentiality.

## State and response visibility

Accepted requests, including informative answers, determined answers, and refusals, commit a state transition.

This keeps accepted requests consistent in version advancement and record size. Floor and allocation refusals have the same external response format.

An Anchor observer can still see metadata such as verifier identity, nonce, request digest, timing, version, and the existence of activity. The threshold, answer, decision, interval, and counters are not plaintext fields in the Anchor record.

The request digest does not automatically hide the threshold. Its protection depends on the verifier's blinding value remaining secret and high-entropy. The local implementation does not demonstrate cryptographic confidentiality.

The complete transcript, including decisions, is subject to the feasible-set floor. That does not mean refusals reveal nothing to an individual verifier.

## Known gaps

1. **Credential re-issuance:** A new credential creates a new accounting domain and may reset the budget. Stable subject-level continuity is not implemented.

2. **Real confidentiality:** The local sealer is not encryption. Real authenticated encryption and key custody remain integration work.

3. **Rollback resistance:** CAS prevents competing writes from the same version, but does not guarantee that an Anchor will never revert committed state. This depends on the real Anchor's behavior and remains unproven locally.

4. **Finality and availability:** These depend on the deployed infrastructure. The local test double does not establish either. The system fails closed when state cannot be read or committed.

5. **Request metadata:** Timing, verifier identity, request counts, and activity remain observable. Side-channel protection is not claimed.

6. **No response mailbox:** A response is recoverable only through replay while the Gate is available and the request remains the verifier's latest committed request.

7. **Credential authenticity:** The current credential is a mock. No real issuer verification is implemented.

8. **Verifier admission and Sybil resistance:** The admitted set is fixed at genesis. There is no registration or identity-continuity mechanism.

9. **Value changes and epochs:** The model does not define how changing income or other attributes should be handled across epochs.

10. **External integrations:** Real NEAR finality guarantees, OutLayer execution and attestation, real payments, and production credential verification are not established by this local phase.

## Security boundary

Bit Budget is designed to limit cumulative inference from exact threshold answers across verifiers.

Its central guarantee is the global feasible-set floor, not differential privacy, encryption, or a claim that refusals reveal no information.

The local implementation tests the policy and state-transition model. Infrastructure security, cryptographic confidentiality, rollback resistance, attestation, and production availability remain separate requirements.