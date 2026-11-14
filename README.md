# Bit Budget

**Every verifier sees one answer. Bit Budget tracks what all of them can collectively learn.**

Bit Budget is a disclosure-accounting gate for exact threshold questions about a private numeric attribute.

Consider an attribute such as annual income. An application asks whether the value is greater than a threshold. One answer reveals little. But several applications can coordinate their questions, or independently combine their answers, until they reconstruct the underlying value.

Bit Budget maintains a shared feasible interval across verifiers. It answers questions that can be answered without violating a configured minimum candidate floor, and refuses informative questions that would reduce the remaining possibilities below that floor.

USD ($) is used only for the demonstration. The underlying mechanism operates on integer-valued attributes.

## Quick start

The project uses Python's standard library. No paid services or external API credentials are required for local operation.

```bash
# Start the local web application
python -m app.server --port 8000

# Open http://127.0.0.1:8000/

# Run the attacker-versus-gate demonstration
python demo.py

# Run the complete test suite
python -m unittest discover -s tests -t .

# Run tests and report which claims their evidence supports
python claims_check.py

# Run engine mutation checks
python claims_check.py --mutations

# Run the floor-versus-caps mutation kill matrix
python claims_check.py --killmatrix

# Run application mutation checks
python claims_check.py --appmutations

# Check consistency between tests, claims and documentation
python claims_check.py --docs
```

On Windows, use `py` instead of `python` if that is your configured Python launcher.

The current test suite contains **207 tests**: 69 engine tests and 138 application tests. The mutation checks include 19 engine mutation checks and 17 application mutation checks.

See `APPLICATION.md` for application setup and usage.

## How the gate works

The demonstration uses a numeric domain from 0 to 999,999 and a global minimum candidate floor of 10,000.

The gate maintains a feasible interval:

`[L, U]`

A verifier submits a threshold question:

`Is the attribute greater than T?`

The gate evaluates the possible outcomes against the shared interval.

- **Informative answer:** The answer narrows the feasible interval without violating the floor.
- **Determined answer:** The existing interval already implies the answer. It can be returned without narrowing the interval.
- **Refusal:** An informative answer would leave fewer than the configured minimum number of candidates in at least one possible outcome.

The accounting is global across verifiers, not isolated per application.

The floor guarantees that the recorded transcript of threshold answers does not reduce the feasible set below the configured minimum. It does not guarantee confidentiality against every possible source of information or attack.

This is not differential privacy. It does not provide a differential privacy guarantee.

Per-verifier limits are fairness and resource controls. The global feasible-set floor is the central disclosure constraint.

## Demonstrations

### Local simulation

The default application runs locally. It demonstrates the difference between unrestricted threshold querying and querying through the shared gate.

The local simulation does not require NEAR or an internet connection.

### Live NEAR testnet demonstration

Bit Budget also has an operator-run live mode backed by a NEAR testnet anchor.

The deployed demo contract is:

`bbdemo-teedor.testnet`

The signing account is:

`teedor.testnet`

The live application was run against this deployment. A session produced ten committed transitions across three verifiers:

| Result | Count |
|---|---:|
| Informative answers | 6 |
| Determined answers | 3 |
| Refusals | 1 |
| Total transitions | 10 |

The final feasible interval was:

`[78,126, 93,750]`

That left 15,625 possible values.

The tenth request was refused because an informative split could violate the 10,000-candidate floor. The refusal itself was committed as version 10.

The persisted session history was subsequently reconstructed from the local record store. The reconstruction passed eight integrity checks, including record-digest verification, consecutive versions, previous-digest linkage, constant scope and policy, and agreement with the reported final digest.

Final digest:

`841dffaa119725f99eac09412bbd1be0f5488aad3af26617b073377b4973b1c6`

This reconstruction is evidence of the persisted record sequence. It is not a recovery of the original in-memory request log. Original timestamps, original log text, and the thresholds of determined and refused requests were not persisted.

### What NEAR stores

The NEAR contract stores the current state head: a version and digest, alongside scope, policy and writer metadata.

The full gate state, mock credential, and sealed state remain on the operator's computer.

The server signs authorized updates using its configured signing account. Visitors can read the public chain head but cannot submit authorized writes.

Answers and refusals are released only after the corresponding transition is confirmed on chain.

The contract does not store the full gate state or independently verify the correspondence between every digest and its off-chain record. That correspondence is checked by the application-side adapter.

## Running live mode

Live mode is optional and must be started by the operator.

```bash
python -m app.server --anchor near --store .\bbstore-demo --contract bbdemo-teedor.testnet --writer teedor.testnet --port 8001
```

Live mode is restricted to loopback interfaces because the server signs transactions with the operator's account.

The operator must have the required NEAR CLI configuration and signing access. The server displays an owner token at startup. Keep it private.

Do not expose the live server to other machines or share its operator token.

See `APPLICATION.md`, `NEAR_DEPLOY.md`, and `NEAR_EVIDENCE.md` for configuration and deployment details.

## Architecture

The main implementation is divided into:

- `core/`: gate logic, state, records, interfaces and policy.
- `app/`: HTTP application and session handling.
- `integrations/`: record serialization, local record storage, NEAR RPC and anchor integration.
- `contracts/anchor/`: Rust smart contract implementing the on-chain state head.
- `tests/`: engine and application tests.
- `scripts/`: deployment, inspection and verification utilities.
- `web/`: browser interface.

The local application uses a local simulation. The optional live mode connects the same gate logic to the NEAR-backed anchor.

## Verification

Run the Python test suite:

```bash
python -m unittest discover -s tests -t .
```

Run the contract tests:

```bash
cd contracts/anchor
cargo test --locked
```

Run the NEAR VM harness:

```bash
cd vmtest
cargo test --locked
```

Check the NEAR CLI syntax:

```bash
python scripts/check_cli_syntax.py --near <path>
```

The contract has 11 Rust unit tests. The VM harness has been exercised against the contract build.

The Python suite, mutation checks and claims checks provide local evidence for the implemented behavior. They do not establish production security or prove every deployment and operational property.

## Limitations and security boundaries

Bit Budget is a prototype and research implementation, not a production privacy system.

The following limitations are explicit:

- **No encryption:** The current test sealer does not encrypt the stored state.
- **Mock credential:** The demonstration uses a fixture secret, not a credential issued by a real identity provider.
- **No rollback resistance:** The prototype does not demonstrate protection against every rollback, fork or restoration of stale off-chain state.
- **No attestation:** The application does not demonstrate trusted execution or remote attestation.
- **No production confidentiality:** The on-chain digest does not conceal or encrypt the off-chain state.
- **Single operator:** Live writes are signed by the configured server-side account.
- **Testnet only:** The NEAR deployment is a demonstration, not a production deployment.
- **No OutLayer/TEE integration:** This has not been demonstrated.
- **No payments:** No payment or settlement mechanism is implemented.

The current sealer, credential and authenticator are test doubles. The live demonstration must not be interpreted as evidence that the off-chain state is confidential or protected against a malicious operator.

## Prior art

Bit Budget builds on established ideas in cumulative disclosure accounting, query auditing and privacy-budget enforcement.

A relevant related work is OCELOT:

`https://arxiv.org/abs/2606.12341`

The project does not claim to have invented cumulative query budgeting or refusal-based disclosure controls. Its focus is the application of a global feasible-set floor to exact threshold questions shared across multiple verifiers, supported by an executable attack-versus-gate demonstration.

See `PRIOR_ART.md` for the related-work discussion.

## Documentation

Recommended reading order:

1. `SECURITY_SPEC.md` - security model, assumptions and boundaries.
2. `HARDENING_REPORT.md` - implementation hardening and test evidence.
3. `CLAIMS_MATRIX.md` - claims and their supporting evidence.
4. `APPLICATION.md` - application setup and usage.
5. `NEAR_EVIDENCE.md` - NEAR testnet evidence.
6. `NEAR_DEPLOY.md` - contract deployment and live-mode instructions.
7. `PRIOR_ART.md` - related work and novelty boundaries.


The `prototype/` directory is quarantined and has not been reviewed. Do not treat it as part of the verified implementation.

---

**Bit Budget is a demonstration of cumulative disclosure accounting, not a claim that a hash on a blockchain makes off-chain data private.**