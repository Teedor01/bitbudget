# Running the application (local simulation)

    python3 -m app.server --port 8000      # then open http://127.0.0.1:8000/

Standard library only; binds to 127.0.0.1; in the default mode no network access, no accounts, no cost. **Status: not yet validated in a real browser** (see UI_AUDIT.md and BROWSER_CHECKLIST.md).

**What the page shows.** First, a story panel with a fixed $120,000 income: unrestricted, 20 yes/no questions reveal it exactly; with Bit Budget the candidates narrow 1,000,000 → 500,001 → 250,001 → 125,001 → 62,500 → 31,250 → 15,625 and further questions are refused. Every number comes from the real engine. Below, "Try it yourself": an owner creates a session, a **verifier screen** shows only YES/NO/REFUSED, and a separate dashed **owner/auditor screen** shows the internal state (secret, candidate counts, policy decision and reason, committed transition).

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /api/demo-story` | none (fixed public demo secret) | deterministic story on a private session |
| `POST /api/sessions` `{income_usd, K?, R?}` | none | creates a session; returns `session_id` (verifier-facing) and `owner_token` (owner only) |
| `POST /api/sessions/{id}/query` `{verifier_id, threshold}` | session id | **verifier-facing**: returns only `{verifier_id, threshold, response, answer}` |
| `GET /api/sessions/{id}` | `X-Owner-Token` | owner view: secret, candidates, counters, transitions, full log |
| `POST /api/sessions/{id}/attack` `{strategy}` | `X-Owner-Token` | adaptive attacker on a separate shadow copy |
| `GET /api/mode` | none | `{mode: "local" | "near-testnet", notice, ...}`; no network access, no secrets |
| `GET /api/chain` | none | live mode only (404 in local mode): read-only on-chain head (version, digest, scope id, policy digest, writer), contract and signing account, explorer links, a curl command; public chain data only |
POST requires `Content-Type: application/json`; the `Host` header must be the loopback address.

**Real:** the policy engine, gate protocol, HTTP backend, frontend logic. **Simulated (labeled in the UI):** the anchor is `LocalTestAnchor` (an in-memory test double), the sealer does not encrypt, the credential is a mock, verifier authentication is an HMAC test double.
**Limitations:** sessions live in memory in one process; the owner token is the only access control and is held in the browser tab; the server holds the secret; at most 100 sessions; demo parameters fixed; the default mode has no NEAR/OutLayer; the guarantees are the local-simulation guarantees in CLAIMS_MATRIX.md.

## Live NEAR testnet mode (optional, operator-run; implemented, tested only against a model, NOT yet run on testnet)

    python3 -m app.server --anchor near --store ./<store> --contract <contract.testnet> --writer <signing-account.testnet> [--deploy-tx <tx id>] [--sign-with legacy-keychain] [--near-cli <path>]

- **Same gate and policy**; only the anchor is the deployed NEAR contract. One fixed session `live`, one accounting domain (one contract = one scope). Sessions cannot be created and the adversarial demo is disabled.
- **Loopback only.** `--anchor near` refuses any non-loopback host: every query is committed by **this server's signing account** (the operator's near-cli-rs key for `--writer`). Visitors can read the chain head but cannot submit authorized writes. The operator token (owner view only) is printed once on the console.
- **Startup fails closed** (nothing served, nothing written) if the store is missing or inconsistent, the policy or scope does not match, the network is not testnet or is older than the contract requires, or the chain head cannot be read.
- **Answers appear only after chain confirmation** (several seconds). If the write is not confirmed the verifier sees `RETRY` and must resend the same threshold; the server resends the identical request, never a blind new write. Integrity errors halt the session.
- **UI:** a separate blue "LIVE NEAR TESTNET MODE" banner replaces the local-simulation notice, plus an on-chain panel with contract, signing account, version, digest, scope, read-only NearBlocks links and a curl command.
- **Anyone can inspect the chain head without credentials:** `python3 scripts/chain_head.py --contract <contract.testnet>` or `GET /api/chain`.
- **Do not point this at the evidence deployment** (`bbanchor-teedor.testnet` / its `bbstore`): every question consumes the shared privacy budget (the interval only narrows; the gate eventually refuses permanently) and writes to the chain. Use a separate demo contract with its own fresh store (planned, not created).
- Caveats as everywhere: the test sealer does not encrypt, the credential is a mock, the server holds the secret and sealed state, no confidentiality, rollback resistance or attestation. See NEAR_EVIDENCE.md section 9 for what the tests do and do not show.
