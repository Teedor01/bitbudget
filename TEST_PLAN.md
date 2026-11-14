# TEST_PLAN.md  (as implemented; consistent with SECURITY_SPEC.md v0.4)

Run everything: `python3 claims_check.py` (all tests + per-claim evidence) and `python3 claims_check.py --mutations`. Tests use only the standard library, fixed seeds, no network. A test is reported passing only if it ran; local simulations are named in each test. "Production" = `D=[0,999999]`, `W=10000`; "scaled" = `D=[0,999]`, `W=100` or `[0,9999]`, `W=1000`; "tiny" = `[0,15]`, `[0,49]`, `[0,63]`.

## Policy and reference model (tests/test_policy.py, tests/test_reference.py, tests/reference_model.py)
| ID | What it asserts |
|---|---|
| T-P01 | Lower boundary on production: t = -1, 0, 9997, 9998, 9999, 10000 → DETERMINED, REFUSED, REFUSED, REFUSED, INFORMATIVE (exactly 10,000), INFORMATIVE; widths 9,999 vs 10,000 checked |
| T-P02 | Upper boundary: 989998/989999 INFORMATIVE (YES width 10,001/10,000), 990000/990001/999998 REFUSED (9,999/…/1), 999999 and 1,000,000 DETERMINED(no) |
| T-P03 | Interior interval of width 20,000: exactly-floor (10,000/10,000) INFORMATIVE; one below on either side REFUSED |
| T-P04 | Interval of exactly 10,000: every query with both branches nonempty REFUSED; outside DETERMINED |
| T-P05 | Repeated/implied thresholds DETERMINED with the same answer; impossible branch raises |
| T-P06 | Invalid policies rejected (N < 2W, W < 1, bad K/R, float bounds) |
| T-P07 | Integers only: float/bool threshold raises; static scan of `core/policy.py`: no float constants, imports only dataclasses/enum/typing |
| T-P08 | Caps only add restrictions: K cap refuses informative but not determined; floor-refused thresholds stay refused for every count; quota boundary; disabled quota |
| T-X01 | Tiny `[0,49]`, `W=5`: every interval × t in [-3,52]: `decide()` equals the independent set-based model (>70,000 cases), plus K-cap grid |
| T-X02 | Tiny `[0,63]`, `W=8`: exhaustive reachable-state search; every reachable interval ≥ W |
| T-X03 | **Gate-level** transcript indistinguishability on tiny `[0,15]`, `W=2`, two verifiers alternating, caps disabled: **all** sequences of length 1, 2 and 3 over **all 17** behaviourally distinct thresholds (-1..15) = 83,504 secret×sequence runs; for every secret the set of secrets with an identical full transcript (responses incl. refusals) equals the final feasible set. Length ≥ 4, other verifier assignments and larger domains are **not** covered |
| T-X04 | Tiny domain: reachable leaves partition the domain, all ≥ W; Bayes success = (#leaves)/N ≤ 1/W for binary-search and edge strategies (exact `Fraction`s) |
| T-X05 | Scaled domain: 400 random adaptive sequences, engine vs set model; production: 60,000 random (interval, t) cases vs an independent `range()`-length model |

## Adaptive attacks (tests/test_attacks.py, harness/attackers.py)
| ID | What it asserts |
|---|---|
| T-A01 | Stateless baseline recovers the exact value in exactly 20 queries for the fixture and ≤ 20 for 63 secrets |
| T-A02 | Same attacker through the gate stalls; attacker interval = gate state interval ≥ W; secret inside |
| T-A03 | 1, 3, 10 colluding verifiers, round-robin and random assignment, binary and squeeze strategies, 16 secrets incl. edges: floor holds |
| T-A04 | Greedy squeeze on 38 secrets: floor holds; **directed edge queries reach exactly W and nothing further** (tightness) |
| T-A05 | Tail prober: every threshold in [0,9998] and [990000,999998] REFUSED; 999999 DETERMINED; nothing learned (≈20,000 requests) |
| T-A06 | Unadmitted/forged ids (V9, "", "V1 ", "v1") REJECTED; zero CAS calls, version unchanged |
| T-A07 | Replay spam and fresh-nonce retry spam leak no extra information; quota respected |
| T-A08 | Determined-query spam: interval and informative count unchanged; quota R reached then REJECTED without commit |
| T-A09 | **Decision-oracle attacker**, scaled domain, 39 secrets × 3 strategies: brute-force replay of the full query log (including refusals) over every candidate secret; consistent set contains the secret, has ≥ W values, and equals the answers-only feasible set |

## State machine and anchor (tests/test_state.py; local test double only)
| ID | Scenario |
|---|---|
| T-S01 | Duplicate request: same response, version and CAS count unchanged, charged once |
| T-S02 | Same nonce with different threshold or different blinding → REJECTED, no commit |
| T-S03 | Nonce must be exactly last+1 (0, 2, 5, -1, then 3, 4 after progress rejected) |
| T-S04 | Two gates read the same version (barrier); one COMMITTED, the other RETRY, nothing released |
| T-S05 | UNKNOWN: (a) applied → reread confirms → released once; (b) not applied → RETRY, one CAS only, retry commits; (c) applied then another commit lands → RETRY, retry is a REPLAY, no re-commit |
| T-S06 | CAS unavailable / read unavailable → RETRY, no advance; liveness returns |
| T-S07 | Stale read (version 1 while head is 2): conflict → RETRY, or wrong-nonce → REJECTED; never a release |
| T-S08 | 3 threads × 60 requests, own gate each: one transition per accepted request, hash-linked contiguous chain, floor holds, nonces consistent |
| T-S09 / T-S10 | Crash after / before commit; a fresh gate with no memory replays / reprocesses correctly |
| T-S11 | Gate replacement mid-stream continues from the anchor |
| T-S12 | Wrong scope or policy digest in a request → REJECTED; a gate configured for another scope/policy raises `GateConfigError` against this anchor; no commit |
| T-S13 | Unauthorized writer key → UNAUTHORIZED; a gate with the wrong key raises; no commit |
| T-S14 | **Transition-binding audit**: version contiguity, `prev_digest` links, header nonce/digest equal sealed state, status commitment opens; negative control with a tampered header is detected |
| T-S15 | K and R caps per verifier; V2 unaffected by V1's allowance; quota exhaustion REJECTED without commit; **with caps enabled, floor-violating thresholds (5,000-value branch) are still REFUSED and leave the interval unchanged** |
| T-S16 | Caps and floor together over random traffic for four (K,R) settings: floor holds at every step. **Regression only: with small K this traffic never reaches the floor region, so it does NOT detect floor weakening under caps (kill matrix: survives MUT05/13/14)** |
| T-S17 | Runs with allocations disabled (K=R=None) |
| T-S18 | Bad tag, nonce 0/9, quota-exhausted, unadmitted id, conflicting duplicate: all REJECTED; version and CAS count unchanged |
| T-S20 | **Differential, policy level, exhaustive** on `[0,39]`, `W=4`: >400,000 (interval, t, count) cases × 12 cap variants (K ∈ {None,1,2,5}, R ∈ {None,1,3}). Failure mode caught: any cap configuration changing a decision in the **permissive** direction (floor refusal lifted, DETERMINED altered, cap not refusing at `count >= K`) |
| T-S21 | **Edge battery through the real gate under six (K,R) configurations**: nine floor-violating thresholds REFUSED with the interval untouched; lucky edge queries leave exactly `W`. Failure mode caught: the floor disabled/bypassed/weakened **only when caps are configured** |
| T-S22 | **Adaptive squeeze attackers** (4 cap settings × 6 secrets incl. edges) with generous caps; floor checked after **every** request. Failure mode caught: floor breach reached by an attacker walking toward the floor under caps |
| T-S19 | A committed refusal changes exactly: version, the verifier's nonce, digest, request count, last response, gamma; interval and informative count and other verifiers unchanged |

## Stale reads and the client policy (tests/test_client_policy.py, harness/client_policy.py)
Every H test runs through `CheckedGate`, which asserts on every response that nothing is released unless the exact request is committed on the public anchor history.
| ID | Scenario |
|---|---|
| T-H01 | Stale read (V1 looks like it committed nothing) makes a valid nonce-3 request REJECTED; client resends the **same** request; 2 attempts, first releases nothing, exactly one commit, nonce advances once |
| T-H02 | Genuinely invalid nonce: INVALID_NONCE after 1 attempt, expected nonce reported, no commit, no CAS, nonce not advanced; `resync()` then works |
| T-H03 | Forged auth tag and quota exhaustion: bounded attempts then UNRESOLVED, request kept pending, no commit |
| T-H04 | Lost response after commit: resend replays (1 attempt, no re-commit); stale-induced REJECTED although committed: public evidence ⇒ retry ⇒ replay, same response, no re-commit |
| T-H05 | Same nonce, different request: CONFLICT after 1 attempt, no retry, no commit |
| T-H06 | UNKNOWN: (a) applied → released once in 1 attempt; (b) not applied → RETRY then success, exactly one CAS per attempt; (c) applied then another commit lands → RETRY then REPLAY, committed once |
| T-H07 | Stale read replays an **older** committed request: same recorded response, no commit, no CAS (information-neutral) |
| T-H08 | A pending request is never silently skipped: new asks return PENDING; abandon only on public evidence of non-commit; refused when the nonce is committed |
| T-H09 | Incomplete public history: no INVALID_NONCE, no abandon, no resync; UNRESOLVED after bounded attempts |
| T-H10 | What a verifier can observe: all eight rejection causes (bad tag, unadmitted, lower/higher nonce, conflicting duplicate, short blinding, quota, stale) are byte-identical `REJECTED`; conflict/unavailable/unknown are byte-identical `RETRY` |

## Metadata (tests/test_metadata.py) — structural, local model
T-M01 identical record and sealed-state length across informative/determined/refused/other verifiers; T-M02 version +1 per accepted request regardless of decision; T-M03 floor and cap refusals byte-identical, **raw first response** (not via client retry); T-M04 response classes ⊆ {ANSWER:1, ANSWER:0, REFUSED, REJECTED, RETRY}, no reason words in headers, no print/logging in the gate; T-M05 public view keys fixed, no threshold/answer/interval; T-M06 two secrets in the same final interval: identical responses and public views (status commitment excluded, random by design); T-M07 request digest with random blinding resists a 10⁶ dictionary attack with guessed blindings, empty-blinding positive control is recovered; T-M08 blinding audit: length check only, constant public 32-byte blinding is accepted and the threshold is recovered, a leaked reused blinding exposes later thresholds, distinct blindings do not; T-M09 blinding never stored, logged (repr), returned, or placed in any record. **Not tested (non-goals):** timing, request rates, verifier-identity privacy, REJECTED-vs-accepted distinguishability.

## Limitations and layering (tests/test_limitations.py)
T-R01 two credentials for the same value: combined knowledge falls below W (documented limit; each domain alone holds its floor). T-R02 anchor reverting committed state breaks the floor (assumption A4 violation, expected). T-R03 spiked non-uniform prior: guessing probability ≫ 1/W while the feasible-count claim is unchanged. T-L01 layering/import boundaries; T-L02 no network/subprocess/db/third-party-crypto imports, no env or file I/O in core/testdoubles/harness; only `hashlib`, `hmac`, `secrets` for primitives. T-L03 `integrations/` imports only stdlib + core, no third-party or crypto packages, no key handling. NEAR adapter tests (`tests/test_near_anchor.py`, 46 cases) run against `ContractModel`, a Python semantic model of the Rust contract: they are NOT evidence about NEAR or about the Rust contract.

## NEAR contract and tooling checks (outside `unittest`; results in NEAR_EVIDENCE.md)
| Check | Command | Runs against | Expected |
|---|---|---|---|
| 11 Rust unit tests: genesis head, commit + one valid event, chain continues, stale CAS conflicts (no log), wrong digest, wrong version, unauthorized (before format check), malformed digests, malformed headers, bad genesis/policy digest panics | `cd contracts/anchor && cargo test --locked` | real Rust (near-sdk mocked blockchain) | 11 pass |
| Rust test meaning: 12 source mutations (no auth, ignore version, ignore digest, no increment, no digest update, unchecked digests, unchecked header size/shape, no log, uppercase hex, unchecked genesis) | applied by hand-run script, restored after | real Rust | each fails at least one test |
| Compiled wasm in the nearcore VM: init, head, commit, stale CAS, unauthorized, chain continues, re-init rejected | `cd contracts/anchor/vmtest && cargo test --locked` (`ANCHOR_WASM` overrides the wasm path) | `near-vm-runner` 0.38.0, in-memory storage | 4 pass |
| Authorization negative control | rebuild wasm with the check removed, run vmtest | same | `committed_then_stale_conflict_then_unauthorized` fails |
| near-cli-rs command syntax | `python3 scripts/check_cli_syntax.py --near <path>` | real v0.30.1 parser (`--help`) | 10 OK |
| Workflow steps | `.github/workflows/contract.yml` (rust x {1.95.0, 1.99.1}, python, cli-syntax) | **never run on GitHub**; steps reproduced locally | n/a |
| Live self-test: preflight, read, 2 successful writes, chain +2, stale CAS = CONFLICT, head unchanged, unauthorized signer does not commit, lost-response confirmed by re-read after one broadcast, failed write releases nothing | `python scripts/near_live_check.py selftest --store ./bbstore --contract <acct> --writer <acct> --other-signer <acct>` | **NEAR testnet** (owner-reported single run) and, separately, the Python model (`LiveScriptLogicTests`) | `SELFTEST: ALL PASSED (10/10)`; owner reported exactly that, final version 3 |

## Mutation checks (`claims_check.py --mutations`; each must make a mapped test fail)
| ID | Mutation | Result (final run) |
|---|---|---|
| T-MUT01 | floor `<` → `<=` | KILLED by P01, P02, P03 |
| T-MUT02 | decision depends on secret parity | KILLED by X03, A09, M06 |
| T-MUT03 | release answer on CONFLICT | KILLED by S04, S08 |
| T-MUT04 | CAS made unconditional | KILLED by S04, S07, S08 |
| T-MUT05 | caps disable the floor | KILLED by S15, S20, S21, S22 (run **without** T-P08); alone: P08, X01, S15, S20, S21, S22 kill it, **S16 does not** |
| T-MUT06 | scope/policy binding removed | KILLED by S12 |
| T-MUT07 | cap refusal encoded differently | KILLED by M03, M04 (**first run SURVIVED**: tests went through client retry; fixed) |
| T-MUT08 | width = upper − lower | KILLED by P03, X01 |
| T-MUT09 | idempotency keyed by nonce only | KILLED by S02, S18 |
| T-MUT10 | UNKNOWN treated as committed | KILLED by S05 |
| T-MUT11 | quota not enforced | KILLED by A08, S15, S18 |
| T-MUT12 | refusals not committed | KILLED by M02, S19 |
| T-MUT13 | floor halved when K is set | KILLED by S20, S21, S22 (alone: P08, X01, S15, S20, S21, S22) |
| T-MUT14 | floor bypassed when R is set | KILLED by S20, S21, S22 (alone: P08, S15, S20, S21, S22; **X01 and S16 do not**) |
| T-MUT15 | blinding length check removed | KILLED by M08, H10 |
| T-MUT16 | client treats REJECTED as success | KILLED by H01, H02, H03 |
| T-MUT17 | gate accepts higher nonces | KILLED by S03, H02 |
| T-MUT18 | client ignores a conflicting committed request | KILLED by H05 |
| T-MUT19 | client abandons pending without evidence | KILLED by H08, H09 |

## Invariant → falsifying tests
INV-1: P01-P04, X02, A02-A05, MUT01, MUT08. INV-2: X01, X03, P07, MUT02. INV-3: X03, A09, M06, MUT02. INV-4: S04, S08, MUT04. INV-5: S05, S09, H01, H04, MUT03, MUT10, MUT16. INV-6: S01-S03, S18, H05, MUT09, MUT17. INV-7: S06, S07, S05, H06, MUT10. INV-8: M01-M04, MUT07, MUT12. INV-9: S12, MUT06. INV-10: L01, L02. INV-11: P08, S15, S20, S21, S22, MUT05, MUT13, MUT14 (S16 is not evidence for INV-11).

## Application tests (tests/test_app.py, tests/e2e_fake_dom.js; IDs APPnn, outside the claims matrix)
APP01 input validation; APP02 boundary decisions through the service (9,998 refused, 9,999 informative, out-of-domain determined); APP03 750 random queries over 3 cap settings match the engine and the floor holds; APP04 verifier response is exactly `{verifier_id, threshold, response, answer}` and floor/cap refusals are identical; APP05 quota rejection not committed; APP06 attack demo (6 secrets × 2 strategies) keeps the floor and leaves the interactive session byte-for-byte unchanged; APP07 session isolation, 404, a token from another session is refused; APP08 full slice over real HTTP with independent policy recomputation; APP09 twelve malformed-request cases; APP10 three concurrent HTTP clients, one consistent history; APP11 static files, exact CSP, no unsafe directives, honest-label phrases present; APP12 frontend pure logic executed under Node; APP13 ids, forms, buttons, labels and listener targets statically consistent, `node --check`; APP14 service uses the real engine; APP15 core does not import the application; APP16 owner floor indicator computed from state; **audit findings:** APP17 verifier-facing responses contain no owner/auditor information or token (120 random queries); APP18 owner endpoints require the token (six bad tokens); APP19 story deterministic and every number matches an independent recomputation; APP20 story/attack share no state with user sessions; APP21 Content-Type, Host and owner-token enforcement over HTTP; APP22 verifier panel is structurally disjoint from the auditor panel (HTML subtree, visible text, verifier JS block, verifier call carries no token); APP24 initial page state, CSP-compatible markup, no external resources, no unsafe JS APIs, CSS rules and focus styles exist; APP25 honest labels on the first screen and banner never overwritten; **APP23 (fake DOM, NOT a browser):** real `app.js` handlers against the real server: initial state, in-flight guard, form submit with `preventDefault`, invalid input, refusal/answer flows, double submit adds one row, network failure, session loss, story failure and recovery, and a scan that nothing displayed on the verifier side contains owner/auditor strings.
Mutation checks for the application: `python3 claims_check.py --appmutations` (17 mutations, each must make an application test fail).

## Web app live NEAR mode (model-based; `tests/test_near_app.py`, `tests/e2e_fake_dom_near.js`)
All cases run against `ContractModel` (not NEAR), a temp-directory store, the real HTTP server, and (APPN19) the real `web/app.js` in a fake DOM (not a browser). None contacts the testnet or the owner's `bbstore`.
| Case | What it checks |
|---|---|
| APPN01-02 | successful writes (answers and refusals) through the real Gate and NearAnchor; verifier view carries only the four verifier keys |
| APPN03-05 | lost response: nothing released, identical request resent, one broadcast per call, different threshold refused while pending |
| APPN06-07 | late-landing transaction replayed without a second write; signer-reports-failure but chain shows commit |
| APPN08-09 | answer withheld if the confirm-before-release read fails (then replayed); a failed auditor post-read does not retract a confirmed answer |
| APPN10, 10b | RPC failure: 503, nothing sent, no internals, recovery; public chain head never stale after a write |
| APPN11 | integrity failure halts the session and it stays halted after the store is repaired |
| APPN12 | stale compare-and-swap against a competing writer |
| APPN13-15 | startup: missing/inconsistent store, wrong scope/policy, unreachable or old network, bad ids, non-loopback host, missing arguments |
| APPN16-18 | public endpoints expose only public chain data; one fixed session; no attack demo; safe HTTP errors |
| APPN19 | live UI wiring in a fake DOM: banner, hidden local notice, chain panel, RETRY text, token form |
| APPN20-21 | local mode unchanged: no NEAR code loaded, `/api/mode` local, `/api/chain` 404 |
Test meaning: 14 injected bugs in the live-mode code (no confirm-before-release, fresh request on every call, request not remembered, no halt, stale cache, other threshold allowed, error text leaked, skipped preflight, skipped head/store check, non-loopback allowed, attack allowed, sessions creatable, owner token in the public view, error mapping bypassed) were each caught. The existing 19 engine and 17 application mutation checks were re-run after the change and still pass.
Not covered: a real browser, the real network, real latency, concurrency beyond one competing writer on the model.

## Demo deployment script (model-based, plus real child processes for the decoding and timeout cases; `tests/test_deploy_demo.py`)
All cases run against `FakeChain` (an in-memory model of accounts, code hashes, `get_head` and the near CLI's failure modes), not NEAR; nothing is signed or sent and the evidence deployment and `bbstore` are never touched.
| Case | What it checks |
|---|---|
| DD01-03 | evidence account/store refused at every stage with zero RPC and CLI use; bad ids; tampered wasm refused before anything is sent |
| DD04-05 | base58 `code_hash` encoding against known vectors (zero hash, empty-input hash) and the shipped wasm; required balance computed from the wasm |
| DD06-09 | `plan` and `syntax` offline; `prepare` makes a fresh scope (differs from the evidence scope), never overwrites, refuses a non-empty store |
| DD10-17 | `create-account`: dry run; `--execute` needs `--confirm`; refuses an existing account or an unprepared store; exactly one transaction as an argument list; low-balance warning; ambiguous outcomes stop without retry; chain authoritative; unreadable chain after sending reported as "may have been sent"; missing binary |
| DD18-24 | `deploy`: every precondition blocks with no CLI call; exactly one atomic transaction with the init JSON as a single argument; applied-despite-timeout confirmed by the chain and a second deploy refused; lost/failed deploys stop and are never retried; unexpected code hash or initial state stops |
| DD30-38 | CLI handling (the Windows failure mode): real child processes emitting non-UTF-8 bytes (no crash, ASCII-safe text, ANSI stripped) and hanging after partial output (status `timeout`, partial stdout and stderr kept, "NOT proof of failure"); bytes mode with stdin closed; the exact `UnicodeDecodeError(cp1252)` and any other unexpected exception treated as ambiguous, never retried, never a crash; timeout with the account created is success and with it missing is ambiguous (never reported as `failed`); non-UTF-8 output through a whole stage prints only console-safe text; a binary that cannot start proves nothing was sent and needs no acknowledgement; seed-phrase/secret lines and bare ed25519 secret keys are never printed or written; console printing cannot raise on a cp1252 stream |
| DD39-45 | attempt journal: recorded before the command runs; an interrupted or ambiguous attempt blocks a blind second attempt until `--acknowledge-ambiguous-attempt`; the on-chain account is checked first even when acknowledged; confirmed and unsent attempts never block; the same for `deploy`; read-only `inspect`; an attempt from before the journal existed can be recorded offline with `note-prior-attempt` |
| DD25-29 | `verify`: 11 read-only checks through the Python adapter and the read-only chain reader, which must agree; every mismatch fails and withholds the app command; wrong expected version; old network |
Test meaning: 37 injected bugs, each caught (the original 19:guards removed, hash check skipped, overwrite allowed, existing account or contract ignored, balance ignored, `--execute` without `--confirm`, dry run executing, ambiguous result treated as success, hidden automatic retry of either transaction, verify checks skipped, app command shown after a failed read-back, preflight skipped, balance requirement too small, "nothing sent" reported after a possible send, unexpected code hash accepted) were each caught.
Further injected bugs: text mode restored, no decoding fallback, partial output dropped, timeout classified as failure, unexpected exceptions escaping, stdin left open, secret lines not withheld, bare keys not masked, journal written after the command, unresolved attempts not blocking (create and deploy), ambiguous journaled as confirmed, unsent counted as unresolved, `inspect` skipping the evidence guard, console printing that can raise, `note-prior-attempt` not writing or recording the wrong outcome.
Not covered: the real near binary executing a command on Windows, the faucet, the Windows keychain, real latency, a real chain. The cp1252 failure is reproduced with real child processes on Linux and with a fake that raises the same `UnicodeDecodeError`; it was not reproduced on Windows.
