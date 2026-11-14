# ARCHITECTURE.md
```
Verifier --(authenticated query, request_id, t)--> Gate
Gate: 1 auth  2 idempotency  3 local head == anchor head?  4 decide() [no secret]
      5 write-ahead pending entry  6 anchor.cas(seq,head -> seq+1,new_head)  7 promote + release answer
Trust boundaries: [Verifier] | [Gate+Store: intended TEE] | [Anchor: intended NEAR contract] | [Issuer]
```
Modules: `credential` (mock issuer), `policy` (pure decision), `gate` (protocol, hash-chained ledger, WAL, recovery), `anchor` (SIMULATED contract CAS), `fixtures`, `demo` (attack harness).
Implemented mapping (stage 1; contract deployed to NEAR testnet and live-tested once, owner-reported; the web app's optional live mode, `--anchor near`, wires this same NearAnchor into the real Gate; it is tested only against the contract model): Anchor -> `integrations/near_anchor.py` + `contracts/anchor` (head digest on chain, full records in a gate-side store). Target mapping: Gate -> OutLayer WASM; Anchor -> NEAR contract; verifier auth -> NEAR account; payment -> optional, disabled.

## Web app live NEAR mode (optional, operator-run)
Layering: `app.server` -> (lazy import, only for `--anchor near`) `app.near_mode` -> `integrations/` (NearAnchor, NearRpc, NearCliSender, DirRecordStore) and the unchanged `core.gate.Gate` + `core.policy`. Default mode never imports `integrations/` or `app.near_mode` (tested in a fresh process). There is no second implementation of the privacy logic: live mode differs only in the Anchor.
Scope: one fixed session (`live`), one accounting domain (one deployed contract = one scope), loopback hosts only. The server process holds the secret, the owner token, the sealed state and the signing capability (near-cli-rs key for the writer account). Visitors hold none of them: they can read the on-chain head (`GET /api/chain`, `GET /api/mode`, `scripts/chain_head.py`) but cannot submit authorized writes.
Request flow per API call: validate -> one `Gate.handle` round -> (if ANSWER/REFUSED) re-read the chain state and require that this very request is the verifier's last committed one -> release; otherwise keep the identical request as pending and return RETRY. No loops, no blind retries; a different threshold is refused while one is pending. Integrity or configuration errors halt the session (fail closed); RPC or store read failures return a 503 that releases nothing.
Evidence for this layer is model-based (NEAR_EVIDENCE.md section 9). It has not been run on testnet.
