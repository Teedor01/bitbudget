"""One-command adversarial demo:  python3 demo.py
Same secret, same adaptive attacker, two systems. Every number is derived from actual system state.
SIMULATION: local test-double anchor, non-cryptographic sealer, mock credential, HMAC test authenticator."""
import math
import random

from harness.attackers import adaptive_attack, baseline_binary_search, make_query_fn
from harness.system import DEMO_POLICY, FIXTURE_SECRET, build_system

P = DEMO_POLICY
usd = lambda x: f"${x:,}"


def main():
    print(f"Domain {usd(P.lo)}..{usd(P.hi)} whole USD, floor W = {P.W:,} values, caps disabled. SIMULATION (see labels in code).")
    value, n = baseline_binary_search(FIXTURE_SECRET, P.lo, P.hi)
    print(f"\n[1] STATELESS BASELINE: exact answers, no accounting -> recovered {usd(value)} in {n} queries "
          f"(ceil(log2 N) = {math.ceil(math.log2(P.hi - P.lo + 1))}).")

    print("\n[2] SAME ATTACK THROUGH THE GATE (3 colluding verifiers, round robin):")
    s = build_system()
    vids = ["V1", "V2", "V3"]; clients = [s.client(v) for v in vids]
    a, b, i = P.lo, P.hi, 0
    while a < b and i < 60:
        t = (a + b) // 2; c = clients[i % 3]; i += 1
        r = c.ask(t)
        st = s.state().interval
        shown = {"ANSWER": "YES" if r.answer else "NO", "REFUSED": "REFUSED", "REJECTED": "REJECTED", "RETRY": "RETRY"}[r.kind]
        print(f"  {i:>2} {c.vid} asks income > {usd(t):>9}: {shown:8} gate feasible set {usd(st.lo)}..{usd(st.hi)} ({st.size:,} values)")
        if r.kind != "ANSWER":
            print(f"  -> first refusal; attacker stops with {st.size:,} candidate values (floor {P.W:,}); anchor version {s.anchor.version}")
            break
        a, b = (t + 1, b) if r.answer else (a, t)
    fin = s.state().interval
    assert fin.size >= P.W and fin.lo <= FIXTURE_SECRET <= fin.hi
    print(f"  invariant: |I| = {fin.size:,} >= {P.W:,}  (guessing advantage under a uniform prior = log2(N/|I|) = {math.log2((P.hi-P.lo+1)/fin.size):.2f} bits <= {math.log2((P.hi-P.lo+1)/P.W):.2f})")

    print("\n[3] INVARIANT SWEEP (not one secret, not one sequence): adaptive attackers x many secrets")
    rng = random.Random(2026)
    secrets_ = [0, 1, 9_999, 10_000, 83_250, 500_000, 989_999, 990_000, 999_999] + [rng.randint(0, P.hi) for _ in range(40)]
    worst = P.hi - P.lo + 1; runs = 0
    for secret in secrets_:
        for strategy in ("binary", "squeeze", "random"):
            sys_ = build_system(secret=secret, history_limit=4)
            q = make_query_fn(sys_, vids, rng)
            (aa, bb), _ = adaptive_attack(q, P.lo, P.hi, P.W, rng, strategy)
            gi = sys_.state().interval
            assert gi.size >= P.W and (aa, bb) == (gi.lo, gi.hi) and gi.lo <= secret <= gi.hi
            worst = min(worst, gi.size); runs += 1
    print(f"  {runs} attack runs, {len(secrets_)} secrets, 3 strategies: smallest candidate set any attacker reached = {worst:,} (floor {P.W:,}).")
    print("\nNot demonstrated here: rollback resistance, finality, confidentiality, attestation, any real infrastructure.")


if __name__ == "__main__":
    main()
