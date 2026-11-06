import math
from .fixtures import build, ask, POLICY, SECRET_USD
from .policy import width

def usd(x): return f"${x:,}"

def attack(query_fn, label):
    a, b = POLICY.lo, POLICY.hi
    print(f"\n=== {label} ===  domain {usd(a)}..{usd(b)} (whole USD)")
    n_ok = 0
    refused = None
    for i in range(1, 60):
        t = (a + b) // 2
        vid = f"V{(i - 1) % 3 + 1}"
        r = query_fn(vid, f"req-{label[:1]}{i}", t)
        if r["status"] != "ANSWERED":
            print(f"{i:>2} {vid} asks v > {usd(t):>10}: REFUSED ({r['reason']})  feasible still {usd(a)}..{usd(b)}  width {usd(b-a+1)}")
            refused = r["reason"]; break
        n_ok += 1
        a, b = (t + 1, b) if r["answer"] else (a, t)
        print(f"{i:>2} {vid} asks v > {usd(t):>10}: {'YES' if r['answer'] else 'NO ':3}  feasible {usd(a)}..{usd(b)}  width {usd(b-a+1)}")
        if a == b: break
    return a, b, n_ok, refused

def main():
    base = lambda vid, rid, t: {"status": "ANSWERED", "answer": SECRET_USD > t}
    a, b, n, _ = attack(base, "BASELINE stateless")
    print(f"-> attacker recovered exact value {usd(a)} in {n} queries (secret fixture {usd(SECRET_USD)}); "
          f"information-theoretic minimum ceil(log2 N) = {math.ceil(math.log2(POLICY.hi-POLICY.lo+1))}")
    gate, anchor, store = build()
    a2, b2, n2, why = attack(lambda v, r, t: ask(gate, v, r, t), "PROTECTED bit-budget gate")
    print(f"-> after {n2} permitted answers the attacker's feasible range is {usd(a2)}..{usd(b2)} "
          f"(width {usd(b2-a2+1)} >= floor {usd(POLICY.min_width)}); first refusal reason: {why}")
    print(f"   anchor seq={anchor.seq} (SIMULATED anchor; no real chain or hardware attestation involved)")
    print("   Guarantee (stated precisely): against any exact-threshold attacker, the feasible interval never drops "
          f"below {usd(POLICY.min_width)}; under a uniform public prior that is >= {math.log2(POLICY.min_width):.2f} bits of remaining uncertainty.")

if __name__ == "__main__":
    main()
