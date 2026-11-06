import math


def baseline_binary_search(secret, lo, hi):
    """Stateless baseline: exact answers, no accounting. Returns (recovered_value_or_interval, queries)."""
    a, b, n = lo, hi, 0
    while a < b:
        t = (a + b) // 2
        n += 1
        a, b = (t + 1, b) if secret > t else (a, t)
    return a, n


def adaptive_attack(query_fn, lo, hi, W, rng, strategy="squeeze", max_queries=300):
    """query_fn(t) -> True/False (answer) or None (refused/rejected). Returns the attacker's final
    interval (derived only from released answers) and the number of answers obtained."""
    a, b, answers = lo, hi, 0
    for _ in range(max_queries):
        if a == b:
            break
        mid = (a + b) // 2
        if strategy == "binary":
            cands = [mid]
        elif strategy == "squeeze":          
            cands = [mid, a + W - 1, b - W, a + W, b - W + 1]
        elif strategy == "random":
            cands = [rng.randint(a - 2, b + 2) for _ in range(4)]
        else:
            raise ValueError(strategy)
        progressed = False
        for t in cands:
            if not (a <= t < b):             
                continue
            r = query_fn(t)
            if r is None:
                continue
            answers += 1
            a, b = (t + 1, b) if r else (a, t)
            progressed = True
            break
        if not progressed:
            for t in {mid - 1, mid + 1, a, b - 1, a + 1, b - 2}:
                if a <= t < b:
                    r = query_fn(t)
                    if r is not None:
                        answers += 1
                        a, b = (t + 1, b) if r else (a, t)
                        progressed = True
                        break
        if not progressed:
            break
    return (a, b), answers


def make_query_fn(system, verifier_ids, rng, assign="rr", log=None):
    clients = [system.client(v) for v in verifier_ids]
    state = {"i": 0}

    def q(t):
        if assign == "rr":
            c = clients[state["i"] % len(clients)]
            state["i"] += 1
        else:
            c = rng.choice(clients)
        resp = c.ask(t)
        if log is not None:
            log.append((c.vid, t))
        if resp.kind == "ANSWER":
            return resp.answer
        return None
    return q
