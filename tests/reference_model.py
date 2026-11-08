def ref_decide(feasible, t, W, K=None, informative_count=0):
    yes = {x for x in feasible if x > t}
    no = {x for x in feasible if x <= t}
    if not yes:
        return ("DETERMINED", False)
    if not no:
        return ("DETERMINED", True)
    if len(yes) < W or len(no) < W:
        return ("REFUSED", None)
    if K is not None and informative_count >= K:
        return ("REFUSED", None)
    return ("INFORMATIVE", None)


def ref_simulate(lo, hi, W, K, secret, queries):
    """queries: list of (verifier_id, threshold). Returns (transcript, final feasible set).
    transcript items: ('ANSWER', bool) or ('REFUSED',)."""
    feasible = set(range(lo, hi + 1))
    counts, out = {}, []
    for vid, t in queries:
        kind, forced = ref_decide(feasible, t, W, K, counts.get(vid, 0))
        if kind == "REFUSED":
            out.append(("REFUSED",))
        elif kind == "DETERMINED":
            out.append(("ANSWER", forced))
        else:
            ans = secret > t
            feasible = {x for x in feasible if (x > t) == ans}
            counts[vid] = counts.get(vid, 0) + 1
            out.append(("ANSWER", ans))
    return out, feasible
