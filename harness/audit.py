from core.records import State, status_commitment

KINDS = ("INFORMATIVE", "DETERMINED", "REFUSED")


def audit_chain(system):
    """Check hash linkage, version contiguity, header/state agreement and status-commitment openings."""
    problems, recs = [], system.anchor.history()
    for prev, cur in zip(recs, recs[1:]):
        h = cur.header
        if h.version != prev.header.version + 1:
            problems.append(("version", h.version))
        if h.prev_digest != prev.digest():
            problems.append(("prev_digest", h.version))
        st = State.from_bytes(system.sealer.unseal(cur.sealed_state))
        vs = st.verifiers.get(h.verifier_id)
        if vs is None or vs.last_nonce != h.nonce or vs.last_digest != h.request_digest:
            problems.append(("binding", h.version))
            continue
        gamma = bytes.fromhex(vs.last_gamma)
        code = vs.last_response
        if not any(status_commitment(k + ":" + code, gamma) == h.status_commitment for k in KINDS):
            problems.append(("status_commitment", h.version))
    return problems


def observer_view(record):
    """What an Anchor observer sees, assuming a sound Sealer: header fields and the sealed-state LENGTH only."""
    h = record.header
    return {"scope_id": h.scope_id, "version": h.version, "prev_digest": h.prev_digest,
            "verifier_id": h.verifier_id, "nonce": h.nonce, "request_digest": h.request_digest,
            "status_commitment": h.status_commitment, "policy_digest": h.policy_digest,
            "sealed_len": len(record.sealed_state)}
