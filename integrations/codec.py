import base64

from core.records import Header, Record

_HEADER_FIELDS = ("scope_id", "version", "prev_digest", "verifier_id", "nonce",
                  "request_digest", "status_commitment", "policy_digest")


def header_to_dict(h: Header) -> dict:
    return {f: getattr(h, f) for f in _HEADER_FIELDS}


def record_to_json(rec: Record) -> dict:
    return {"header": header_to_dict(rec.header),
            "sealed_state_b64": base64.b64encode(rec.sealed_state).decode()}


def record_from_json(obj: dict) -> Record:
    h = obj["header"]
    if set(h) != set(_HEADER_FIELDS):
        raise ValueError("unexpected header fields")
    hdr = Header(str(h["scope_id"]), int(h["version"]), str(h["prev_digest"]), str(h["verifier_id"]),
                 int(h["nonce"]), str(h["request_digest"]), str(h["status_commitment"]), str(h["policy_digest"]))
    return Record(hdr, base64.b64decode(obj["sealed_state_b64"], validate=True))
