import hmac, hashlib, json, secrets
from dataclasses import dataclass, asdict

ISSUER = "MOCK-TEST-ISSUER (not a real income attestation)"

@dataclass(frozen=True)
class Credential:
    cred_id: str
    attribute: str      
    value: int          
    currency: str     
    issuer: str
    tag: str = ""

def _body(c: Credential) -> bytes:
    d = asdict(c); d.pop("tag")
    return json.dumps(d, sort_keys=True).encode()

def issue(issuer_key: bytes, value: int) -> Credential:
    c = Credential(secrets.token_hex(16), "annual_income_usd", value, "USD", ISSUER)
    tag = hmac.new(issuer_key, _body(c), hashlib.sha256).hexdigest()
    return Credential(**{**asdict(c), "tag": tag})

def verify(issuer_key: bytes, c: Credential) -> bool:
    exp = hmac.new(issuer_key, _body(c), hashlib.sha256).hexdigest()
    return hmac.compare_digest(exp, c.tag)
