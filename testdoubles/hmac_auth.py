import hmac
import hashlib

from core.interfaces import Authenticator


class HmacTestAuthenticator(Authenticator):
    def __init__(self, keys):
        self._keys = dict(keys)

    def tag(self, verifier_id, digest_hex):
        return hmac.new(self._keys[verifier_id], digest_hex.encode(), hashlib.sha256).hexdigest()

    def verify(self, request) -> bool:
        key = self._keys.get(request.verifier_id)
        if key is None:
            return False
        exp = hmac.new(key, request.digest().encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(exp, request.auth_tag)
