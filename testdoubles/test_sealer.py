from core.interfaces import Sealer

MARK = b"UNSEALED-TEST-DOUBLE:"


class UnsealedTestSealer(Sealer):
    def seal(self, plaintext: bytes) -> bytes:
        return MARK + plaintext

    def unseal(self, sealed: bytes) -> bytes:
        if not sealed.startswith(MARK):
            raise ValueError("not a test-double sealed blob")
        return sealed[len(MARK):]
