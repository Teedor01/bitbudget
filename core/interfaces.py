from abc import ABC, abstractmethod
from enum import Enum


class CasResult(Enum):
    COMMITTED = "COMMITTED"
    CONFLICT = "CONFLICT"
    UNAUTHORIZED = "UNAUTHORIZED"
    MALFORMED = "MALFORMED"
    UNKNOWN = "UNKNOWN"         


class AnchorUnavailable(Exception):
    """The operation was definitely NOT applied."""


class GateConfigError(Exception):
    """Gate refuses to operate (scope/policy mismatch, unauthorized writer, integrity failure)."""


class Anchor(ABC):
    @abstractmethod
    def read(self):  
        ...

    @abstractmethod
    def compare_and_swap(self, writer_key, expected_version, expected_digest, new_record) -> CasResult:
        ...


class Sealer(ABC):
    @abstractmethod
    def seal(self, plaintext: bytes) -> bytes: ...

    @abstractmethod
    def unseal(self, sealed: bytes) -> bytes: ...


class Authenticator(ABC):
    @abstractmethod
    def verify(self, request) -> bool: ...
