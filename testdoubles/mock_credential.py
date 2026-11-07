import secrets
from dataclasses import dataclass


@dataclass(frozen=True)
class MockCredential:
    scope_id: str      
    value: int

    @staticmethod
    def new(value: int) -> "MockCredential":
        return MockCredential(secrets.token_hex(16), value)
