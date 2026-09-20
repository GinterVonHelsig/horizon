"""Authority write credential type (opaque; issuance is authority-service only)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AuthorityWriteCredential:
    token: str
