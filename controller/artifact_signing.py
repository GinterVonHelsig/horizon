"""Domain-separated messages for signed delivery artifacts."""

from __future__ import annotations

import hashlib


def domain_separated_message(schema: str, digest: str) -> str:
    """Return the exact message signed for one artifact schema and digest."""

    if not schema or len(digest) != 64:
        raise ValueError("artifact signing domain or digest is malformed")
    return hashlib.sha256(
        f"top-delivery:artifact-signature:v1:{schema}:{digest}".encode("utf-8")
    ).hexdigest()
