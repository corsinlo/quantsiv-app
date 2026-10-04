"""Organisation API tokens (WP7). Only the SHA-256 is stored; the value is shown once."""

import hashlib
import secrets

PREFIX = "qsv_"


def new_token() -> tuple[str, bytes, str]:
    """Return (token to show once, hash to store, display prefix)."""
    token = PREFIX + secrets.token_urlsafe(32)
    return token, hash_token(token), token[:8]


def hash_token(token: str) -> bytes:
    return hashlib.sha256(token.encode()).digest()
