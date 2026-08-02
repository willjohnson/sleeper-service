"""API key generation and hashing.

Keys are shown once at creation and stored only as SHA-256 hashes. The prefix
(`ss_user_` / `ss_invoke_`) makes the kind recognizable in logs and secret
scanners without consulting the database.
"""

import hashlib
import secrets

from sleeper_service.constants import KeyKind

_PREFIXES = {KeyKind.USER: "ss_user_", KeyKind.INVOKE: "ss_invoke_"}


def generate_key(kind: KeyKind) -> tuple[str, str]:
    """Return (plaintext, hash). Plaintext is never stored."""
    plaintext = _PREFIXES[kind] + secrets.token_urlsafe(32)
    return plaintext, hash_key(plaintext)


def hash_key(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode()).hexdigest()
