"""Fernet encryption for credentials at rest, keyed off SECRET_KEY."""

import base64
import hashlib
from functools import lru_cache

from cryptography.fernet import Fernet

from sleeper_service.config import get_settings


@lru_cache
def _fernet() -> Fernet:
    digest = hashlib.sha256(get_settings().secret_key.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt(plaintext: str) -> bytes:
    return _fernet().encrypt(plaintext.encode())


def decrypt(ciphertext: bytes) -> str:
    return _fernet().decrypt(ciphertext).decode()
