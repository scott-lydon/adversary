"""Security helpers (encryption of registered-target credentials)."""

from __future__ import annotations

from adversary.security.secrets import (
    SecretsError,
    decrypt_secret,
    encrypt_secret,
    load_or_create_key,
)

__all__ = [
    "SecretsError",
    "decrypt_secret",
    "encrypt_secret",
    "load_or_create_key",
]
