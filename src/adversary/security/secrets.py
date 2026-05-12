"""Symmetric encryption helpers for registered-target credentials.

The credential plaintext never appears in logs, HTTP responses, audit log
payloads, agent_messages payloads, or the dashboard. Plaintext lives in
memory only as long as the `register_target` HTTP request takes to execute,
then gets encrypted with Fernet and persisted as a BLOB.

Key resolution order:
  1. ``ADVERSARY_SECRET`` environment variable (must be a 32-byte url-safe
     base64 Fernet key, the exact format produced by ``Fernet.generate_key()``).
  2. ``~/.config/adversary/secret.key`` (auto-created with mode 0600 on first
     run).

The first time the file path is used, a fresh key is generated and written.
Subsequent calls reuse the same key. If the key file is deleted manually,
the next call regenerates it; any ciphertext encrypted under the old key
becomes undecryptable (which is the expected outcome).
"""

from __future__ import annotations

import os
import stat
import threading
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

__all__ = [
    "SecretsError",
    "decrypt_secret",
    "encrypt_secret",
    "load_or_create_key",
]


class SecretsError(RuntimeError):
    """Raised when the symmetric key cannot be loaded or built.

    Messages must name the failing source (env var vs key file) and the
    fix (regenerate a key, unset the env var, etc.).
    """


_LOCK = threading.Lock()
_CACHED_KEY: bytes | None = None
_CACHED_FERNET: Fernet | None = None


def _default_key_path() -> Path:
    """Return the default key-file path, honoring ``XDG_CONFIG_HOME``.

    Tests can override this by setting the ``ADVERSARY_SECRET_KEY_PATH``
    environment variable. The override exists only so the test suite can
    isolate per-test key files; production code uses the default.
    """
    override = os.environ.get("ADVERSARY_SECRET_KEY_PATH")
    if override:
        return Path(override).expanduser().resolve()
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        return Path(xdg).expanduser().resolve() / "adversary" / "secret.key"
    return Path.home() / ".config" / "adversary" / "secret.key"


def _validate_fernet_key(raw: bytes, source: str) -> bytes:
    """Raise SecretsError if ``raw`` is not a valid Fernet key."""
    try:
        Fernet(raw)
    except (ValueError, TypeError) as exc:
        raise SecretsError(
            f"{source} is not a valid Fernet key: {exc}. "
            "A Fernet key is 32 url-safe base64-encoded bytes "
            "(44 ASCII characters, no padding except the trailing '='). "
            "Generate one with `python -c \"from cryptography.fernet "
            "import Fernet; print(Fernet.generate_key().decode())\"`."
        ) from exc
    return raw


def load_or_create_key() -> bytes:
    """Resolve the symmetric key, creating one on disk if necessary.

    Returns the raw url-safe base64 Fernet key bytes. The result is cached
    in-process so repeated calls are cheap; tests reset the cache via
    ``_reset_key_cache_for_tests``.
    """
    global _CACHED_KEY, _CACHED_FERNET
    with _LOCK:
        if _CACHED_KEY is not None:
            return _CACHED_KEY

        env_val = os.environ.get("ADVERSARY_SECRET")
        if env_val:
            key = _validate_fernet_key(
                env_val.encode("ascii"),
                "the ADVERSARY_SECRET environment variable",
            )
            _CACHED_KEY = key
            _CACHED_FERNET = Fernet(key)
            return key

        path = _default_key_path()
        if path.exists():
            try:
                raw = path.read_bytes().strip()
            except OSError as exc:
                raise SecretsError(
                    f"could not read existing key file at {path!r}: {exc}. "
                    "Either fix the file permissions or delete the file "
                    "and let the next call create a fresh key (which will "
                    "invalidate any previously-encrypted credentials)."
                ) from exc
            key = _validate_fernet_key(raw, f"the key file at {path!r}")
            _CACHED_KEY = key
            _CACHED_FERNET = Fernet(key)
            return key

        # First run: generate a key and persist it 0600.
        path.parent.mkdir(parents=True, exist_ok=True)
        key = Fernet.generate_key()
        # Atomic-ish: write then chmod. We never overwrite an existing file.
        path.write_bytes(key)
        try:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError as exc:
            raise SecretsError(
                f"wrote {path!r} but could not chmod 0600 ({exc}). "
                "Delete the file and re-run after fixing permissions on "
                f"{path.parent!r}."
            ) from exc
        _CACHED_KEY = key
        _CACHED_FERNET = Fernet(key)
        return key


def _fernet() -> Fernet:
    if _CACHED_FERNET is not None:
        return _CACHED_FERNET
    load_or_create_key()
    assert _CACHED_FERNET is not None  # populated by load_or_create_key
    return _CACHED_FERNET


def encrypt_secret(plaintext: str) -> bytes:
    """Encrypt ``plaintext`` to a Fernet token (bytes) suitable for a BLOB."""
    if not isinstance(plaintext, str):
        raise SecretsError(
            f"encrypt_secret expects str, got {type(plaintext).__name__}. "
            "Wrap arbitrary bytes in a base64 str before calling."
        )
    return _fernet().encrypt(plaintext.encode("utf-8"))


def decrypt_secret(ciphertext: bytes) -> str:
    """Decrypt ciphertext bytes back to a plaintext str.

    Raises ``SecretsError`` with a precise message if the ciphertext is
    malformed or the active key cannot decrypt it (usually because the
    key file was rotated since the row was written).
    """
    if not isinstance(ciphertext, (bytes, bytearray)):
        raise SecretsError(
            f"decrypt_secret expects bytes, got {type(ciphertext).__name__}. "
            "Pull the raw BLOB column with `row['auth_secret_encrypted']`."
        )
    try:
        return _fernet().decrypt(bytes(ciphertext)).decode("utf-8")
    except InvalidToken as exc:
        raise SecretsError(
            "stored ciphertext could not be decrypted with the active key. "
            "Either ADVERSARY_SECRET points at a different key than the one "
            "that wrote the row, or the key file was regenerated. Re-register "
            "the target to write fresh ciphertext under the current key."
        ) from exc


def _reset_key_cache_for_tests() -> None:
    """Test-only helper. Drops the in-process key cache.

    Production code never calls this. Tests use it after mutating
    ``ADVERSARY_SECRET_KEY_PATH`` or ``ADVERSARY_SECRET``.
    """
    global _CACHED_KEY, _CACHED_FERNET
    with _LOCK:
        _CACHED_KEY = None
        _CACHED_FERNET = None
