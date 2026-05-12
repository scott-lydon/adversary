"""T: ``adversary.security.secrets`` happy path + failure modes."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from adversary.security import secrets as sec
from adversary.security.secrets import (
    SecretsError,
    decrypt_secret,
    encrypt_secret,
    load_or_create_key,
)


def _reset() -> None:
    sec._reset_key_cache_for_tests()


def test_round_trip_with_generated_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ADVERSARY_SECRET", raising=False)
    monkeypatch.setenv("ADVERSARY_SECRET_KEY_PATH", str(tmp_path / "k.key"))
    _reset()
    key = load_or_create_key()
    assert isinstance(key, bytes)
    ct = encrypt_secret("hunter2")
    assert isinstance(ct, bytes)
    assert b"hunter2" not in ct  # plaintext not present
    assert decrypt_secret(ct) == "hunter2"


def test_keyfile_chmod_0600(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ADVERSARY_SECRET", raising=False)
    path = tmp_path / "k.key"
    monkeypatch.setenv("ADVERSARY_SECRET_KEY_PATH", str(path))
    _reset()
    load_or_create_key()
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode == 0o600, f"key file mode = {oct(mode)}; want 0o600"


def test_malformed_env_var_raises_actionable_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ADVERSARY_SECRET", "not-a-real-fernet-key")
    monkeypatch.setenv("ADVERSARY_SECRET_KEY_PATH", str(tmp_path / "k.key"))
    _reset()
    with pytest.raises(SecretsError) as exc_info:
        load_or_create_key()
    msg = str(exc_info.value)
    assert "ADVERSARY_SECRET" in msg
    assert "Fernet" in msg
    assert "Fernet.generate_key" in msg


def test_keyfile_regenerated_after_manual_delete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("ADVERSARY_SECRET", raising=False)
    path = tmp_path / "k.key"
    monkeypatch.setenv("ADVERSARY_SECRET_KEY_PATH", str(path))
    _reset()
    k1 = load_or_create_key()
    assert path.exists()
    # Manual delete.
    path.unlink()
    _reset()
    k2 = load_or_create_key()
    assert path.exists()
    assert k2 != k1  # fresh key after recreate


def test_decrypt_wrong_key_actionable_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("ADVERSARY_SECRET", raising=False)
    monkeypatch.setenv("ADVERSARY_SECRET_KEY_PATH", str(tmp_path / "k.key"))
    _reset()
    load_or_create_key()
    ct = encrypt_secret("alpha")
    # Rotate keyfile out from under it.
    (tmp_path / "k.key").unlink()
    _reset()
    load_or_create_key()
    with pytest.raises(SecretsError) as exc_info:
        decrypt_secret(ct)
    assert "could not be decrypted" in str(exc_info.value)


def test_encrypt_non_str_raises() -> None:
    _reset()
    with pytest.raises(SecretsError):
        encrypt_secret(b"bytes-not-str")  # type: ignore[arg-type]


def test_decrypt_non_bytes_raises() -> None:
    _reset()
    with pytest.raises(SecretsError):
        decrypt_secret("not-bytes")  # type: ignore[arg-type]
