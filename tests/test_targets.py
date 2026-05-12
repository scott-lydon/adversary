"""T: target registry storage + model validation."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from adversary.models import AuthKind, TargetKind, TargetSubmission
from adversary.security import decrypt_secret
from adversary.storage import SqliteStore
from adversary.target import (
    TargetNotAllowlisted,
    assert_allowlisted,
    register_from_submission,
    resolve_by_name,
    resolve_by_url,
)


def test_seed_rows_are_present(store: SqliteStore) -> None:
    names = {t["name"] for t in store.list_targets()}
    assert "echo-demo" in names
    assert "clinical-copilot-hetzner" in names


def test_seed_idempotent(store: SqliteStore) -> None:
    before = len(store.list_targets())
    store.init_schema()
    store.init_schema()
    after = len(store.list_targets())
    assert after == before


def test_register_target_round_trip(store: SqliteStore) -> None:
    sub = TargetSubmission(
        name="my-local-chat",
        kind=TargetKind.HTTP_CHAT,
        base_url="http://192.168.1.50:8000",
        description="local box",
        reach_steps=["open localhost", "log in"],
        auth_kind=AuthKind.BEARER,
        auth_secret="super-secret-bearer-token-xyz",
        allow_public=False,
        allowlist_on_create=True,
    )
    record = register_from_submission(store, sub)
    assert record.name == "my-local-chat"
    assert record.allowlisted is True
    # The TargetRecord does not carry the secret.
    assert "auth_secret" not in record.model_dump()


def test_registered_secret_is_encrypted_blob(store: SqliteStore) -> None:
    sub = TargetSubmission(
        name="my-chat",
        kind=TargetKind.HTTP_CHAT,
        base_url="http://192.168.1.50",
        auth_kind=AuthKind.BEARER,
        auth_secret="plaintext-token-do-not-leak",
        allow_public=False,
    )
    record = register_from_submission(store, sub)
    # Raw BLOB must not contain the plaintext.
    raw = store.get_target_secret_ciphertext(record.id)
    assert raw is not None
    assert b"plaintext-token-do-not-leak" not in raw
    assert decrypt_secret(raw) == "plaintext-token-do-not-leak"


def test_public_hostname_rejection(store: SqliteStore) -> None:
    with pytest.raises(Exception) as exc_info:
        TargetSubmission(
            name="evil-target",
            kind=TargetKind.HTTP_CHAT,
            base_url="http://evil.example.com",
            allow_public=False,
        )
    assert "public-internet" in str(exc_info.value).lower() or "allow-public" in str(exc_info.value).lower()


def test_public_hostname_allowed_with_flag(store: SqliteStore) -> None:
    sub = TargetSubmission(
        name="external-svc",
        kind=TargetKind.HTTP_CHAT,
        base_url="http://api.example.com",
        allow_public=True,
    )
    record = register_from_submission(store, sub)
    assert record.base_url == "http://api.example.com"


def test_name_regex_rejected(store: SqliteStore) -> None:
    with pytest.raises(Exception) as exc_info:
        TargetSubmission(
            name="Has Space",
            kind=TargetKind.HTTP_CHAT,
            base_url="http://127.0.0.1",
        )
    assert "Name" in str(exc_info.value) or "match" in str(exc_info.value)


def test_duplicate_name_rejected(store: SqliteStore) -> None:
    sub = TargetSubmission(
        name="duplicate-target",
        kind=TargetKind.HTTP_CHAT,
        base_url="http://127.0.0.1",
    )
    register_from_submission(store, sub)
    with pytest.raises(ValueError) as exc_info:
        register_from_submission(store, sub)
    assert "already exists" in str(exc_info.value)


def test_resolve_by_name(store: SqliteStore) -> None:
    record = resolve_by_name(store, "echo-demo")
    assert record.kind == TargetKind.ECHO


def test_resolve_by_url_existing_echo(store: SqliteStore) -> None:
    record = resolve_by_url(store, "echo://demo")
    assert record.name == "echo-demo"


def test_resolve_by_url_requires_auto_register_for_unknown_http(
    store: SqliteStore,
) -> None:
    with pytest.raises(ValueError) as exc_info:
        resolve_by_url(store, "http://10.0.0.5:1234")
    assert "adversary targets add" in str(exc_info.value)


def test_resolve_by_url_auto_register(store: SqliteStore) -> None:
    record = resolve_by_url(store, "http://10.0.0.5:1234", auto_register=True)
    assert record.name.startswith("auto-")
    assert record.allowlisted is False


def test_allowlist_gate(store: SqliteStore) -> None:
    record = resolve_by_name(store, "clinical-copilot-hetzner")
    assert record.allowlisted is False
    with pytest.raises(TargetNotAllowlisted) as exc_info:
        assert_allowlisted(record)
    msg = str(exc_info.value)
    assert "allowlist" in msg
    assert "clinical-copilot-hetzner" in msg
    assert "ARCHITECTURE" in msg


def test_set_allowlisted_flips_flag(store: SqliteStore) -> None:
    row = store.get_target("clinical-copilot-hetzner")
    assert row is not None
    store.set_allowlisted(row["id"], True)
    row2 = store.get_target("clinical-copilot-hetzner")
    assert row2 is not None and row2["allowlisted"] is True


def test_delete_target_refuses_if_referenced(store: SqliteStore) -> None:
    row = store.get_target("echo-demo")
    assert row is not None
    # Insert an attack pointing at this target.
    store.insert_attack(
        {
            "attack_id": "test-attack-1",
            "category": "direct_prompt_injection",
            "subcategory": "x",
            "prompt_sequence": [],
            "expected_unsafe_behavior": "x",
            "mutation_lineage": [],
            "generation_metadata": {},
        },
        "2026-05-12T00:00:00",
        target_id=row["id"],
    )
    with pytest.raises(ValueError) as exc_info:
        store.delete_target(row["id"])
    assert "reference" in str(exc_info.value)


def test_delete_target_succeeds_when_unreferenced(store: SqliteStore) -> None:
    sub = TargetSubmission(
        name="throwaway",
        kind=TargetKind.HTTP_CHAT,
        base_url="http://127.0.0.1",
    )
    record = register_from_submission(store, sub)
    store.delete_target(record.id)
    assert store.get_target(record.id) is None


def test_target_stats_counts(store: SqliteStore) -> None:
    row = store.get_target("echo-demo")
    assert row is not None
    stats = store.target_stats(row["id"])
    assert stats == {"campaigns": 0, "attacks": 0, "findings": 0}
