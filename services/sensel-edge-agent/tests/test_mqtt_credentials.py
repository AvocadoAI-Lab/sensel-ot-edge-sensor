"""Tests for persisting Control-Plane-issued MQTT credentials (P4)."""

from __future__ import annotations

import json
import stat

from src.runtime.mqtt_credentials import (
    credentials_status,
    load_persisted_credentials,
    persist_credentials,
)


def test_persist_then_load_roundtrip(tmp_path) -> None:
    path = tmp_path / "mqtt-credentials.json"
    ok = persist_credentials(
        username="ndr-tenant-acme-ndr-x",
        password="s3cret",
        host="broker.example",
        port=1883,
        tenant_id="tenant-acme",
        acl_version=3,
        path=path,
    )
    assert ok is True

    loaded = load_persisted_credentials(path)
    assert loaded is not None
    assert loaded["username"] == "ndr-tenant-acme-ndr-x"
    assert loaded["password"] == "s3cret"
    assert loaded["host"] == "broker.example"
    assert loaded["port"] == 1883
    assert loaded["acl_version"] == 3

    # Secret file must not be world/group readable.
    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode & 0o077 == 0


def test_persist_rejects_empty_username(tmp_path) -> None:
    path = tmp_path / "creds.json"
    assert persist_credentials(username="  ", password="x", path=path) is False
    assert not path.exists()


def test_load_missing_returns_none(tmp_path) -> None:
    assert load_persisted_credentials(tmp_path / "absent.json") is None


def test_load_ignores_invalid_or_empty(tmp_path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    assert load_persisted_credentials(bad) is None

    empty = tmp_path / "empty.json"
    empty.write_text(json.dumps({"username": ""}), encoding="utf-8")
    assert load_persisted_credentials(empty) is None


def test_credentials_status_not_landed(tmp_path) -> None:
    assert credentials_status(tmp_path / "absent.json") == {"landed": False}


def test_credentials_status_omits_password(tmp_path) -> None:
    path = tmp_path / "mqtt-credentials.json"
    persist_credentials(
        username="ndr-tenant-acme-ndr-x",
        password="s3cret",
        host="broker.example",
        port=1883,
        tenant_id="tenant-acme",
        acl_version=3,
        path=path,
    )
    status = credentials_status(path)
    assert status["landed"] is True
    assert status["username"] == "ndr-tenant-acme-ndr-x"
    assert status["host"] == "broker.example"
    assert status["port"] == 1883
    assert status["tenant_id"] == "tenant-acme"
    assert status["acl_version"] == 3
    # The plaintext secret must never be surfaced.
    assert "password" not in status
