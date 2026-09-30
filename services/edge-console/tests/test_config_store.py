"""Tests for Edge Console config store."""

from pathlib import Path

from src.config_store import ConfigStore, PlatformConfig


def test_save_and_mask_secrets(tmp_path: Path) -> None:
    path = tmp_path / "platform.json"
    store = ConfigStore(path)
    cfg = PlatformConfig(
        configured=True,
        registration_token="invite-secret-123",
        sensel_api_key="sensel-ot-ingest-lab-2026",
    )
    store.save(cfg)
    loaded = store.load()
    assert loaded.registration_token == "invite-secret-123"

    public = store.public_view(loaded)
    assert public["registration_token_set"] is True
    assert "registration_token" not in public
    assert public["sensel_api_key_set"] is True
