"""Persist edge platform configuration on shared agent data volume."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel, Field

from src.platform_detect import detect_hardware
from src.sensor_id_resolve import (
    get_hostname,
    resolve_sensor_id_with_source,
    sensor_id_from_hostname,
    should_auto_assign_from_hostname,
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class PlatformConfig(BaseModel):
    configured: bool = False
    sensor_id: str = "ot-edge-001"
    site_id: str = "factory-lab-001"
    sensor_type: str = "ot-edge-sensor"
    # Deployment profile (read-only when set via NDR_PROFILE env): ot_ids | it_ndr
    ndr_profile: str = "ot_ids"
    # Auto-detect the host platform (pi4 / ubuntu / windows-docker …) instead of
    # a hardcoded default so the sensor table is accurate out of the box.
    hardware: str = Field(default_factory=detect_hardware)
    sensel_api_url: str = "http://192.168.1.108:8081"
    sensel_api_key: str = ""
    smb_intel_api_key: str = ""
    policy_sync_tenant_id: str = ""
    registration_token: str = ""
    sensel_verify_tls: bool = False
    mqtt_enabled: bool = True
    mqtt_host: str = "192.168.1.203"
    mqtt_port: int = 1883
    mqtt_tenant_id: str = "default"
    capture_interface: str = "eth0"
    capture_bpf_filter: str = "(ether proto 0x88b8) or (tcp port 102)"
    last_register_at: Optional[str] = None
    last_register_ok: Optional[bool] = None
    last_register_tenant_id: Optional[str] = None
    last_register_error: Optional[str] = None
    updated_at: Optional[str] = None


class ConfigStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or Path(os.environ.get("PLATFORM_CONFIG_PATH", "/data/agent/platform.json"))

    def _apply_sensor_id_defaults(self, config: PlatformConfig) -> PlatformConfig:
        if should_auto_assign_from_hostname(
            config.sensor_id,
            configured=config.configured,
            registered=bool(config.last_register_ok),
        ):
            config.sensor_id, _ = resolve_sensor_id_with_source(
                env_id=os.environ.get("SENSOR_ID", ""),
                platform_id=config.sensor_id,
            )
        env_profile = (os.environ.get("NDR_PROFILE", "") or "").strip().lower()
        if env_profile in ("it", "it_ndr"):
            config.ndr_profile = "it_ndr"
            if config.sensor_type == "ot-edge-sensor":
                config.sensor_type = "it-ndr-edge"
        return config

    def load(self) -> PlatformConfig:
        if not self.path.is_file():
            config = PlatformConfig(
                sensel_api_key=os.environ.get("DEFAULT_SENSEL_API_KEY", "sensel-ot-ingest-lab-2026"),
            )
            return self._apply_sensor_id_defaults(config)
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return self._apply_sensor_id_defaults(PlatformConfig())
        return self._apply_sensor_id_defaults(PlatformConfig.model_validate(raw))

    def save(self, config: PlatformConfig) -> PlatformConfig:
        config.updated_at = _now_iso()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            config.model_dump_json(indent=2),
            encoding="utf-8",
        )
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass
        return config

    def public_view(self, config: PlatformConfig) -> dict[str, Any]:
        """Mask secrets for API responses."""
        data = config.model_dump()
        token = data.get("registration_token") or ""
        key = data.get("sensel_api_key") or ""
        intel_key = data.get("smb_intel_api_key") or ""
        data["registration_token_set"] = bool(token.strip())
        data["registration_token_preview"] = (
            f"{token[:4]}…{token[-2:]}" if len(token) > 6 else ("••••" if token else "")
        )
        data["sensel_api_key_set"] = bool(key.strip())
        data["sensel_api_key_preview"] = (
            f"{key[:6]}…" if len(key) > 8 else ("••••" if key else "")
        )
        data["smb_intel_api_key_set"] = bool(intel_key.strip())
        data["smb_intel_api_key_preview"] = (
            f"{intel_key[:6]}…" if len(intel_key) > 8 else ("••••" if intel_key else "")
        )
        data.pop("registration_token", None)
        data.pop("sensel_api_key", None)
        data.pop("smb_intel_api_key", None)
        data["hostname"] = get_hostname()
        data["sensor_id_suggested"] = sensor_id_from_hostname()
        _, source = resolve_sensor_id_with_source(
            env_id=os.environ.get("SENSOR_ID", ""),
            platform_id=config.sensor_id,
        )
        data["sensor_id_source"] = source
        env_profile = (os.environ.get("NDR_PROFILE", "") or "").strip().lower()
        data["ndr_profile_locked"] = env_profile in ("it", "it_ndr")
        data["ndr_profile_label"] = (
            "IT NDR" if (data.get("ndr_profile") or "") == "it_ndr" else "OT IDS"
        )
        return data

    def sync_env_file(self, config: PlatformConfig) -> None:
        """Write capture overrides for packet-sensor env_file."""
        capture_env = self.path.parent / "capture.env"
        capture_env.parent.mkdir(parents=True, exist_ok=True)
        lines = [
            f"CAPTURE_INTERFACE={config.capture_interface}",
            f"CAPTURE_BPF_FILTER={config.capture_bpf_filter}",
            f"MQTT_TENANT_ID={config.mqtt_tenant_id or config.last_register_tenant_id or 'default'}",
            f"SENSOR_ID={config.sensor_id}",
        ]
        capture_env.write_text("\n".join(lines) + "\n", encoding="utf-8")
        try:
            os.chmod(capture_env, 0o600)
        except OSError:
            pass

    def merge_update(self, patch: dict[str, Any]) -> PlatformConfig:
        current = self.load()
        merged = current.model_dump()
        for key, value in patch.items():
            if value is None:
                continue
            if key == "ndr_profile" and (os.environ.get("NDR_PROFILE", "") or "").strip().lower() in (
                "it",
                "it_ndr",
            ):
                continue
            if key in ("registration_token", "sensel_api_key", "smb_intel_api_key") and value == "":
                continue
            if key in merged:
                merged[key] = value
        merged["configured"] = True
        saved = self.save(PlatformConfig.model_validate(merged))
        self.sync_env_file(saved)
        return saved

    def record_register_result(
        self,
        *,
        ok: bool,
        tenant_id: Optional[str] = None,
        error: Optional[str] = None,
    ) -> PlatformConfig:
        config = self.load()
        config.last_register_at = _now_iso()
        config.last_register_ok = ok
        config.last_register_tenant_id = tenant_id
        config.last_register_error = error
        if ok and tenant_id:
            config.mqtt_tenant_id = tenant_id
            config.configured = True
        return self.save(config)
