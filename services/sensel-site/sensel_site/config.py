"""Environment-backed configuration for the isolated Tier 2 Site service."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

_IDENTITY = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


def _bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be a boolean")


def _int(name: str, default: int, *, minimum: int = 1) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if value < minimum:
        raise ValueError(f"{name} must be at least {minimum}")
    return value


@dataclass(frozen=True)
class SiteConfig:
    tenant_id: str
    site_id: str
    node_id: str
    data_dir: Path
    mqtt_enabled: bool
    mqtt_host: str
    mqtt_port: int
    mqtt_username: str
    mqtt_password: str
    mqtt_tls: bool
    mqtt_ca_path: str
    mqtt_cert_path: str
    mqtt_key_path: str
    mqtt_tls_insecure: bool
    mqtt_session_expiry_sec: int
    signing_key_path: Path
    signing_key_id: str
    max_episode_bytes: int
    episode_retention_days: int
    feature_contract_dir: Path

    @classmethod
    def from_env(cls) -> SiteConfig:
        tenant_id = os.getenv("SENSEL_SITE_TENANT_ID", "").strip()
        site_id = os.getenv("SENSEL_SITE_ID", "").strip()
        node_id = os.getenv("SENSEL_SITE_NODE_ID", "").strip()
        if not tenant_id or not site_id or not node_id:
            raise ValueError(
                "SENSEL_SITE_TENANT_ID, SENSEL_SITE_ID and "
                "SENSEL_SITE_NODE_ID are required"
            )
        if not all(_IDENTITY.fullmatch(value) for value in (tenant_id, site_id, node_id)):
            raise ValueError("Site tenant, site and node identities contain invalid characters")
        mqtt_tls = _bool("SENSEL_SITE_MQTT_TLS", True)
        mqtt_insecure = _bool("SENSEL_SITE_MQTT_TLS_INSECURE", False)
        environment = os.getenv("SENSEL_SITE_ENV", "production").strip().lower()
        if mqtt_insecure and environment != "lab":
            raise ValueError("insecure MQTT TLS is only allowed when SENSEL_SITE_ENV=lab")
        mqtt_enabled = _bool("SENSEL_SITE_MQTT_ENABLED", True)
        if mqtt_enabled and environment != "lab" and not mqtt_tls:
            raise ValueError("production Site MQTT requires TLS")
        ca_path = os.getenv("SENSEL_SITE_MQTT_CA_PATH", "").strip()
        cert_path = os.getenv("SENSEL_SITE_MQTT_CERT_PATH", "").strip()
        key_path = os.getenv("SENSEL_SITE_MQTT_KEY_PATH", "").strip()
        if mqtt_enabled and mqtt_tls and environment != "lab" and not all(
            (ca_path, cert_path, key_path)
        ):
            raise ValueError("production Site MQTT requires CA, client cert and key")
        return cls(
            tenant_id=tenant_id,
            site_id=site_id,
            node_id=node_id,
            data_dir=Path(os.getenv("SENSEL_SITE_DATA_DIR", "/var/lib/sensel-site")),
            mqtt_enabled=mqtt_enabled,
            mqtt_host=os.getenv("SENSEL_SITE_MQTT_HOST", "site-mqtt").strip(),
            mqtt_port=_int("SENSEL_SITE_MQTT_PORT", 8883),
            mqtt_username=os.getenv("SENSEL_SITE_MQTT_USERNAME", "").strip(),
            mqtt_password=os.getenv("SENSEL_SITE_MQTT_PASSWORD", ""),
            mqtt_tls=mqtt_tls,
            mqtt_ca_path=ca_path,
            mqtt_cert_path=cert_path,
            mqtt_key_path=key_path,
            mqtt_tls_insecure=mqtt_insecure,
            mqtt_session_expiry_sec=_int(
                "SENSEL_SITE_MQTT_SESSION_EXPIRY_SEC", 86400
            ),
            signing_key_path=Path(
                os.getenv(
                    "SENSEL_SITE_SIGNING_KEY_PATH",
                    "/run/secrets/sensel-site-signing-key.pem",
                )
            ),
            signing_key_id=os.getenv("SENSEL_SITE_SIGNING_KEY_ID", "").strip(),
            max_episode_bytes=_int(
                "SENSEL_SITE_MAX_EPISODE_BYTES",
                1_048_576,
                minimum=4096,
            ),
            episode_retention_days=_int(
                "SENSEL_SITE_EPISODE_RETENTION_DAYS",
                30,
            ),
            feature_contract_dir=Path(
                os.getenv("SENSEL_SITE_FEATURE_CONTRACT_DIR", "/app/contracts")
            ),
        )

    @property
    def db_path(self) -> Path:
        return self.data_dir / "site.db"

    @property
    def export_dir(self) -> Path:
        return self.data_dir / "datasets"

    @property
    def trainer_inbox_dir(self) -> Path:
        return self.data_dir / "trainer-inbox"

    @property
    def mqtt_topic(self) -> str:
        return f"sensel/{self.tenant_id}/{self.site_id}/+/episode/v1"
