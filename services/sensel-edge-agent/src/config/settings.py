"""Load sensor.yaml with ${ENV} expansion and pydantic validation."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from src.config.platform_overlay import apply_platform_overlay


_ENV_PATTERN = re.compile(r"\$\{([^}]+)\}")


def _expand_env(value: Any) -> Any:
    if isinstance(value, str):
        return _ENV_PATTERN.sub(
            lambda m: os.environ.get(m.group(1), m.group(0)), value
        )
    if isinstance(value, dict):
        return {k: _expand_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand_env(v) for v in value]
    return value


class SensorIdentity(BaseModel):
    id: str
    site_id: str
    type: str = "ot-edge-sensor"
    hardware: str = "ubuntu"
    software_version: str = "0.1.0"
    capabilities: list[str] = Field(default_factory=list)


class UploadPaths(BaseModel):
    events_path: str = "/api/v1/ot/security-events"
    telemetry_path: str = "/api/v1/ot/telemetry"
    health_path: str = "/api/v1/edge-sensors/health"
    register_path: str = "/api/v1/edge-sensors/register"


class RetryConfig(BaseModel):
    max_attempts: int = 10
    backoff_sec: int = 30


class BufferConfig(BaseModel):
    max_events: int = 1000
    db_path: str = "/app/data/event-buffer.db"


class EventsConfig(BaseModel):
    watch_path: str = "/app/data/assets/security-events.jsonl"
    offset_path: str = "/app/data/security-events.offset"


class NorthboundMqttConfig(BaseModel):
    enabled: bool = False
    host: str = ""
    port: int = 1883
    tenant_id: str = "default"
    username: str = ""
    password: str = ""
    qos_events: int = 1
    tls: bool = False


class SenselConfig(BaseModel):
    api_url: str
    api_key: str
    registration_token: str = ""
    upload: UploadPaths = Field(default_factory=UploadPaths)
    retry: RetryConfig = Field(default_factory=RetryConfig)
    buffer: BufferConfig = Field(default_factory=BufferConfig)
    events: EventsConfig = Field(default_factory=EventsConfig)
    health_interval_sec: int = 30
    verify_tls: bool = True


class LoggingConfig(BaseModel):
    level: str = "info"


class AppConfig(BaseModel):
    sensor: SensorIdentity
    sensel: SenselConfig
    northbound_mqtt: NorthboundMqttConfig = Field(default_factory=NorthboundMqttConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)


def _default_config_path() -> Path:
    for candidate in (
        os.environ.get("SENSOR_CONFIG_PATH"),
        "/app/config/sensor.yaml",
        "config/sensor.yaml",
        "config/sensor.yaml.example",
    ):
        if candidate and Path(candidate).is_file():
            return Path(candidate)
    return Path("config/sensor.yaml.example")


def load_config(path: Path | None = None) -> AppConfig:
    config_path = path or _default_config_path()
    if not config_path.is_file():
        raise FileNotFoundError(f"Sensor config not found: {config_path}")

    raw = yaml.safe_load(config_path.read_text()) or {}
    expanded = _expand_env(raw)

    sensor_raw = expanded.get("sensor", {})
    sensel_raw = expanded.get("sensel", {})
    capture_raw = expanded.get("capture", {})

    sensel_raw.setdefault("api_url", os.environ.get("SENSEL_API_URL", ""))
    sensel_raw.setdefault("api_key", os.environ.get("SENSEL_API_KEY", ""))
    sensel_raw.setdefault("registration_token", os.environ.get("OT_REGISTRATION_TOKEN", ""))
    events_raw = sensel_raw.get("events", {})
    events_raw.setdefault(
        "watch_path",
        os.environ.get("SECURITY_EVENTS_PATH", "/app/data/assets/security-events.jsonl"),
    )
    events_raw.setdefault(
        "offset_path",
        os.environ.get("SECURITY_EVENTS_OFFSET", "/app/data/security-events.offset"),
    )
    sensel_raw["events"] = events_raw
    sensel_raw["health_interval_sec"] = int(
        capture_raw.get("health_check_interval_sec", 30)
    )
    if os.environ.get("SENSEL_VERIFY_TLS", "").lower() in ("0", "false", "no"):
        sensel_raw["verify_tls"] = False

    sensor_raw.setdefault("id", os.environ.get("SENSOR_ID", "ot-edge-001"))
    sensor_raw.setdefault("site_id", os.environ.get("SITE_ID", "factory-lab-001"))

    nb_raw = expanded.get("northbound_mqtt", {})
    if os.environ.get("CONTROL_PLANE_MQTT_HOST"):
        nb_raw["host"] = os.environ.get("CONTROL_PLANE_MQTT_HOST", "")
    else:
        nb_raw.setdefault("host", "")
    nb_raw["port"] = int(os.environ.get("CONTROL_PLANE_MQTT_PORT", str(nb_raw.get("port", 1883))))
    nb_raw.setdefault("tenant_id", os.environ.get("MQTT_TENANT_ID", "default"))
    nb_raw.setdefault("username", os.environ.get("CONTROL_PLANE_MQTT_USERNAME", ""))
    nb_raw.setdefault("password", os.environ.get("CONTROL_PLANE_MQTT_PASSWORD", ""))
    enabled_env = os.environ.get("NORTHBOUND_MQTT_ENABLED", "").lower()
    if enabled_env in ("1", "true", "yes"):
        nb_raw["enabled"] = True
    elif enabled_env in ("0", "false", "no"):
        nb_raw["enabled"] = False
    elif nb_raw.get("host"):
        nb_raw["enabled"] = True

    return apply_platform_overlay(
        AppConfig(
            sensor=SensorIdentity(**sensor_raw),
            sensel=SenselConfig(**sensel_raw),
            northbound_mqtt=NorthboundMqttConfig(**nb_raw),
            logging=LoggingConfig(**expanded.get("logging", {})),
        )
    )
