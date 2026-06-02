"""Load sensor.yaml with ${ENV} expansion."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field


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
    software_version: str = "0.1.0"


class CaptureConfig(BaseModel):
    interface: str = "eth1"
    promiscuous: bool = True
    bpf_filter: str = ""
    timestamping: bool = True
    health_check_interval_sec: int = 30
    stats_log_interval_sec: int = 10


class FeaturesMqttConfig(BaseModel):
    host: str = "local-mqtt"
    port: int = 1883
    topic_prefix: str = "sensel/ot"
    edgex_device_name: str = "packet-sensor-features"
    edgex_data_topic: str = ""


class FeaturesConfig(BaseModel):
    window_sec: int = 60
    mqtt: FeaturesMqttConfig = Field(default_factory=FeaturesMqttConfig)
    assets_dir: str = "/app/data/assets"


class DetectionConfig(BaseModel):
    policy_file: str = "/app/config/policy/baseline.json"
    rules_enabled: list[str] = Field(default_factory=list)


class PcapConfig(BaseModel):
    ring_buffer_path: str = "/app/data/pcap"
    retention_minutes: int = 120
    max_disk_mb: int = 2048
    ring_buffer_max_packets: int = 5000
    evidence_before_sec: int = 60
    evidence_after_sec: int = 60


class LoggingConfig(BaseModel):
    level: str = "info"


class AppConfig(BaseModel):
    sensor: SensorIdentity
    capture: CaptureConfig = Field(default_factory=CaptureConfig)
    features: FeaturesConfig = Field(default_factory=FeaturesConfig)
    detection: DetectionConfig = Field(default_factory=DetectionConfig)
    pcap: PcapConfig = Field(default_factory=PcapConfig)
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
    capture_raw = expanded.get("capture", {})
    features_raw = expanded.get("features", {})
    detection_raw = expanded.get("detection", {})

    sensor_raw.setdefault("id", os.environ.get("SENSOR_ID", "ot-edge-001"))
    sensor_raw.setdefault("site_id", os.environ.get("SITE_ID", "factory-lab-001"))
    capture_raw.setdefault("interface", os.environ.get("CAPTURE_INTERFACE", "eth1"))
    capture_raw.setdefault("bpf_filter", os.environ.get("CAPTURE_BPF_FILTER", ""))

    mqtt_raw = features_raw.get("mqtt", {})
    mqtt_raw.setdefault("host", os.environ.get("LOCAL_MQTT_HOST", "local-mqtt"))
    mqtt_raw.setdefault("port", int(os.environ.get("LOCAL_MQTT_PORT", "1883")))
    mqtt_raw.setdefault(
        "edgex_device_name",
        os.environ.get("EDGEX_FEATURE_DEVICE_NAME", "packet-sensor-features"),
    )
    mqtt_raw.setdefault(
        "edgex_data_topic",
        os.environ.get("EDGEX_FEATURE_DATA_TOPIC", ""),
    )
    features_raw["mqtt"] = mqtt_raw
    features_raw.setdefault("assets_dir", os.environ.get("ASSETS_DIR", "/app/data/assets"))

    detection_raw.setdefault(
        "policy_file",
        os.environ.get("POLICY_FILE", "/app/config/policy/baseline.json"),
    )

    return AppConfig(
        sensor=SensorIdentity(**sensor_raw),
        capture=CaptureConfig(**capture_raw),
        features=FeaturesConfig(**features_raw),
        detection=DetectionConfig(**detection_raw),
        pcap=PcapConfig(**expanded.get("pcap", {})),
        logging=LoggingConfig(**expanded.get("logging", {})),
    )
