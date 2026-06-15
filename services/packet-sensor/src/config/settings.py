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
    backend: str = "scapy"
    xdp_mode: str = "native"
    xdp_queue_id: int = 0
    af_xdp_frame_size: int = 2048
    af_xdp_num_frames: int = 4096
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
    policy_path: str = "/app/data/agent/detection-policy.json"
    policy_stamp_path: str = "/app/data/agent/detection-policy.stamp"
    reload_check_sec: int = 5
    operational_mode_path: str = "/app/data/agent/operational-mode.json"
    operational_mode_stamp_path: str = "/app/data/agent/operational-mode.stamp"
    operational_mode_reload_sec: int = 5
    baseline_profile_path: str = "/app/data/agent/baseline-profile.json"
    baseline_profile_stamp_path: str = "/app/data/agent/baseline-profile.stamp"


class IocConfig(BaseModel):
    enabled: bool = True
    cache_path: str = "/app/data/agent/ioc-cache.json"
    stamp_path: str = "/app/data/agent/ioc-cache.stamp"
    cooldown_sec: int = 300
    reload_check_sec: int = 5


class LoggingConfig(BaseModel):
    level: str = "info"


class AppConfig(BaseModel):
    sensor: SensorIdentity
    capture: CaptureConfig = Field(default_factory=CaptureConfig)
    features: FeaturesConfig = Field(default_factory=FeaturesConfig)
    detection: DetectionConfig = Field(default_factory=DetectionConfig)
    ioc: IocConfig = Field(default_factory=IocConfig)
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
    capture_raw.setdefault(
        "backend",
        os.environ.get("CAPTURE_BACKEND", capture_raw.get("backend", "scapy")).lower(),
    )
    capture_raw.setdefault(
        "xdp_mode",
        os.environ.get("XDP_MODE", capture_raw.get("xdp_mode", "native")).lower(),
    )
    capture_raw.setdefault(
        "xdp_queue_id",
        int(os.environ.get("XDP_QUEUE_ID", capture_raw.get("xdp_queue_id", 0))),
    )
    capture_raw.setdefault(
        "af_xdp_frame_size",
        int(os.environ.get("AF_XDP_FRAME_SIZE", capture_raw.get("af_xdp_frame_size", 2048))),
    )
    capture_raw.setdefault(
        "af_xdp_num_frames",
        int(os.environ.get("AF_XDP_NUM_FRAMES", capture_raw.get("af_xdp_num_frames", 4096))),
    )

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
    detection_raw.setdefault(
        "policy_path",
        os.environ.get("DETECTION_POLICY_PATH", "/app/data/agent/detection-policy.json"),
    )
    detection_raw.setdefault(
        "policy_stamp_path",
        os.environ.get("DETECTION_POLICY_STAMP_PATH", "/app/data/agent/detection-policy.stamp"),
    )
    detection_raw.setdefault(
        "reload_check_sec",
        int(os.environ.get("DETECTION_POLICY_RELOAD_SEC", detection_raw.get("reload_check_sec", 5))),
    )
    detection_raw.setdefault(
        "operational_mode_path",
        os.environ.get("OPERATIONAL_MODE_PATH", "/app/data/agent/operational-mode.json"),
    )
    detection_raw.setdefault(
        "operational_mode_stamp_path",
        os.environ.get("OPERATIONAL_MODE_STAMP_PATH", "/app/data/agent/operational-mode.stamp"),
    )
    detection_raw.setdefault(
        "operational_mode_reload_sec",
        int(os.environ.get("OPERATIONAL_MODE_RELOAD_SEC", detection_raw.get("operational_mode_reload_sec", 5))),
    )
    detection_raw.setdefault(
        "baseline_profile_path",
        os.environ.get("BASELINE_PROFILE_PATH", "/app/data/agent/baseline-profile.json"),
    )
    detection_raw.setdefault(
        "baseline_profile_stamp_path",
        os.environ.get("BASELINE_PROFILE_STAMP_PATH", "/app/data/agent/baseline-profile.stamp"),
    )

    ioc_raw = expanded.get("ioc", {})
    enabled_env = os.environ.get("IOC_MATCH_ENABLED", "").lower()
    if enabled_env in ("0", "false", "no"):
        ioc_raw["enabled"] = False
    elif enabled_env in ("1", "true", "yes"):
        ioc_raw["enabled"] = True
    ioc_raw.setdefault(
        "cache_path",
        os.environ.get("IOC_CACHE_PATH", "/app/data/agent/ioc-cache.json"),
    )
    ioc_raw.setdefault(
        "stamp_path",
        os.environ.get("IOC_CACHE_STAMP_PATH", "/app/data/agent/ioc-cache.stamp"),
    )
    ioc_raw.setdefault(
        "cooldown_sec",
        int(os.environ.get("IOC_MATCH_COOLDOWN_SEC", ioc_raw.get("cooldown_sec", 300))),
    )
    ioc_raw.setdefault(
        "reload_check_sec",
        int(os.environ.get("IOC_CACHE_RELOAD_SEC", ioc_raw.get("reload_check_sec", 5))),
    )

    return AppConfig(
        sensor=SensorIdentity(**sensor_raw),
        capture=CaptureConfig(**capture_raw),
        features=FeaturesConfig(**features_raw),
        detection=DetectionConfig(**detection_raw),
        ioc=IocConfig(**ioc_raw),
        logging=LoggingConfig(**expanded.get("logging", {})),
    )
