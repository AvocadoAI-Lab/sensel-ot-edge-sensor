"""Load sensor.yaml with ${ENV} expansion."""

from __future__ import annotations

import json
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
    tenant_id: str = "default"
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
    contract_id: str = "ot-window-v1"
    contract_path: str = "/app/config/model/feature-contract.ot-window-v1.json"


class ModelAdapterConfig(BaseModel):
    enabled: bool = False
    model_path: str = ""
    model_version: str = "unconfigured"
    artifact_sha256: str = ""
    calibration_path: str = "/app/config/model/calibration.json"
    threshold: float = Field(default=0.5, ge=0.0, le=1.0)
    output_index: int = Field(default=0, ge=0)
    anomaly_class_index: int = Field(default=1, ge=0)
    class_labels: list[str] = Field(default_factory=lambda: ["normal", "anomaly"])


class InferenceConfig(BaseModel):
    enabled: bool = False
    episode_output_path: str = "/app/data/assets/trust-episodes.jsonl"
    runtime_status_path: str = "/app/data/assets/model-runtime.json"
    emit_decisions: list[str] = Field(default_factory=lambda: ["alert"])
    fusion_policy_version: str = "fusion-v1"
    fusion_alert_threshold: float = Field(default=0.75, ge=0.0, le=1.0)
    fusion_maximum_weight: float = Field(default=0.7, ge=0.0, le=1.0)
    isolation_forest: ModelAdapterConfig = Field(default_factory=ModelAdapterConfig)
    xgboost: ModelAdapterConfig = Field(
        default_factory=lambda: ModelAdapterConfig(output_index=1)
    )
    tiny_lstm: ModelAdapterConfig = Field(default_factory=ModelAdapterConfig)


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


class SnortSourceConfig(BaseModel):
    """External Snort 3 alert_json bridge (opt-in, off by default)."""

    enabled: bool = False
    alert_json_path: str = "/app/data/snort/alert_json.txt"
    offset_path: str = "/app/data/assets/.snort-source.offset"
    poll_interval_sec: int = 2


class SuricataSourceConfig(BaseModel):
    """External Suricata EVE JSON bridge (opt-in, off by default)."""

    enabled: bool = False
    eve_json_path: str = "/app/data/suricata/eve.json"
    offset_path: str = "/app/data/assets/.suricata-source.offset"
    poll_interval_sec: int = 2


class LoggingConfig(BaseModel):
    level: str = "info"


class AppConfig(BaseModel):
    sensor: SensorIdentity
    capture: CaptureConfig = Field(default_factory=CaptureConfig)
    features: FeaturesConfig = Field(default_factory=FeaturesConfig)
    inference: InferenceConfig = Field(default_factory=InferenceConfig)
    detection: DetectionConfig = Field(default_factory=DetectionConfig)
    ioc: IocConfig = Field(default_factory=IocConfig)
    snort_source: SnortSourceConfig = Field(default_factory=SnortSourceConfig)
    suricata_source: SuricataSourceConfig = Field(default_factory=SuricataSourceConfig)
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

    from src.config.sensor_id_resolve import load_platform_sensor_id, resolve_sensor_id

    sensor_raw["id"] = resolve_sensor_id(
        env_id=os.environ.get("SENSOR_ID", ""),
        yaml_id=str(sensor_raw.get("id") or ""),
        platform_id=load_platform_sensor_id(),
    )
    sensor_raw.setdefault("site_id", os.environ.get("SITE_ID", "factory-lab-001"))
    sensor_raw.setdefault("tenant_id", os.environ.get("MQTT_TENANT_ID", "default"))
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
    features_raw.setdefault(
        "contract_id",
        os.environ.get("FEATURE_CONTRACT_ID", "ot-window-v1"),
    )

    inference_raw = expanded.get("inference", {})
    inference_enabled = os.environ.get("MODEL_INFERENCE_ENABLED", "").strip().lower()
    if inference_enabled in ("1", "true", "yes", "on"):
        inference_raw["enabled"] = True
    elif inference_enabled in ("0", "false", "no", "off"):
        inference_raw["enabled"] = False
    inference_raw.setdefault(
        "episode_output_path",
        os.environ.get(
            "TRUST_EPISODE_OUTPUT_PATH",
            "/app/data/assets/trust-episodes.jsonl",
        ),
    )
    inference_raw.setdefault(
        "runtime_status_path",
        os.environ.get(
            "MODEL_RUNTIME_STATUS_PATH",
            "/app/data/assets/model-runtime.json",
        ),
    )
    inference_raw.setdefault(
        "fusion_policy_version",
        os.environ.get("FUSION_POLICY_VERSION", "fusion-v1"),
    )
    inference_raw.setdefault(
        "fusion_alert_threshold",
        float(os.environ.get("FUSION_ALERT_THRESHOLD", "0.75")),
    )
    inference_raw.setdefault(
        "fusion_maximum_weight",
        float(os.environ.get("FUSION_MAXIMUM_WEIGHT", "0.7")),
    )

    def _model_config(name: str, prefix: str, *, output_index: int = 0) -> dict[str, Any]:
        model_raw = inference_raw.get(name, {})
        deployment_path = Path(
            os.environ.get(
                f"{prefix}_DEPLOYMENT_MANIFEST_PATH",
                f"/app/data/models/{name}/current/deployment.json",
            )
        )
        if deployment_path.is_file() and not deployment_path.is_symlink():
            deployment = json.loads(deployment_path.read_text(encoding="utf-8"))
            if (
                deployment.get("schema_version")
                != "sensel.edge.verified-model-deployment.v1"
                or deployment.get("adapter") != name
                or deployment.get("model_filename") != "model.onnx"
                or deployment.get("feature_contract_id") != features_raw["contract_id"]
            ):
                raise ValueError(f"{name} verified deployment manifest is invalid")
            model_raw.update(
                {
                    "enabled": True,
                    "model_path": str(deployment_path.parent / "model.onnx"),
                    "model_version": str(deployment["model_version"]),
                    "artifact_sha256": str(deployment["artifact_sha256"]),
                    "output_index": int(deployment["output_index"]),
                    "anomaly_class_index": int(deployment["anomaly_class_index"]),
                }
            )
        enabled = os.environ.get(f"{prefix}_ENABLED", "").strip().lower()
        if enabled in ("1", "true", "yes", "on"):
            model_raw["enabled"] = True
        elif enabled in ("0", "false", "no", "off"):
            model_raw["enabled"] = False
        model_raw.setdefault("model_path", os.environ.get(f"{prefix}_MODEL_PATH", ""))
        model_raw.setdefault(
            "model_version",
            os.environ.get(f"{prefix}_MODEL_VERSION", "unconfigured"),
        )
        model_raw.setdefault(
            "artifact_sha256",
            os.environ.get(f"{prefix}_MODEL_SHA256", ""),
        )
        model_raw.setdefault(
            "calibration_path",
            os.environ.get(
                f"{prefix}_CALIBRATION_PATH",
                "/app/config/model/calibration.json",
            ),
        )
        model_raw.setdefault(
            "threshold",
            float(os.environ.get(f"{prefix}_THRESHOLD", "0.5")),
        )
        model_raw.setdefault(
            "output_index",
            int(os.environ.get(f"{prefix}_OUTPUT_INDEX", str(output_index))),
        )
        model_raw.setdefault(
            "anomaly_class_index",
            int(os.environ.get(f"{prefix}_ANOMALY_CLASS_INDEX", "1")),
        )
        return model_raw

    inference_raw["isolation_forest"] = _model_config(
        "isolation_forest", "IF", output_index=0
    )
    inference_raw["xgboost"] = _model_config("xgboost", "XGB", output_index=1)
    inference_raw["tiny_lstm"] = _model_config("tiny_lstm", "LSTM", output_index=0)
    features_raw.setdefault(
        "contract_path",
        os.environ.get(
            "FEATURE_CONTRACT_PATH",
            "/app/config/model/feature-contract.ot-window-v1.json",
        ),
    )

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

    snort_raw = expanded.get("snort_source", {})
    snort_enabled_env = os.environ.get("SNORT_SOURCE_ENABLED", "").lower()
    if snort_enabled_env in ("1", "true", "yes"):
        snort_raw["enabled"] = True
    elif snort_enabled_env in ("0", "false", "no"):
        snort_raw["enabled"] = False
    snort_raw.setdefault(
        "alert_json_path",
        os.environ.get("SNORT_ALERT_JSON_PATH", "/app/data/snort/alert_json.txt"),
    )
    snort_raw.setdefault(
        "offset_path",
        os.environ.get("SNORT_SOURCE_OFFSET_PATH", "/app/data/assets/.snort-source.offset"),
    )
    snort_raw.setdefault(
        "poll_interval_sec",
        int(os.environ.get("SNORT_SOURCE_POLL_SEC", snort_raw.get("poll_interval_sec", 2))),
    )

    suricata_raw = expanded.get("suricata_source", {})
    suricata_enabled_env = os.environ.get("SURICATA_SOURCE_ENABLED", "").lower()
    if suricata_enabled_env in ("1", "true", "yes"):
        suricata_raw["enabled"] = True
    elif suricata_enabled_env in ("0", "false", "no"):
        suricata_raw["enabled"] = False
    suricata_raw.setdefault(
        "eve_json_path",
        os.environ.get("SURICATA_EVE_JSON_PATH", "/app/data/suricata/eve.json"),
    )
    suricata_raw.setdefault(
        "offset_path",
        os.environ.get("SURICATA_SOURCE_OFFSET_PATH", "/app/data/assets/.suricata-source.offset"),
    )
    suricata_raw.setdefault(
        "poll_interval_sec",
        int(os.environ.get("SURICATA_SOURCE_POLL_SEC", suricata_raw.get("poll_interval_sec", 2))),
    )

    return AppConfig(
        sensor=SensorIdentity(**sensor_raw),
        capture=CaptureConfig(**capture_raw),
        features=FeaturesConfig(**features_raw),
        inference=InferenceConfig(**inference_raw),
        detection=DetectionConfig(**detection_raw),
        ioc=IocConfig(**ioc_raw),
        snort_source=SnortSourceConfig(**snort_raw),
        suricata_source=SuricataSourceConfig(**suricata_raw),
        logging=LoggingConfig(**expanded.get("logging", {})),
    )
