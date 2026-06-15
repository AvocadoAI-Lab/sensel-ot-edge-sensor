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
    require_tenant: bool = False
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
    register_retry_sec: int = 60
    verify_tls: bool = True


class LoggingConfig(BaseModel):
    level: str = "info"


class PolicySyncConfig(BaseModel):
    enabled: bool = True
    interval_sec: int = 60
    cache_path: str = "/app/data/ioc-cache.json"
    stamp_path: str = "/app/data/ioc-cache.stamp"
    feed_path_template: str = "/api/v1/feed/{tenant_id}/blacklist.json"
    feed_tenant_id: str = ""
    smb_intel_api_key: str = ""
    mqtt_enabled: bool = False
    mqtt_host: str = ""
    mqtt_port: int = 1883
    mqtt_topic_template: str = "sensel/{tenant_id}/policy/blacklist"
    mqtt_qos: int = 1
    mqtt_username: str = ""
    mqtt_password: str = ""
    detection_policy_enabled: bool = True
    detection_policy_path: str = "/app/data/detection-policy.json"
    detection_policy_stamp_path: str = "/app/data/detection-policy.stamp"
    detection_policy_mqtt_enabled: bool = True
    detection_policy_mqtt_topic_template: str = "sensel/{tenant_id}/policy/ot-detection"
    operational_mode_enabled: bool = True
    operational_mode_path: str = "/app/data/operational-mode.json"
    operational_mode_stamp_path: str = "/app/data/operational-mode.stamp"
    operational_mode_mqtt_enabled: bool = True
    operational_mode_mqtt_topic_template: str = "sensel/{tenant_id}/cmd/{sensor_id}/operational"
    learning_session_path: str = "/app/data/learning-session.json"
    baseline_profile_enabled: bool = True
    baseline_profile_path: str = "/app/data/baseline-profile.json"
    baseline_profile_stamp_path: str = "/app/data/baseline-profile.stamp"
    baseline_profile_mqtt_enabled: bool = True
    baseline_profile_mqtt_topic_template: str = "sensel/{tenant_id}/baseline/+"
    topology_override_enabled: bool = True
    topology_override_path: str = "/app/data/topology-asset-overrides.json"
    topology_override_stamp_path: str = "/app/data/topology-asset-overrides.stamp"
    topology_override_mqtt_enabled: bool = True
    topology_override_mqtt_topic_template: str = "sensel/{tenant_id}/cmd/{sensor_id}/topology/override"
    observe_tick_enabled: bool = True
    observe_tick_interval_sec: int = 60
    capture_live_path: str = "/app/data/assets/capture-live.json"
    live_observed_path: str = "/app/data/assets/baseline/live-observed.json"
    observe_tick_state_path: str = "/app/data/observe-tick-state.json"
    topology_snapshot_enabled: bool = True
    topology_snapshot_interval_sec: int = 120
    topology_snapshot_detect_interval_sec: int = 300
    topology_snapshot_state_path: str = "/app/data/topology-snapshot-state.json"


class SightingReportConfig(BaseModel):
    enabled: bool = True
    interval_sec: int = 10
    queue_path: str = "/app/data/sighting-queue.jsonl"
    events_offset_path: str = "/app/data/sighting-events.offset"
    ingest_path: str = "/api/v1/smb/sightings/ingest"
    source_system: str = "ndr"
    smb_intel_api_key: str = ""
    max_attempts: int = 10
    backoff_base_sec: int = 5
    backoff_max_sec: int = 300


class AppConfig(BaseModel):
    sensor: SensorIdentity
    sensel: SenselConfig
    northbound_mqtt: NorthboundMqttConfig = Field(default_factory=NorthboundMqttConfig)
    policy_sync: PolicySyncConfig = Field(default_factory=PolicySyncConfig)
    sighting_report: SightingReportConfig = Field(default_factory=SightingReportConfig)
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
    retry_raw = sensel_raw.get("retry") or {}
    sensel_raw["register_retry_sec"] = int(
        os.environ.get(
            "REGISTER_RETRY_SEC",
            sensel_raw.get(
                "register_retry_sec",
                retry_raw.get("backoff_sec", 60),
            ),
        )
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
    require_tenant_env = os.environ.get("MQTT_REQUIRE_TENANT", "").lower()
    if require_tenant_env in ("1", "true", "yes"):
        nb_raw["require_tenant"] = True

    policy_raw = expanded.get("policy_sync", {})
    enabled_env = os.environ.get("POLICY_SYNC_ENABLED", "").lower()
    if enabled_env in ("0", "false", "no"):
        policy_raw["enabled"] = False
    elif enabled_env in ("1", "true", "yes"):
        policy_raw["enabled"] = True
    policy_raw.setdefault(
        "interval_sec",
        int(os.environ.get("POLICY_SYNC_INTERVAL_SEC", policy_raw.get("interval_sec", 60))),
    )
    policy_raw.setdefault(
        "cache_path",
        os.environ.get("IOC_CACHE_PATH", "/app/data/ioc-cache.json"),
    )
    policy_raw.setdefault(
        "stamp_path",
        os.environ.get("IOC_CACHE_STAMP_PATH", "/app/data/ioc-cache.stamp"),
    )
    policy_raw.setdefault(
        "feed_path_template",
        os.environ.get(
            "POLICY_FEED_PATH_TEMPLATE",
            "/api/v1/feed/{tenant_id}/blacklist.json",
        ),
    )
    policy_raw.setdefault(
        "smb_intel_api_key",
        os.environ.get("SMB_INTEL_API_KEY", ""),
    )
    policy_raw.setdefault(
        "feed_tenant_id",
        os.environ.get("POLICY_SYNC_TENANT_ID", ""),
    )
    mqtt_enabled_env = os.environ.get("POLICY_SYNC_MQTT_ENABLED", "").lower()
    if mqtt_enabled_env in ("0", "false", "no"):
        policy_raw["mqtt_enabled"] = False
    elif mqtt_enabled_env in ("1", "true", "yes"):
        policy_raw["mqtt_enabled"] = True
    policy_raw.setdefault(
        "mqtt_host",
        os.environ.get(
            "POLICY_SYNC_MQTT_HOST",
            os.environ.get("CONTROL_PLANE_MQTT_HOST", policy_raw.get("mqtt_host", "")),
        ),
    )
    policy_raw.setdefault(
        "mqtt_port",
        int(
            os.environ.get(
                "POLICY_SYNC_MQTT_PORT",
                os.environ.get(
                    "CONTROL_PLANE_MQTT_PORT",
                    str(policy_raw.get("mqtt_port", 1883)),
                ),
            )
        ),
    )
    policy_raw.setdefault(
        "mqtt_topic_template",
        os.environ.get(
            "POLICY_SYNC_MQTT_TOPIC",
            policy_raw.get("mqtt_topic_template", "sensel/{tenant_id}/policy/blacklist"),
        ),
    )
    policy_raw.setdefault(
        "mqtt_qos",
        int(os.environ.get("POLICY_SYNC_MQTT_QOS", policy_raw.get("mqtt_qos", 1))),
    )
    policy_raw.setdefault(
        "mqtt_username",
        os.environ.get(
            "POLICY_SYNC_MQTT_USERNAME",
            os.environ.get("CONTROL_PLANE_MQTT_USERNAME", ""),
        ),
    )
    policy_raw.setdefault(
        "mqtt_password",
        os.environ.get(
            "POLICY_SYNC_MQTT_PASSWORD",
            os.environ.get("CONTROL_PLANE_MQTT_PASSWORD", ""),
        ),
    )
    det_enabled_env = os.environ.get("DETECTION_POLICY_ENABLED", "").lower()
    if det_enabled_env in ("0", "false", "no"):
        policy_raw["detection_policy_enabled"] = False
    elif det_enabled_env in ("1", "true", "yes"):
        policy_raw["detection_policy_enabled"] = True
    policy_raw.setdefault(
        "detection_policy_path",
        os.environ.get("DETECTION_POLICY_PATH", "/app/data/detection-policy.json"),
    )
    policy_raw.setdefault(
        "detection_policy_stamp_path",
        os.environ.get("DETECTION_POLICY_STAMP_PATH", "/app/data/detection-policy.stamp"),
    )
    det_mqtt_env = os.environ.get("DETECTION_POLICY_MQTT_ENABLED", "").lower()
    if det_mqtt_env in ("0", "false", "no"):
        policy_raw["detection_policy_mqtt_enabled"] = False
    elif det_mqtt_env in ("1", "true", "yes"):
        policy_raw["detection_policy_mqtt_enabled"] = True
    policy_raw.setdefault(
        "detection_policy_mqtt_topic_template",
        os.environ.get(
            "DETECTION_POLICY_MQTT_TOPIC",
            "sensel/{tenant_id}/policy/ot-detection",
        ),
    )
    op_enabled_env = os.environ.get("OPERATIONAL_MODE_ENABLED", "").lower()
    if op_enabled_env in ("0", "false", "no"):
        policy_raw["operational_mode_enabled"] = False
    elif op_enabled_env in ("1", "true", "yes"):
        policy_raw["operational_mode_enabled"] = True
    policy_raw.setdefault(
        "operational_mode_path",
        os.environ.get("OPERATIONAL_MODE_PATH", "/app/data/operational-mode.json"),
    )
    policy_raw.setdefault(
        "operational_mode_stamp_path",
        os.environ.get("OPERATIONAL_MODE_STAMP_PATH", "/app/data/operational-mode.stamp"),
    )
    op_mqtt_env = os.environ.get("OPERATIONAL_MODE_MQTT_ENABLED", "").lower()
    if op_mqtt_env in ("0", "false", "no"):
        policy_raw["operational_mode_mqtt_enabled"] = False
    elif op_mqtt_env in ("1", "true", "yes"):
        policy_raw["operational_mode_mqtt_enabled"] = True
    policy_raw.setdefault(
        "operational_mode_mqtt_topic_template",
        os.environ.get(
            "OPERATIONAL_MODE_MQTT_TOPIC",
            "sensel/{tenant_id}/cmd/{sensor_id}/operational",
        ),
    )
    policy_raw.setdefault(
        "learning_session_path",
        os.environ.get("LEARNING_SESSION_PATH", "/app/data/learning-session.json"),
    )
    policy_raw.setdefault(
        "baseline_profile_path",
        os.environ.get("BASELINE_PROFILE_PATH", "/app/data/baseline-profile.json"),
    )
    policy_raw.setdefault(
        "baseline_profile_stamp_path",
        os.environ.get("BASELINE_PROFILE_STAMP_PATH", "/app/data/baseline-profile.stamp"),
    )
    bprof_mqtt_env = os.environ.get("BASELINE_PROFILE_MQTT_ENABLED", "").lower()
    if bprof_mqtt_env in ("0", "false", "no"):
        policy_raw["baseline_profile_mqtt_enabled"] = False
    elif bprof_mqtt_env in ("1", "true", "yes"):
        policy_raw["baseline_profile_mqtt_enabled"] = True
    policy_raw.setdefault(
        "baseline_profile_mqtt_topic_template",
        os.environ.get("BASELINE_PROFILE_MQTT_TOPIC", "sensel/{tenant_id}/baseline/+"),
    )
    topo_env = os.environ.get("TOPOLOGY_OVERRIDE_ENABLED", "").lower()
    if topo_env in ("0", "false", "no"):
        policy_raw["topology_override_enabled"] = False
    elif topo_env in ("1", "true", "yes"):
        policy_raw["topology_override_enabled"] = True
    policy_raw.setdefault(
        "topology_override_path",
        os.environ.get("TOPOLOGY_OVERRIDE_PATH", "/app/data/topology-asset-overrides.json"),
    )
    policy_raw.setdefault(
        "topology_override_stamp_path",
        os.environ.get("TOPOLOGY_OVERRIDE_STAMP_PATH", "/app/data/topology-asset-overrides.stamp"),
    )
    topo_mqtt_env = os.environ.get("TOPOLOGY_OVERRIDE_MQTT_ENABLED", "").lower()
    if topo_mqtt_env in ("0", "false", "no"):
        policy_raw["topology_override_mqtt_enabled"] = False
    elif topo_mqtt_env in ("1", "true", "yes"):
        policy_raw["topology_override_mqtt_enabled"] = True
    policy_raw.setdefault(
        "topology_override_mqtt_topic_template",
        os.environ.get(
            "TOPOLOGY_OVERRIDE_MQTT_TOPIC",
            "sensel/{tenant_id}/cmd/{sensor_id}/topology/override",
        ),
    )
    observe_env = os.environ.get("OBSERVE_TICK_ENABLED", "").lower()
    if observe_env in ("0", "false", "no"):
        policy_raw["observe_tick_enabled"] = False
    elif observe_env in ("1", "true", "yes"):
        policy_raw["observe_tick_enabled"] = True
    policy_raw.setdefault(
        "observe_tick_interval_sec",
        int(os.environ.get("OBSERVE_TICK_INTERVAL_SEC", policy_raw.get("observe_tick_interval_sec", 60))),
    )
    policy_raw.setdefault(
        "capture_live_path",
        os.environ.get("CAPTURE_LIVE_PATH", "/app/data/assets/capture-live.json"),
    )
    policy_raw.setdefault(
        "live_observed_path",
        os.environ.get("LIVE_OBSERVED_PATH", "/app/data/assets/baseline/live-observed.json"),
    )
    policy_raw.setdefault(
        "observe_tick_state_path",
        os.environ.get("OBSERVE_TICK_STATE_PATH", "/app/data/observe-tick-state.json"),
    )
    topo_snap_env = os.environ.get("TOPOLOGY_SNAPSHOT_ENABLED", "").lower()
    if topo_snap_env in ("0", "false", "no"):
        policy_raw["topology_snapshot_enabled"] = False
    elif topo_snap_env in ("1", "true", "yes"):
        policy_raw["topology_snapshot_enabled"] = True
    policy_raw.setdefault(
        "topology_snapshot_interval_sec",
        int(
            os.environ.get(
                "TOPOLOGY_SNAPSHOT_INTERVAL_SEC",
                policy_raw.get("topology_snapshot_interval_sec", 120),
            )
        ),
    )
    policy_raw.setdefault(
        "topology_snapshot_detect_interval_sec",
        int(
            os.environ.get(
                "TOPOLOGY_SNAPSHOT_DETECT_INTERVAL_SEC",
                policy_raw.get("topology_snapshot_detect_interval_sec", 300),
            )
        ),
    )
    policy_raw.setdefault(
        "topology_snapshot_state_path",
        os.environ.get("TOPOLOGY_SNAPSHOT_STATE_PATH", "/app/data/topology-snapshot-state.json"),
    )

    sighting_raw = expanded.get("sighting_report", {})
    enabled_env = os.environ.get("SIGHTING_REPORT_ENABLED", "").lower()
    if enabled_env in ("0", "false", "no"):
        sighting_raw["enabled"] = False
    elif enabled_env in ("1", "true", "yes"):
        sighting_raw["enabled"] = True
    sighting_raw.setdefault(
        "interval_sec",
        int(os.environ.get("SIGHTING_REPORT_INTERVAL_SEC", sighting_raw.get("interval_sec", 10))),
    )
    sighting_raw.setdefault(
        "queue_path",
        os.environ.get("SIGHTING_QUEUE_PATH", "/app/data/sighting-queue.jsonl"),
    )
    sighting_raw.setdefault(
        "events_offset_path",
        os.environ.get("SIGHTING_EVENTS_OFFSET", "/app/data/sighting-events.offset"),
    )
    sighting_raw.setdefault(
        "ingest_path",
        os.environ.get("SIGHTING_INGEST_PATH", "/api/v1/smb/sightings/ingest"),
    )
    sighting_raw.setdefault(
        "source_system",
        os.environ.get("SIGHTING_SOURCE_SYSTEM", sighting_raw.get("source_system", "ndr")),
    )
    sighting_raw.setdefault(
        "smb_intel_api_key",
        os.environ.get("SMB_INTEL_API_KEY", ""),
    )
    sighting_raw.setdefault(
        "max_attempts",
        int(os.environ.get("SIGHTING_MAX_ATTEMPTS", sighting_raw.get("max_attempts", 10))),
    )

    config = AppConfig(
            sensor=SensorIdentity(**sensor_raw),
            sensel=SenselConfig(**sensel_raw),
            northbound_mqtt=NorthboundMqttConfig(**nb_raw),
            policy_sync=PolicySyncConfig(**policy_raw),
            sighting_report=SightingReportConfig(**sighting_raw),
            logging=LoggingConfig(**expanded.get("logging", {})),
        )
    return apply_platform_overlay(config)
