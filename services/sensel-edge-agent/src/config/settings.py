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
    # Optional extra sources: external engine events (off unless the matching
    # packet-sensor bridge is enabled and writing these files).
    snort_watch_path: str = "/app/data/assets/snort-events.jsonl"
    snort_offset_path: str = "/app/data/snort-events.offset"
    suricata_watch_path: str = "/app/data/assets/suricata-events.jsonl"
    suricata_offset_path: str = "/app/data/suricata-events.offset"


class EpisodesConfig(BaseModel):
    watch_path: str = "/app/data/assets/trust-episodes.jsonl"
    offset_path: str = "/app/data/trust-episodes.offset"
    spool_db_path: str = "/app/data/trust-episode-spool.db"
    max_episodes: int = Field(default=2000, ge=1)


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
    tls_ca_path: str = ""
    tls_cert_path: str = ""
    tls_key_path: str = ""
    tls_insecure: bool = False
    wire_mode: str = "json"
    protobuf_failure_threshold: int = Field(default=3, ge=1)
    rollback_state_path: str = "/app/data/northbound-wire-state.json"
    rollback_reset: bool = False


class EdgeXDeviceManagementConfig(BaseModel):
    """EdgeX is the site device registry; passive capture remains independent."""

    enabled: bool = True
    metadata_url: str = "http://edgex-core-metadata:59881"
    request_timeout_sec: float = Field(default=5.0, gt=0)
    inventory_interval_sec: int = Field(default=60, ge=5)
    gateway_id: str = ""
    live_observed_path: str = "/app/data/assets/baseline/live-observed.json"
    identity_inventory_path: str = "/app/data/asset-inventory.json"
    inventory_state_path: str = "/app/data/edgex-inventory-state.json"
    desired_state_path: str = "/app/data/edgex-desired-state.json"
    reconcile_state_path: str = "/app/data/edgex-reconcile-state.json"
    observed_spool_db_path: str = "/app/data/edgex-observed-spool.db"
    desired_mqtt_enabled: bool = True
    max_pending_reports: int = Field(default=2000, ge=1)
    sampling_profiles: dict[str, str] = Field(
        default_factory=lambda: {
            "disabled": "",
            "slow": "60s",
            "standard": "10s",
            "fast": "1s",
        }
    )


class SenselConfig(BaseModel):
    api_url: str
    api_key: str
    registration_token: str = ""
    upload: UploadPaths = Field(default_factory=UploadPaths)
    retry: RetryConfig = Field(default_factory=RetryConfig)
    buffer: BufferConfig = Field(default_factory=BufferConfig)
    events: EventsConfig = Field(default_factory=EventsConfig)
    episodes: EpisodesConfig = Field(default_factory=EpisodesConfig)
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
    # OT protection-center IDS rule bundles (P2/EPIC B edge apply): pull signed
    # snort/suricata rules, reload-healthcheck, rollback on failure.
    ids_rule_enabled: bool = True
    ids_rule_interval_sec: int = 300
    ids_rule_engines: list[str] = Field(default_factory=lambda: ["suricata"])
    ids_rule_feed_path_template: str = "/api/v1/feed/{tenant_id}/ot-rules.rules"
    ids_rule_feed_profile: str = "ot_ids"
    ids_rule_target_dir: str = "/app/data/ids-rules"
    ids_rule_status_path: str = "/app/data/ids-rule-status.json"
    ids_rule_signing_secret: str = ""
    ids_rule_reload_cmd: str = ""
    ids_rule_healthcheck_cmd: str = ""
    ids_rule_cmd_timeout_sec: int = 30
    ids_rule_mqtt_enabled: bool = True
    ids_rule_mqtt_topic_template: str = "sensel/{tenant_id}/policy/ids-rules-+"
    # OT protection-center managed black/white lists (P1/EPIC C edge apply).
    listfile_enabled: bool = True
    listfile_interval_sec: int = 300
    listfile_feed_path_template: str = "/api/v1/feed/{tenant_id}/listfiles.json"
    listfile_cache_path: str = "/app/data/managed-listfiles.json"
    listfile_stamp_path: str = "/app/data/managed-listfiles.stamp"
    listfile_mqtt_enabled: bool = True
    listfile_mqtt_topic_template: str = "sensel/{tenant_id}/policy/listfiles"
    # Policy apply ACK/NACK northbound report: MQTT primary, HTTP fallback when
    # the bus is down so the Control Plane distribution log still converges.
    policy_ack_http_fallback_enabled: bool = True
    policy_ack_ingest_path: str = "/api/v1/internal/ot-security/policy-ack"
    policy_ack_ingest_secret: str = ""
    # Edge-side suricata-update execution + northbound report (G10). Disabled by
    # default; when enabled the agent periodically runs `suricata-update`, applies
    # the refreshed ruleset (reusing the IDS reload/health-check), and reports the
    # outcome to the Control Plane autoupdate-report ingest endpoint.
    suricata_update_enabled: bool = False
    suricata_update_interval_sec: int = 86400
    suricata_update_cmd: str = "suricata-update"
    suricata_update_status_path: str = "/app/data/suricata-update-status.json"
    suricata_update_cmd_timeout_sec: int = 300
    autoupdate_report_ingest_path: str = "/api/v1/internal/ot-security/autoupdate-report"


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
    # External-engine CTI sighting bridge (opt-in). Snort/Suricata alerts whose
    # SID falls within the configured CTI range are treated as CTI-rule hits and
    # reported as sightings. Disabled by default (max=0) so no external-engine
    # sightings are emitted unless a CTI SID range is configured. The SID range
    # is shared across engines.
    snort_sighting_enabled: bool = False
    snort_cti_sid_min: int = 0
    snort_cti_sid_max: int = 0
    snort_events_offset_path: str = "/app/data/sighting-snort-events.offset"
    suricata_sighting_enabled: bool = False
    suricata_events_offset_path: str = "/app/data/sighting-suricata-events.offset"


class AppConfig(BaseModel):
    sensor: SensorIdentity
    sensel: SenselConfig
    northbound_mqtt: NorthboundMqttConfig = Field(default_factory=NorthboundMqttConfig)
    edgex_device_management: EdgeXDeviceManagementConfig = Field(
        default_factory=EdgeXDeviceManagementConfig
    )
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
    events_raw.setdefault(
        "snort_watch_path",
        os.environ.get("SNORT_EVENTS_PATH", "/app/data/assets/snort-events.jsonl"),
    )
    events_raw.setdefault(
        "snort_offset_path",
        os.environ.get("SNORT_EVENTS_OFFSET", "/app/data/snort-events.offset"),
    )
    events_raw.setdefault(
        "suricata_watch_path",
        os.environ.get("SURICATA_EVENTS_PATH", "/app/data/assets/suricata-events.jsonl"),
    )
    events_raw.setdefault(
        "suricata_offset_path",
        os.environ.get("SURICATA_EVENTS_OFFSET", "/app/data/suricata-events.offset"),
    )
    sensel_raw["events"] = events_raw
    episodes_raw = sensel_raw.get("episodes", {})
    episodes_raw.setdefault(
        "watch_path",
        os.environ.get(
            "TRUST_EPISODES_PATH",
            "/app/data/assets/trust-episodes.jsonl",
        ),
    )
    episodes_raw.setdefault(
        "offset_path",
        os.environ.get(
            "TRUST_EPISODES_OFFSET",
            "/app/data/trust-episodes.offset",
        ),
    )
    episodes_raw.setdefault(
        "spool_db_path",
        os.environ.get(
            "TRUST_EPISODE_SPOOL_DB",
            "/app/data/trust-episode-spool.db",
        ),
    )
    episodes_raw.setdefault(
        "max_episodes",
        int(os.environ.get("TRUST_EPISODE_SPOOL_MAX", "2000")),
    )
    sensel_raw["episodes"] = episodes_raw
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

    from src.config.sensor_id_resolve import load_platform_sensor_id, resolve_sensor_id

    sensor_raw["id"] = resolve_sensor_id(
        env_id=os.environ.get("SENSOR_ID", ""),
        yaml_id=str(sensor_raw.get("id") or ""),
        platform_id=load_platform_sensor_id(),
    )
    sensor_raw.setdefault("site_id", os.environ.get("SITE_ID", "factory-lab-001"))
    # Resolve hardware label: explicit yaml/env wins; otherwise auto-detect the
    # real platform (pi4 / ubuntu / ubuntu-docker / …) so the platform sensor
    # table is accurate instead of the static "ubuntu" default.
    if not sensor_raw.get("hardware"):
        env_hardware = (os.environ.get("SENSOR_HARDWARE") or "").strip()
        if env_hardware:
            sensor_raw["hardware"] = env_hardware
        else:
            from src.config.platform_detect import detect_hardware

            sensor_raw["hardware"] = detect_hardware()

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
    tls_env = os.environ.get("CONTROL_PLANE_MQTT_TLS", "").lower()
    if tls_env in ("1", "true", "yes", "on"):
        nb_raw["tls"] = True
    elif tls_env in ("0", "false", "no", "off"):
        nb_raw["tls"] = False
    nb_raw.setdefault(
        "tls_ca_path",
        os.environ.get("CONTROL_PLANE_MQTT_CA_PATH", ""),
    )
    nb_raw.setdefault(
        "tls_cert_path",
        os.environ.get("CONTROL_PLANE_MQTT_CERT_PATH", ""),
    )
    nb_raw.setdefault(
        "tls_key_path",
        os.environ.get("CONTROL_PLANE_MQTT_KEY_PATH", ""),
    )
    insecure_env = os.environ.get("CONTROL_PLANE_MQTT_TLS_INSECURE", "").lower()
    if insecure_env in ("1", "true", "yes", "on"):
        nb_raw["tls_insecure"] = True
    nb_raw["wire_mode"] = os.environ.get(
        "NORTHBOUND_WIRE_MODE",
        str(nb_raw.get("wire_mode", "json")),
    ).strip().lower()
    if nb_raw["wire_mode"] not in {"json", "dual", "protobuf"}:
        raise ValueError("NORTHBOUND_WIRE_MODE must be json, dual, or protobuf")
    nb_raw["protobuf_failure_threshold"] = int(
        os.environ.get(
            "NORTHBOUND_PROTOBUF_FAILURE_THRESHOLD",
            str(nb_raw.get("protobuf_failure_threshold", 3)),
        )
    )
    nb_raw["rollback_state_path"] = os.environ.get(
        "NORTHBOUND_WIRE_STATE_PATH",
        str(nb_raw.get("rollback_state_path", "/app/data/northbound-wire-state.json")),
    )
    reset_env = os.environ.get("NORTHBOUND_WIRE_ROLLBACK_RESET", "").lower()
    if reset_env in ("1", "true", "yes", "on"):
        nb_raw["rollback_reset"] = True

    edgex_dm_raw = expanded.get("edgex_device_management", {})
    dm_enabled_env = os.environ.get("EDGEX_DEVICE_MANAGEMENT_ENABLED", "").lower()
    if dm_enabled_env in ("1", "true", "yes", "on"):
        edgex_dm_raw["enabled"] = True
    elif dm_enabled_env in ("0", "false", "no", "off"):
        edgex_dm_raw["enabled"] = False
    edgex_dm_raw["metadata_url"] = os.environ.get(
        "EDGEX_CORE_METADATA_URL",
        str(edgex_dm_raw.get("metadata_url", "http://edgex-core-metadata:59881")),
    )
    edgex_dm_raw["request_timeout_sec"] = float(
        os.environ.get(
            "EDGEX_METADATA_TIMEOUT_SEC",
            str(edgex_dm_raw.get("request_timeout_sec", 5.0)),
        )
    )
    edgex_dm_raw["inventory_interval_sec"] = int(
        os.environ.get(
            "EDGEX_INVENTORY_INTERVAL_SEC",
            str(edgex_dm_raw.get("inventory_interval_sec", 60)),
        )
    )
    if os.environ.get("EDGEX_GATEWAY_ID"):
        edgex_dm_raw["gateway_id"] = os.environ["EDGEX_GATEWAY_ID"]
    for key, env_name, default in (
        (
            "live_observed_path",
            "LIVE_OBSERVED_PATH",
            "/app/data/assets/baseline/live-observed.json",
        ),
        (
            "identity_inventory_path",
            "EDGEX_IDENTITY_INVENTORY_PATH",
            "/app/data/asset-inventory.json",
        ),
        (
            "inventory_state_path",
            "EDGEX_INVENTORY_STATE_PATH",
            "/app/data/edgex-inventory-state.json",
        ),
        (
            "desired_state_path",
            "EDGEX_DESIRED_STATE_PATH",
            "/app/data/edgex-desired-state.json",
        ),
        (
            "reconcile_state_path",
            "EDGEX_RECONCILE_STATE_PATH",
            "/app/data/edgex-reconcile-state.json",
        ),
        (
            "observed_spool_db_path",
            "EDGEX_OBSERVED_SPOOL_DB",
            "/app/data/edgex-observed-spool.db",
        ),
    ):
        edgex_dm_raw.setdefault(key, os.environ.get(env_name, default))
    desired_mqtt_env = os.environ.get("EDGEX_DESIRED_MQTT_ENABLED", "").lower()
    if desired_mqtt_env in ("1", "true", "yes", "on"):
        edgex_dm_raw["desired_mqtt_enabled"] = True
    elif desired_mqtt_env in ("0", "false", "no", "off"):
        edgex_dm_raw["desired_mqtt_enabled"] = False

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

    # Control-Plane-issued credentials persisted from a prior registration take
    # precedence for provisioned sensors, so the bus stays authenticated across
    # restarts even before the next registration completes.
    from src.runtime.mqtt_credentials import load_persisted_credentials

    persisted = load_persisted_credentials()
    if persisted:
        nb_raw["username"] = persisted["username"]
        nb_raw["password"] = persisted.get("password", "")
        policy_raw["mqtt_username"] = persisted["username"]
        policy_raw["mqtt_password"] = persisted.get("password", "")
        if not nb_raw.get("host") and persisted.get("host"):
            nb_raw["host"] = persisted["host"]
            nb_raw["enabled"] = True
            if persisted.get("port"):
                nb_raw["port"] = int(persisted["port"])
        if not policy_raw.get("mqtt_host") and persisted.get("host"):
            policy_raw["mqtt_host"] = persisted["host"]
            if persisted.get("port"):
                policy_raw["mqtt_port"] = int(persisted["port"])
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

    ids_rule_env = os.environ.get("IDS_RULE_ENABLED", "").lower()
    if ids_rule_env in ("0", "false", "no"):
        policy_raw["ids_rule_enabled"] = False
    elif ids_rule_env in ("1", "true", "yes"):
        policy_raw["ids_rule_enabled"] = True
    policy_raw.setdefault(
        "ids_rule_interval_sec",
        int(os.environ.get("IDS_RULE_INTERVAL_SEC", policy_raw.get("ids_rule_interval_sec", 300))),
    )
    engines_env = (os.environ.get("IDS_RULE_ENGINES", "") or "").strip()
    if engines_env:
        policy_raw["ids_rule_engines"] = [e.strip() for e in engines_env.split(",") if e.strip()]
    policy_raw.setdefault(
        "ids_rule_feed_path_template",
        os.environ.get("IDS_RULE_FEED_PATH_TEMPLATE", "/api/v1/feed/{tenant_id}/ot-rules.rules"),
    )
    feed_profile = (
        os.environ.get("IDS_RULE_FEED_PROFILE", "")
        or os.environ.get("NDR_PROFILE", "")
        or policy_raw.get("ids_rule_feed_profile", "ot_ids")
    ).strip().lower()
    if feed_profile in ("it_ndr", "ot_ids"):
        policy_raw["ids_rule_feed_profile"] = feed_profile
    policy_raw.setdefault(
        "ids_rule_target_dir",
        os.environ.get("IDS_RULE_TARGET_DIR", "/app/data/ids-rules"),
    )
    policy_raw.setdefault(
        "ids_rule_status_path",
        os.environ.get("IDS_RULE_STATUS_PATH", "/app/data/ids-rule-status.json"),
    )
    policy_raw.setdefault(
        "ids_rule_signing_secret",
        os.environ.get("OT_FEED_SIGNING_SECRET", os.environ.get("OT_EDGE_SENSOR_API_KEY", "")),
    )
    policy_raw.setdefault("ids_rule_reload_cmd", os.environ.get("IDS_RULE_RELOAD_CMD", ""))
    policy_raw.setdefault("ids_rule_healthcheck_cmd", os.environ.get("IDS_RULE_HEALTHCHECK_CMD", ""))
    policy_raw.setdefault(
        "ids_rule_cmd_timeout_sec",
        int(os.environ.get("IDS_RULE_CMD_TIMEOUT_SEC", policy_raw.get("ids_rule_cmd_timeout_sec", 30))),
    )
    ids_rule_mqtt_env = os.environ.get("IDS_RULE_MQTT_ENABLED", "").lower()
    if ids_rule_mqtt_env in ("0", "false", "no"):
        policy_raw["ids_rule_mqtt_enabled"] = False
    elif ids_rule_mqtt_env in ("1", "true", "yes"):
        policy_raw["ids_rule_mqtt_enabled"] = True
    policy_raw.setdefault(
        "ids_rule_mqtt_topic_template",
        os.environ.get("IDS_RULE_MQTT_TOPIC", "sensel/{tenant_id}/policy/ids-rules-+"),
    )

    listfile_env = os.environ.get("LISTFILE_ENABLED", "").lower()
    if listfile_env in ("0", "false", "no"):
        policy_raw["listfile_enabled"] = False
    elif listfile_env in ("1", "true", "yes"):
        policy_raw["listfile_enabled"] = True
    policy_raw.setdefault(
        "listfile_interval_sec",
        int(os.environ.get("LISTFILE_INTERVAL_SEC", policy_raw.get("listfile_interval_sec", 300))),
    )
    policy_raw.setdefault(
        "listfile_feed_path_template",
        os.environ.get("LISTFILE_FEED_PATH_TEMPLATE", "/api/v1/feed/{tenant_id}/listfiles.json"),
    )
    policy_raw.setdefault(
        "listfile_cache_path",
        os.environ.get("LISTFILE_CACHE_PATH", "/app/data/managed-listfiles.json"),
    )
    policy_raw.setdefault(
        "listfile_stamp_path",
        os.environ.get("LISTFILE_STAMP_PATH", "/app/data/managed-listfiles.stamp"),
    )
    listfile_mqtt_env = os.environ.get("LISTFILE_MQTT_ENABLED", "").lower()
    if listfile_mqtt_env in ("0", "false", "no"):
        policy_raw["listfile_mqtt_enabled"] = False
    elif listfile_mqtt_env in ("1", "true", "yes"):
        policy_raw["listfile_mqtt_enabled"] = True
    policy_raw.setdefault(
        "listfile_mqtt_topic_template",
        os.environ.get("LISTFILE_MQTT_TOPIC", "sensel/{tenant_id}/policy/listfiles"),
    )
    ack_http_env = os.environ.get("POLICY_ACK_HTTP_FALLBACK_ENABLED", "").lower()
    if ack_http_env in ("0", "false", "no"):
        policy_raw["policy_ack_http_fallback_enabled"] = False
    elif ack_http_env in ("1", "true", "yes"):
        policy_raw["policy_ack_http_fallback_enabled"] = True
    policy_raw.setdefault(
        "policy_ack_ingest_path",
        os.environ.get("POLICY_ACK_INGEST_PATH", "/api/v1/internal/ot-security/policy-ack"),
    )
    policy_raw.setdefault(
        "policy_ack_ingest_secret",
        os.environ.get(
            "OT_SECURITY_INGEST_SECRET",
            os.environ.get("OT_EDGE_SENSOR_API_KEY", sensel_raw.get("api_key", "")),
        ),
    )
    suricata_update_env = os.environ.get("SURICATA_UPDATE_ENABLED", "").lower()
    if suricata_update_env in ("0", "false", "no"):
        policy_raw["suricata_update_enabled"] = False
    elif suricata_update_env in ("1", "true", "yes"):
        policy_raw["suricata_update_enabled"] = True
    policy_raw.setdefault(
        "suricata_update_interval_sec",
        int(os.environ.get("SURICATA_UPDATE_INTERVAL_SEC", policy_raw.get("suricata_update_interval_sec", 86400))),
    )
    policy_raw.setdefault(
        "suricata_update_cmd",
        os.environ.get("SURICATA_UPDATE_CMD", "suricata-update"),
    )
    policy_raw.setdefault(
        "suricata_update_status_path",
        os.environ.get("SURICATA_UPDATE_STATUS_PATH", "/app/data/suricata-update-status.json"),
    )
    policy_raw.setdefault(
        "suricata_update_cmd_timeout_sec",
        int(os.environ.get("SURICATA_UPDATE_CMD_TIMEOUT_SEC", policy_raw.get("suricata_update_cmd_timeout_sec", 300))),
    )
    policy_raw.setdefault(
        "autoupdate_report_ingest_path",
        os.environ.get("AUTOUPDATE_REPORT_INGEST_PATH", "/api/v1/internal/ot-security/autoupdate-report"),
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
    snort_sighting_env = os.environ.get("SNORT_SIGHTING_ENABLED", "").lower()
    if snort_sighting_env in ("1", "true", "yes"):
        sighting_raw["snort_sighting_enabled"] = True
    elif snort_sighting_env in ("0", "false", "no"):
        sighting_raw["snort_sighting_enabled"] = False
    sighting_raw.setdefault(
        "snort_cti_sid_min",
        int(os.environ.get("SNORT_CTI_SID_MIN", sighting_raw.get("snort_cti_sid_min", 0))),
    )
    sighting_raw.setdefault(
        "snort_cti_sid_max",
        int(os.environ.get("SNORT_CTI_SID_MAX", sighting_raw.get("snort_cti_sid_max", 0))),
    )
    sighting_raw.setdefault(
        "snort_events_offset_path",
        os.environ.get("SNORT_SIGHTING_EVENTS_OFFSET", "/app/data/sighting-snort-events.offset"),
    )
    suricata_sighting_env = os.environ.get("SURICATA_SIGHTING_ENABLED", "").lower()
    if suricata_sighting_env in ("1", "true", "yes"):
        sighting_raw["suricata_sighting_enabled"] = True
    elif suricata_sighting_env in ("0", "false", "no"):
        sighting_raw["suricata_sighting_enabled"] = False
    sighting_raw.setdefault(
        "suricata_events_offset_path",
        os.environ.get(
            "SURICATA_SIGHTING_EVENTS_OFFSET", "/app/data/sighting-suricata-events.offset"
        ),
    )

    config = AppConfig(
            sensor=SensorIdentity(**sensor_raw),
            sensel=SenselConfig(**sensel_raw),
            northbound_mqtt=NorthboundMqttConfig(**nb_raw),
            edgex_device_management=EdgeXDeviceManagementConfig(**edgex_dm_raw),
            policy_sync=PolicySyncConfig(**policy_raw),
            sighting_report=SightingReportConfig(**sighting_raw),
            logging=LoggingConfig(**expanded.get("logging", {})),
        )
    return apply_platform_overlay(config)
