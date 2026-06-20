<<<<<<< Updated upstream
"""Apply platform.json from Edge Console over env/yaml config."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from src.config.settings import AppConfig


def _platform_path() -> Path:
    return Path(os.environ.get("PLATFORM_CONFIG_PATH", "/app/data/platform.json"))


def load_platform_raw() -> dict[str, Any]:
    path = _platform_path()
    if not path.is_file():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return raw if isinstance(raw, dict) else {}


def apply_platform_overlay(config: AppConfig) -> AppConfig:
    raw = load_platform_raw()
    if not raw:
        return config

    sensor = config.sensor.model_copy(deep=True)
    sensel = config.sensel.model_copy(deep=True)
    mqtt = config.northbound_mqtt.model_copy(deep=True)

    if raw.get("sensor_id"):
        sensor.id = str(raw["sensor_id"])
    if raw.get("site_id"):
        sensor.site_id = str(raw["site_id"])
    if raw.get("sensor_type"):
        sensor.type = str(raw["sensor_type"])
    if raw.get("hardware"):
        sensor.hardware = str(raw["hardware"])

    if raw.get("sensel_api_url"):
        sensel.api_url = str(raw["sensel_api_url"]).rstrip("/")
    if raw.get("sensel_api_key"):
        sensel.api_key = str(raw["sensel_api_key"])
    if raw.get("registration_token"):
        sensel.registration_token = str(raw["registration_token"])
    if "sensel_verify_tls" in raw:
        sensel.verify_tls = bool(raw["sensel_verify_tls"])

    if raw.get("mqtt_host"):
        mqtt.host = str(raw["mqtt_host"])
    if raw.get("mqtt_port"):
        mqtt.port = int(raw["mqtt_port"])
    if raw.get("mqtt_tenant_id"):
        mqtt.tenant_id = str(raw["mqtt_tenant_id"])
    if "mqtt_enabled" in raw:
        mqtt.enabled = bool(raw["mqtt_enabled"])
    elif mqtt.host:
        mqtt.enabled = True

    if raw.get("last_register_tenant_id"):
        mqtt.tenant_id = str(raw["last_register_tenant_id"])
    elif raw.get("mqtt_tenant_id") and str(raw.get("mqtt_tenant_id")) != "default":
        mqtt.tenant_id = str(raw["mqtt_tenant_id"])

    if mqtt.enabled and mqtt.tenant_id == "default":
        mqtt.require_tenant = True

    policy_sync = config.policy_sync.model_copy(deep=True)
    sighting_report = config.sighting_report.model_copy(deep=True)
    if raw.get("smb_intel_api_key"):
        policy_sync.smb_intel_api_key = str(raw["smb_intel_api_key"])
        sighting_report.smb_intel_api_key = str(raw["smb_intel_api_key"])
    if raw.get("policy_sync_tenant_id"):
        policy_sync.feed_tenant_id = str(raw["policy_sync_tenant_id"])

    return config.model_copy(
        update={
            "sensor": sensor,
            "sensel": sensel,
            "northbound_mqtt": mqtt,
            "policy_sync": policy_sync,
            "sighting_report": sighting_report,
        }
    )
=======
"""Apply platform.json from Edge Console over env/yaml config."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from src.config.settings import AppConfig


def _platform_path() -> Path:
    return Path(os.environ.get("PLATFORM_CONFIG_PATH", "/app/data/platform.json"))


def load_platform_raw() -> dict[str, Any]:
    path = _platform_path()
    if not path.is_file():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return raw if isinstance(raw, dict) else {}


def apply_platform_overlay(config: AppConfig) -> AppConfig:
    raw = load_platform_raw()
    if not raw:
        return config

    sensor = config.sensor.model_copy(deep=True)
    sensel = config.sensel.model_copy(deep=True)
    mqtt = config.northbound_mqtt.model_copy(deep=True)

    if raw.get("sensor_id"):
        sensor.id = str(raw["sensor_id"])
    if raw.get("site_id"):
        sensor.site_id = str(raw["site_id"])
    if raw.get("sensor_type"):
        sensor.type = str(raw["sensor_type"])
    if raw.get("hardware"):
        sensor.hardware = str(raw["hardware"])

    if raw.get("sensel_api_url"):
        sensel.api_url = str(raw["sensel_api_url"]).rstrip("/")
    if raw.get("sensel_api_key"):
        sensel.api_key = str(raw["sensel_api_key"])
    if raw.get("registration_token"):
        sensel.registration_token = str(raw["registration_token"])
    if "sensel_verify_tls" in raw:
        sensel.verify_tls = bool(raw["sensel_verify_tls"])

    if raw.get("mqtt_host"):
        mqtt.host = str(raw["mqtt_host"])
    if raw.get("mqtt_port"):
        mqtt.port = int(raw["mqtt_port"])
    if raw.get("mqtt_tenant_id"):
        mqtt.tenant_id = str(raw["mqtt_tenant_id"])
    if "mqtt_enabled" in raw:
        mqtt.enabled = bool(raw["mqtt_enabled"])
    elif mqtt.host:
        mqtt.enabled = True

    if raw.get("last_register_tenant_id"):
        mqtt.tenant_id = str(raw["last_register_tenant_id"])
    elif raw.get("mqtt_tenant_id") and str(raw.get("mqtt_tenant_id")) != "default":
        mqtt.tenant_id = str(raw["mqtt_tenant_id"])

    if mqtt.enabled and mqtt.tenant_id == "default":
        mqtt.require_tenant = True

    policy_sync = config.policy_sync.model_copy(deep=True)
    sighting_report = config.sighting_report.model_copy(deep=True)
    if raw.get("smb_intel_api_key"):
        policy_sync.smb_intel_api_key = str(raw["smb_intel_api_key"])
        sighting_report.smb_intel_api_key = str(raw["smb_intel_api_key"])
    if raw.get("policy_sync_tenant_id"):
        policy_sync.feed_tenant_id = str(raw["policy_sync_tenant_id"])

    return config.model_copy(
        update={
            "sensor": sensor,
            "sensel": sensel,
            "northbound_mqtt": mqtt,
            "policy_sync": policy_sync,
            "sighting_report": sighting_report,
        }
    )
>>>>>>> Stashed changes
