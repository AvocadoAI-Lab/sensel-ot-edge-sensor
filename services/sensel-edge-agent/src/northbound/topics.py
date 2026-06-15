"""MQTT topic helpers for ot-edge/default/{site}/{sensor}/..."""


def topic_base(tenant_id: str, site_id: str, sensor_id: str) -> str:
    return f"ot-edge/{tenant_id}/{site_id}/{sensor_id}"


def events_topic(tenant_id: str, site_id: str, sensor_id: str) -> str:
    return f"{topic_base(tenant_id, site_id, sensor_id)}/events/v1"


def state_topic(tenant_id: str, site_id: str, sensor_id: str) -> str:
    return f"{topic_base(tenant_id, site_id, sensor_id)}/state"


def telemetry_topic(tenant_id: str, site_id: str, sensor_id: str) -> str:
    return f"{topic_base(tenant_id, site_id, sensor_id)}/telemetry/v1"


def coverage_topic(tenant_id: str, site_id: str, sensor_id: str) -> str:
    return f"{topic_base(tenant_id, site_id, sensor_id)}/coverage/v1"


def observe_tick_topic(tenant_id: str, site_id: str, sensor_id: str) -> str:
    return f"{topic_base(tenant_id, site_id, sensor_id)}/baseline/observe/v1"


def topology_snapshot_topic(tenant_id: str, site_id: str, sensor_id: str) -> str:
    return f"{topic_base(tenant_id, site_id, sensor_id)}/topology/snapshot/v1"
