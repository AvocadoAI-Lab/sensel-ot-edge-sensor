"""MQTT topic helpers for ot-edge/default/{site}/{sensor}/..."""


def _segment(value: str, name: str) -> str:
    segment = str(value or "").strip()
    if not segment or any(character in segment for character in "/+#"):
        raise ValueError(f"MQTT topic {name} is empty or contains a reserved character")
    return segment


def topic_base(tenant_id: str, site_id: str, sensor_id: str) -> str:
    return "ot-edge/{}/{}/{}".format(
        _segment(tenant_id, "tenant_id"),
        _segment(site_id, "site_id"),
        _segment(sensor_id, "sensor_id"),
    )


def events_topic(tenant_id: str, site_id: str, sensor_id: str) -> str:
    return f"{topic_base(tenant_id, site_id, sensor_id)}/events/v1"


def trust_episode_json_topic(tenant_id: str, site_id: str, sensor_id: str) -> str:
    return f"{topic_base(tenant_id, site_id, sensor_id)}/episodes/v1"


def trust_episode_protobuf_topic(
    tenant_id: str,
    site_id: str,
    sensor_id: str,
) -> str:
    return "sensel/{}/{}/{}/episode/v1".format(
        _segment(tenant_id, "tenant_id"),
        _segment(site_id, "site_id"),
        _segment(sensor_id, "sensor_id"),
    )


def inventory_snapshot_topic(tenant_id: str, site_id: str, sensor_id: str) -> str:
    return "sensel/{}/{}/{}/inventory/v1".format(
        _segment(tenant_id, "tenant_id"),
        _segment(site_id, "site_id"),
        _segment(sensor_id, "sensor_id"),
    )


def desired_device_state_topic(tenant_id: str, site_id: str, sensor_id: str) -> str:
    return "sensel/{}/{}/{}/device/desired/v1".format(
        _segment(tenant_id, "tenant_id"),
        _segment(site_id, "site_id"),
        _segment(sensor_id, "sensor_id"),
    )


def observed_device_state_topic(tenant_id: str, site_id: str, sensor_id: str) -> str:
    return "sensel/{}/{}/{}/device/observed/v1".format(
        _segment(tenant_id, "tenant_id"),
        _segment(site_id, "site_id"),
        _segment(sensor_id, "sensor_id"),
    )


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


def policy_ack_topic(tenant_id: str, site_id: str, sensor_id: str) -> str:
    """ACK/NACK for applied policy artifacts (IDS rules, managed listfiles)."""
    return f"{topic_base(tenant_id, site_id, sensor_id)}/policy/ack/v1"
