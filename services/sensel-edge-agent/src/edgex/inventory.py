"""Build deterministic protobuf inventory from EdgeX and passive evidence."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import uuid
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping
from urllib.parse import urlparse

from google.protobuf.json_format import MessageToDict
from google.protobuf.message import DecodeError
from google.protobuf.timestamp_pb2 import Timestamp
from sensel.device.v1 import device_management_pb2

from src.edgex.client import EdgeXMetadataClient


_PROTOCOLS = {
    "modbus": device_management_pb2.PROTOCOL_KIND_MODBUS_TCP,
    "opcua": device_management_pb2.PROTOCOL_KIND_OPC_UA,
    "opc-ua": device_management_pb2.PROTOCOL_KIND_OPC_UA,
    "ethernetip": device_management_pb2.PROTOCOL_KIND_ETHERNET_IP,
    "ethernet-ip": device_management_pb2.PROTOCOL_KIND_ETHERNET_IP,
    "s7": device_management_pb2.PROTOCOL_KIND_S7,
    "bacnet": device_management_pb2.PROTOCOL_KIND_BACNET_IP,
    "mqtt": device_management_pb2.PROTOCOL_KIND_MQTT,
    "iec61850-mms": device_management_pb2.PROTOCOL_KIND_IEC61850_MMS,
    "iec61850-goose": device_management_pb2.PROTOCOL_KIND_IEC61850_GOOSE,
}


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _timestamp(value: str | None) -> Timestamp | None:
    if not value:
        return None
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    result = Timestamp()
    result.FromDatetime(moment.astimezone(timezone.utc))
    return result


def _valid_ip(value: Any) -> str:
    text = str(value or "").strip()
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return ""


def _property(properties: Any, *names: str) -> Any:
    if not isinstance(properties, Mapping):
        return None
    lowered = {str(key).lower(): value for key, value in properties.items()}
    for name in names:
        if name.lower() in lowered:
            return lowered[name.lower()]
    return None


def _protocol_kind(name: str) -> int:
    normalized = name.lower().replace("_", "-").replace(" ", "")
    for prefix, kind in _PROTOCOLS.items():
        if prefix in normalized:
            return kind
    return device_management_pb2.PROTOCOL_KIND_OTHER


def _protocol_endpoints(device: Mapping[str, Any]) -> list[device_management_pb2.ProtocolEndpoint]:
    result: list[device_management_pb2.ProtocolEndpoint] = []
    protocols = device.get("protocols")
    if not isinstance(protocols, Mapping):
        return result
    for name in sorted(protocols):
        properties = protocols[name]
        address = _property(
            properties,
            "Address",
            "Host",
            "IP",
            "DeviceAddress",
            "Endpoint",
            "Url",
        )
        port = _property(properties, "Port", "TcpPort")
        encrypted = False
        if isinstance(address, str) and "://" in address:
            parsed = urlparse(address)
            encrypted = parsed.scheme.lower() in {"https", "mqtts", "opc.tls"}
            if parsed.hostname:
                address = parsed.hostname
            if port is None and parsed.port:
                port = parsed.port
        endpoint = device_management_pb2.ProtocolEndpoint(
            protocol=_protocol_kind(str(name)),
            address=str(address or ""),
            encrypted=encrypted,
        )
        try:
            numeric_port = int(port)
            if 0 < numeric_port <= 65535:
                endpoint.port = numeric_port
        except (TypeError, ValueError):
            pass
        attribute = endpoint.attributes.add(key="edgex_protocol")
        attribute.string_value = str(name)
        result.append(endpoint)
    return result


def _endpoint_ips(endpoints: Iterable[device_management_pb2.ProtocolEndpoint]) -> set[str]:
    return {ip for endpoint in endpoints if (ip := _valid_ip(endpoint.address))}


def _add_identity(
    device: device_management_pb2.ManagedDevice,
    *,
    source: str,
    confidence: float,
    observed_at: str | None = None,
    vendor: Any = "",
    model: Any = "",
    firmware: Any = "",
    serial: Any = "",
    attributes: Mapping[str, Any] | None = None,
) -> None:
    if not any((vendor, model, firmware, serial, attributes)):
        return
    evidence = device.identity_evidence.add(
        source=source,
        manufacturer=str(vendor or ""),
        brand=str(vendor or ""),
        model=str(model or ""),
        firmware_version=str(firmware or ""),
        serial_number=str(serial or ""),
        confidence=max(0.0, min(float(confidence), 1.0)),
    )
    if observed_at:
        parsed_at = _timestamp(observed_at)
        if parsed_at:
            evidence.observed_at.CopyFrom(parsed_at)
    for key, value in sorted((attributes or {}).items()):
        if value in (None, "", [], {}):
            continue
        attribute = evidence.attributes.add(key=str(key))
        if isinstance(value, bool):
            attribute.bool_value = value
        elif isinstance(value, int):
            attribute.int_value = value
        elif isinstance(value, float):
            attribute.double_value = value
        elif isinstance(value, (list, dict, set, tuple)):
            normalized = sorted(value) if isinstance(value, set) else value
            attribute.json_value = json.dumps(normalized, sort_keys=True)
        else:
            attribute.string_value = str(value)


def _passive_assets(document: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    observed = document.get("observed")
    if not isinstance(observed, Mapping):
        return {}
    assets: dict[str, dict[str, Any]] = {}
    mac_to_ip: dict[str, str] = {}

    def touch(ip: Any, protocol: str, attributes: Mapping[str, Any] | None = None) -> None:
        address = _valid_ip(ip)
        if not address:
            return
        row = assets.setdefault(address, {"protocols": set(), "attributes": {}})
        if protocol:
            row["protocols"].add(protocol)
        row["attributes"].update(dict(attributes or {}))

    def touch_mac(
        mac: Any, protocol: str, attributes: Mapping[str, Any] | None = None
    ) -> None:
        address = str(mac or "").strip().lower()
        parts = address.split(":")
        if len(parts) != 6 or any(
            len(part) != 2 or any(ch not in "0123456789abcdef" for ch in part)
            for part in parts
        ):
            return
        row = assets.setdefault(address, {"protocols": set(), "attributes": {}})
        row["protocols"].add(protocol)
        row["attributes"].update(dict(attributes or {}))

    for row in observed.get("mac_ip") or []:
        if isinstance(row, Mapping):
            ip = _valid_ip(row.get("ip"))
            mac = str(row.get("mac") or "").strip().lower()
            touch(ip, "", {"mac": mac})
            if ip and mac:
                mac_to_ip[mac] = ip
    for row in observed.get("modbus_servers") or []:
        if isinstance(row, Mapping):
            touch(
                row.get("server_ip"),
                "modbus",
                {
                    "unit_ids": row.get("unit_ids") or [],
                    "function_codes": row.get("function_codes") or [],
                },
            )
    iec61850 = observed.get("iec61850")
    if isinstance(iec61850, Mapping):
        for row in iec61850.get("goose_publishers") or []:
            if isinstance(row, Mapping):
                mac = str(row.get("publisher_mac") or "").strip().lower()
                if mac in mac_to_ip:
                    touch(mac_to_ip[mac], "iec61850-goose", row)
                else:
                    touch_mac(mac, "iec61850-goose", row)
        for row in iec61850.get("mms_ieds") or []:
            if isinstance(row, Mapping):
                touch(row.get("ied_ip") or row.get("ip"), "iec61850-mms", row)
    return assets


class InventoryBuilder:
    def __init__(
        self,
        metadata: EdgeXMetadataClient,
        *,
        site_id: str,
        sensor_id: str,
        gateway_id: str,
        live_observed_path: str | Path,
        identity_inventory_path: str | Path,
        desired_state_path: str | Path | None = None,
        reconcile_state_path: str | Path | None = None,
    ) -> None:
        self.metadata = metadata
        self.site_id = site_id
        self.sensor_id = sensor_id
        self.gateway_id = gateway_id or sensor_id
        self.live_observed_path = Path(live_observed_path)
        self.identity_inventory_path = Path(identity_inventory_path)
        self.desired_state_path = Path(desired_state_path) if desired_state_path else None
        self.reconcile_state_path = (
            Path(reconcile_state_path) if reconcile_state_path else None
        )
        self.device_records: dict[str, dict[str, Any]] = {}

    def build(self, tenant_id: str) -> device_management_pb2.InventorySnapshot:
        devices = self.metadata.list_devices()
        profiles = {
            str(profile.get("name") or ""): profile
            for profile in self.metadata.list_device_profiles()
        }
        passive_doc = _read_json(self.live_observed_path)
        passive = _passive_assets(passive_doc)
        identity_doc = _read_json(self.identity_inventory_path)
        identities = identity_doc.get("entries")
        if not isinstance(identities, Mapping):
            identities = {}
        desired_states: dict[str, device_management_pb2.DesiredDeviceState] = {}
        if self.desired_state_path:
            commands = _read_json(self.desired_state_path).get("commands")
            if isinstance(commands, Mapping):
                for desired_asset_id, row in commands.items():
                    if not isinstance(row, Mapping):
                        continue
                    try:
                        command = device_management_pb2.DesiredDeviceStateCommand.FromString(
                            base64.b64decode(str(row.get("payload") or ""), validate=True)
                        )
                        desired_states[str(desired_asset_id)] = command.desired
                    except (ValueError, TypeError, DecodeError):
                        continue
        reconciled_assets: Mapping[str, Any] = {}
        if self.reconcile_state_path:
            loaded_assets = _read_json(self.reconcile_state_path).get("assets")
            if isinstance(loaded_assets, Mapping):
                reconciled_assets = loaded_assets
        generated_at = str(passive_doc.get("generated_at") or "")
        managed: list[device_management_pb2.ManagedDevice] = []
        records: dict[str, dict[str, Any]] = {}
        bound_addresses: set[str] = set()

        for raw in sorted(devices, key=lambda item: str(item.get("name") or "")):
            name = str(raw.get("name") or "").strip()
            if not name:
                continue
            local_id = str(raw.get("id") or name)
            asset_id = f"edgex:{self.site_id}:{local_id}"
            profile_name = str(raw.get("profileName") or "")
            profile = profiles.get(profile_name, {})
            item = device_management_pb2.ManagedDevice(
                asset_id=asset_id,
                tenant_id=tenant_id,
                site_id=self.site_id,
                display_name=str(raw.get("description") or name),
            )
            item.edgex.gateway_id = self.gateway_id
            item.edgex.device_name = name
            item.edgex.device_service_name = str(raw.get("serviceName") or "")
            item.edgex.profile_name = profile_name
            item.edgex.profile_version = str(profile.get("version") or "")
            item.edgex.local_device_id = local_id
            endpoints = _protocol_endpoints(raw)
            item.endpoints.extend(endpoints)
            ips = _endpoint_ips(endpoints)
            bound_addresses.update(
                endpoint.address.strip().lower()
                for endpoint in endpoints
                if endpoint.address.strip()
            )
            item.desired.enabled = str(raw.get("adminState") or "").upper() != "LOCKED"
            item.desired.lifecycle_state = (
                device_management_pb2.DEVICE_LIFECYCLE_STATE_MANAGED
            )
            if asset_id in desired_states:
                item.desired.CopyFrom(desired_states[asset_id])
            item.observed.connection_state = str(raw.get("operatingState") or "UNKNOWN")
            item.observed.profile_version = str(profile.get("version") or "")
            applied = reconciled_assets.get(asset_id)
            if isinstance(applied, Mapping):
                item.observed.applied_config_revision = str(
                    applied.get("applied_config_revision") or ""
                )
            _add_identity(
                item,
                source="edgex-profile",
                confidence=0.9,
                vendor=profile.get("manufacturer"),
                model=profile.get("model"),
                attributes={"profile_name": profile_name},
            )
            for ip in sorted(ips):
                entry = identities.get(ip)
                if isinstance(entry, Mapping):
                    manual = entry.get("manual")
                    if isinstance(manual, Mapping):
                        _add_identity(
                            item,
                            source="manual",
                            confidence=1.0,
                            observed_at=str(entry.get("updated_at") or ""),
                            vendor=manual.get("vendor"),
                            model=manual.get("model"),
                            firmware=manual.get("firmware"),
                        )
                    probe = entry.get("probe")
                    if isinstance(probe, Mapping):
                        _add_identity(
                            item,
                            source="active-probe",
                            confidence=0.8,
                            observed_at=str(probe.get("probed_at") or ""),
                            vendor=probe.get("vendor"),
                            model=probe.get("model"),
                            firmware=probe.get("firmware"),
                            attributes={"open_ports": probe.get("open_ports") or []},
                        )
                if ip in passive:
                    _add_identity(
                        item,
                        source="passive-fingerprint",
                        confidence=0.6,
                        observed_at=generated_at,
                        attributes=passive[ip],
                    )
            managed.append(item)
            records[asset_id] = deepcopy(raw)

        for address, evidence in sorted(passive.items()):
            if address.lower() in bound_addresses:
                continue
            ip = _valid_ip(address)
            asset_id = (
                f"passive:{self.site_id}:{address}"
                if ip
                else f"passive:{self.site_id}:mac:{address}"
            )
            item = device_management_pb2.ManagedDevice(
                asset_id=asset_id,
                tenant_id=tenant_id,
                site_id=self.site_id,
                display_name=address,
            )
            item.desired.enabled = True
            item.desired.lifecycle_state = (
                device_management_pb2.DEVICE_LIFECYCLE_STATE_DISCOVERED
            )
            item.observed.connection_state = "PASSIVELY_OBSERVED"
            last_seen_at = _timestamp(generated_at)
            if last_seen_at:
                item.observed.last_seen_at.CopyFrom(last_seen_at)
            for protocol in sorted(evidence["protocols"]):
                item.endpoints.add(
                    protocol=_protocol_kind(protocol),
                    address=address,
                )
            _add_identity(
                item,
                source="passive-fingerprint",
                confidence=0.6,
                observed_at=generated_at,
                attributes=evidence,
            )
            entry = identities.get(ip) if ip else None
            if isinstance(entry, Mapping) and isinstance(entry.get("manual"), Mapping):
                manual = entry["manual"]
                _add_identity(
                    item,
                    source="manual",
                    confidence=1.0,
                    observed_at=str(entry.get("updated_at") or ""),
                    vendor=manual.get("vendor"),
                    model=manual.get("model"),
                    firmware=manual.get("firmware"),
                )
            managed.append(item)

        managed.sort(key=lambda item: item.asset_id)
        canonical = [
            MessageToDict(
                item,
                preserving_proto_field_name=True,
                always_print_fields_with_no_presence=True,
            )
            for item in managed
        ]
        encoded = json.dumps(
            canonical,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        revision = f"sha256:{hashlib.sha256(encoded).hexdigest()}"
        snapshot_id = str(
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                f"sensel:{tenant_id}:{self.site_id}:{self.sensor_id}:{revision}",
            )
        )
        snapshot = device_management_pb2.InventorySnapshot(
            snapshot_id=snapshot_id,
            inventory_revision=revision,
        )
        snapshot.meta.event_id = snapshot_id
        snapshot.meta.tenant_id = tenant_id
        snapshot.meta.site_id = self.site_id
        snapshot.meta.sensor_id = self.sensor_id
        snapshot.meta.trace_id = snapshot_id
        snapshot.meta.producer.type = "sensel-edge-agent-edgex"
        snapshot.meta.observed_at.GetCurrentTime()
        snapshot.devices.extend(managed)
        self.device_records = records
        return snapshot
