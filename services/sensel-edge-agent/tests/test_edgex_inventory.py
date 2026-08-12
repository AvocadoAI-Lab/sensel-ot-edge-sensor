import json

import httpx

from sensel.device.v1 import device_management_pb2
from src.edgex.client import EdgeXMetadataClient, EdgeXMetadataError
from src.edgex.inventory import InventoryBuilder


def _transport(*, unavailable: bool = False) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        if unavailable:
            return httpx.Response(503, json={"message": "metadata down"})
        if request.url.path == "/api/v3/device/all":
            return httpx.Response(
                200,
                json={
                    "devices": [
                        {
                            "id": "device-uuid-1",
                            "name": "plc-1",
                            "description": "Packaging PLC",
                            "serviceName": "device-modbus",
                            "profileName": "modbus-relay",
                            "adminState": "UNLOCKED",
                            "operatingState": "UP",
                            "protocols": {
                                "modbus-tcp": {
                                    "Address": "192.0.2.10",
                                    "Port": "502",
                                }
                            },
                            "autoEvents": [
                                {"sourceName": "HoldingRegister", "interval": "10s"}
                            ],
                        }
                    ]
                },
            )
        if request.url.path == "/api/v3/deviceprofile/all":
            return httpx.Response(
                200,
                json={
                    "profiles": [
                        {
                            "name": "modbus-relay",
                            "manufacturer": "Acme",
                            "model": "PLC-X",
                            "version": "1.2",
                        }
                    ]
                },
            )
        return httpx.Response(404)

    return httpx.MockTransport(handler)


def test_inventory_merges_edgex_manual_probe_and_passive_without_overwrite(
    tmp_path,
) -> None:
    passive_path = tmp_path / "live-observed.json"
    passive_path.write_text(
        json.dumps(
            {
                "generated_at": "2026-08-12T01:00:00+00:00",
                "observed": {
                    "mac_ip": [
                        {"ip": "192.0.2.10", "mac": "00:11:22:33:44:55"},
                        {"ip": "192.0.2.20", "mac": "00:11:22:33:44:66"},
                    ],
                    "modbus_servers": [
                        {"server_ip": "192.0.2.10", "unit_ids": [1]},
                    ],
                    "iec61850": {
                        "goose_publishers": [
                            {
                                "publisher_mac": "00:11:22:33:44:66",
                                "appid": 1000,
                                "gocb_ref": "IED1/LLN0$GO$gcb1",
                            }
                        ],
                        "mms_ieds": [],
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    identity_path = tmp_path / "asset-inventory.json"
    identity_path.write_text(
        json.dumps(
            {
                "entries": {
                    "192.0.2.10": {
                        "updated_at": "2026-08-12T01:01:00+00:00",
                        "manual": {
                            "vendor": "Operator Vendor",
                            "model": "M-1",
                            "firmware": "9.1",
                        },
                        "probe": {
                            "vendor": "Probe Vendor",
                            "model": "M-probe",
                            "probed_at": "2026-08-12T01:00:30+00:00",
                        },
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    metadata = EdgeXMetadataClient(
        "http://metadata", transport=_transport()
    )
    builder = InventoryBuilder(
        metadata,
        site_id="site-a",
        sensor_id="edge-a",
        gateway_id="gateway-a",
        live_observed_path=passive_path,
        identity_inventory_path=identity_path,
    )

    first = builder.build("tenant-a")
    second = builder.build("tenant-a")

    assert first.inventory_revision == second.inventory_revision
    assert first.snapshot_id == second.snapshot_id
    assert len(first.devices) == 2
    plc = next(item for item in first.devices if item.edgex.device_name == "plc-1")
    assert plc.asset_id == "edgex:site-a:device-uuid-1"
    assert plc.endpoints[0].protocol == device_management_pb2.PROTOCOL_KIND_MODBUS_TCP
    assert plc.endpoints[0].port == 502
    assert [e.source for e in plc.identity_evidence] == [
        "edgex-profile",
        "manual",
        "active-probe",
        "passive-fingerprint",
    ]
    assert plc.identity_evidence[1].manufacturer == "Operator Vendor"
    discovered = next(item for item in first.devices if not item.edgex.device_name)
    assert discovered.asset_id == "passive:site-a:192.0.2.20"
    assert (
        discovered.endpoints[0].protocol
        == device_management_pb2.PROTOCOL_KIND_IEC61850_GOOSE
    )
    assert (
        discovered.desired.lifecycle_state
        == device_management_pb2.DEVICE_LIFECYCLE_STATE_DISCOVERED
    )


def test_edgex_metadata_failure_is_bounded_error() -> None:
    client = EdgeXMetadataClient(
        "http://metadata", transport=_transport(unavailable=True)
    )

    try:
        client.list_devices()
        raise AssertionError("expected EdgeXMetadataError")
    except EdgeXMetadataError as exc:
        assert "503" in str(exc)


def test_edgex_update_uses_v3_bulk_request_and_strips_database_fields() -> None:
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["method"] = request.method
        seen["path"] = request.url.path
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json=[{"statusCode": 200}])

    client = EdgeXMetadataClient(
        "http://metadata", transport=httpx.MockTransport(handler)
    )
    client.update_device(
        {
            "id": "id-1",
            "name": "plc-1",
            "created": 123,
            "modified": 456,
            "adminState": "LOCKED",
        }
    )

    assert (seen["method"], seen["path"]) == ("PUT", "/api/v3/device")
    assert seen["body"][0]["apiVersion"] == "v3"
    assert seen["body"][0]["device"]["adminState"] == "LOCKED"
    assert "created" not in seen["body"][0]["device"]
