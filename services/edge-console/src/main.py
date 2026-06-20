"""SenseL Edge Console — local setup wizard and appliance dashboard."""

from __future__ import annotations

import json
import os
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from fastapi import Cookie, Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from src.auth import (
    _COOKIE,
    _valid_token,
    clear_session,
    create_session,
    password_required,
    require_session,
    set_password,
    verify_password,
)
from src.config_store import ConfigStore, PlatformConfig
from src.sensel_api import ping_sensel, register_sensor
from src.events_index import read_jsonl_tail
from src.status_service import build_status
from src.traffic_service import read_live_traffic
from src.lab_traffic_service import apply_lab_traffic_action, build_lab_traffic_status
from src.edgex_service import (
    build_platform,
    build_protocol_matrix,
    container_logs,
    get_device_readings,
    list_devices,
    restart_edgex_container,
    start_edgex_container,
)
from src.audit_service import log_audit, read_audit_recent
from src.detection_policy_service import build_applied_detection_policy
from src import baseline_service
from src import asset_probe_service
from src.discovery_service import build_discovery, build_ip_device_map, enrich_events
from src.network_service import collect_interfaces, set_interface_state
from src import wifi_service
from src import vpn_service
from src.edgex_config_service import (
    delete_config_device,
    enable_phase2_services,
    get_wizard_templates,
    list_config_devices,
    phase2_status,
    probe_connectivity,
    run_connectivity_suite,
    upsert_config_device,
)

APP_VERSION = "0.1.0"
STATIC_DIR = Path(__file__).resolve().parent.parent / "static"
TLS_DIR = Path(os.environ.get("CONSOLE_TLS_DIR", "/data/agent/tls"))
store = ConfigStore()

app = FastAPI(title="SenseL Edge Console", version=APP_VERSION)


@app.middleware("http")
async def _revalidate_static_assets(request: Request, call_next):
    """Force browsers to revalidate JS/CSS/HTML so deploys take effect without
    a manual hard refresh. ``no-cache`` keeps the cached copy but requires an
    ETag/Last-Modified revalidation (cheap 304 when unchanged), avoiding stale
    ES module subresources (e.g. /assets/pages/ops.js) after an update."""
    response = await call_next(request)
    path = request.url.path
    if path == "/" or path.endswith((".js", ".css", ".html")):
        response.headers["Cache-Control"] = "no-cache"
    return response


class LoginBody(BaseModel):
    password: str


class ConfigPatch(BaseModel):
    sensor_id: Optional[str] = Field(None, max_length=64)
    site_id: Optional[str] = Field(None, max_length=64)
    sensel_api_url: Optional[str] = None
    sensel_api_key: Optional[str] = None
    registration_token: Optional[str] = None
    sensel_verify_tls: Optional[bool] = None
    mqtt_enabled: Optional[bool] = None
    mqtt_host: Optional[str] = None
    mqtt_port: Optional[int] = None
    capture_interface: Optional[str] = Field(None, max_length=64)
    capture_bpf_filter: Optional[str] = Field(None, max_length=512)


class PasswordChangeBody(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=8, max_length=128)


class RegisterTestBody(BaseModel):
    save_first: bool = True


class DeviceConfigBody(BaseModel):
    protocol: str = Field(..., max_length=16)
    name: str = Field(..., max_length=64)
    host: Optional[str] = None
    port: Optional[int] = None
    unit_id: Optional[int] = None
    rack: Optional[int] = None
    slot: Optional[int] = None
    endpoint: Optional[str] = None
    interval: Optional[str] = Field("10s", max_length=16)


class ConnectivityBody(BaseModel):
    protocol: str = Field(..., max_length=16)
    host: str = Field(..., max_length=255)
    port: int = Field(..., ge=1, le=65535)


class LabTrafficActionBody(BaseModel):
    action: Optional[str] = Field(None, max_length=16)
    targets: Optional[list[str]] = None
    preset: Optional[str] = Field(None, max_length=32)


class InterfaceStateBody(BaseModel):
    up: bool


class WifiRadioBody(BaseModel):
    on: bool


class WifiConnectBody(BaseModel):
    ssid: str = Field(..., max_length=64)
    password: Optional[str] = Field(None, max_length=128)
    iface: Optional[str] = Field(None, max_length=16)


class WifiDisconnectBody(BaseModel):
    iface: Optional[str] = Field(None, max_length=16)


class WifiPrimaryBody(BaseModel):
    iface: str = Field(..., max_length=16)


class WifiPriorityBody(BaseModel):
    order: list[str] = Field(default_factory=list, max_length=10)


class VpnConnectBody(BaseModel):
    profile: str = Field(..., max_length=64)
    redirect_gateway: bool = False
    username: Optional[str] = Field(None, max_length=256)
    password: Optional[str] = Field(None, max_length=256)
    auto_reconnect: bool = True


class VpnAutoReconnectBody(BaseModel):
    on: bool


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "edge-console", "version": APP_VERSION}


@app.get("/sensel-root-ca.crt")
def download_root_ca() -> FileResponse:
    """Public download of the appliance's local CA root certificate.

    Operators install this once per client to get a green-lock, warning-free
    https://<name>.local. Served unauthenticated (and reachable over plain
    HTTP:8090) so trust can be bootstrapped before HTTPS is trusted. Returns
    404 when the console is using a plain self-signed cert (no local CA)."""
    ca_crt = TLS_DIR / "ca" / "rootCA.crt"
    if not ca_crt.is_file():
        raise HTTPException(status_code=404, detail="No local CA configured")
    return FileResponse(
        ca_crt,
        media_type="application/x-x509-ca-cert",
        filename="sensel-root-ca.crt",
    )


@app.get("/api/auth/status")
def auth_status(edge_console_session: Optional[str] = Cookie(None, alias=_COOKIE)) -> dict[str, bool]:
    if not password_required():
        return {"password_required": False, "authenticated": True}
    return {
        "password_required": True,
        "authenticated": _valid_token(edge_console_session),
    }


@app.post("/api/auth/login")
def login(body: LoginBody, response: Response) -> dict[str, bool]:
    if not password_required():
        create_session(response)
        log_audit("auth.login", {"mode": "open"})
        return {"ok": True}
    if not verify_password(body.password):
        log_audit("auth.login_failed", {})
        raise HTTPException(status_code=401, detail="Invalid password")
    create_session(response)
    log_audit("auth.login", {"mode": "password"})
    return {"ok": True}


@app.post("/api/auth/logout")
def logout(response: Response, _: None = Depends(require_session)) -> dict[str, bool]:
    log_audit("auth.logout", {})
    clear_session(response)
    return {"ok": True}


@app.put("/api/auth/password")
def change_password(body: PasswordChangeBody, _: None = Depends(require_session)) -> dict[str, bool]:
    if password_required() and not verify_password(body.current_password):
        raise HTTPException(status_code=401, detail="Current password incorrect")
    try:
        set_password(body.new_password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    log_audit("auth.password_changed", {})
    return {"ok": True}


@app.post("/api/capture/reload")
def reload_capture(_: None = Depends(require_session)) -> dict[str, Any]:
    container = os.environ.get("PACKET_SENSOR_CONTAINER", "sensel-packet-sensor")
    ok, detail = _restart_container(container)
    if not ok:
        raise HTTPException(status_code=503, detail=detail)
    log_audit("docker.restart", {"container": container})
    return {"ok": True, "message": detail}


@app.get("/api/config")
def get_config(_: None = Depends(require_session)) -> dict[str, Any]:
    return store.public_view(store.load())


@app.put("/api/config")
def put_config(body: ConfigPatch, _: None = Depends(require_session)) -> dict[str, Any]:
    patch = body.model_dump(exclude_none=True)
    saved = store.merge_update(patch)
    return store.public_view(saved)


@app.get("/api/status")
def get_status(_: None = Depends(require_session)) -> dict[str, Any]:
    return build_status(store)


@app.get("/api/network/interfaces")
def network_interfaces(_: None = Depends(require_session)) -> dict[str, Any]:
    cfg = store.load()
    return collect_interfaces(capture_interface=cfg.capture_interface)


@app.post("/api/network/interfaces/{name}/state")
def network_interface_state(
    name: str,
    body: InterfaceStateBody,
    _: None = Depends(require_session),
) -> dict[str, Any]:
    cfg = store.load()
    result = set_interface_state(name, body.up, capture_interface=cfg.capture_interface)
    if not result.get("ok"):
        raise HTTPException(status_code=int(result.get("status", 400)), detail=result.get("error"))
    log_audit("network.interface_state", {"name": name, "up": body.up})
    return result


@app.get("/api/network/wifi")
def network_wifi(rescan: bool = False, _: None = Depends(require_session)) -> dict[str, Any]:
    return wifi_service.status(rescan=rescan)


@app.post("/api/network/wifi/radio")
def network_wifi_radio(body: WifiRadioBody, _: None = Depends(require_session)) -> dict[str, Any]:
    result = wifi_service.set_radio(body.on)
    if not result.get("ok"):
        raise HTTPException(status_code=int(result.get("status", 400)), detail=result.get("error"))
    log_audit("network.wifi_radio", {"on": body.on})
    return result


@app.post("/api/network/wifi/connect")
def network_wifi_connect(body: WifiConnectBody, _: None = Depends(require_session)) -> dict[str, Any]:
    result = wifi_service.connect(body.ssid, body.password, body.iface)
    if not result.get("ok"):
        raise HTTPException(status_code=int(result.get("status", 400)), detail=result.get("error"))
    # Never log the password.
    log_audit("network.wifi_connect", {"ssid": body.ssid, "iface": body.iface})
    return result


@app.post("/api/network/wifi/disconnect")
def network_wifi_disconnect(body: WifiDisconnectBody, _: None = Depends(require_session)) -> dict[str, Any]:
    result = wifi_service.disconnect(body.iface)
    if not result.get("ok"):
        raise HTTPException(status_code=int(result.get("status", 400)), detail=result.get("error"))
    log_audit("network.wifi_disconnect", {"iface": body.iface})
    return result


@app.post("/api/network/wifi/primary")
def network_wifi_primary(body: WifiPrimaryBody, _: None = Depends(require_session)) -> dict[str, Any]:
    result = wifi_service.set_primary(body.iface)
    if not result.get("ok"):
        raise HTTPException(status_code=int(result.get("status", 400)), detail=result.get("error"))
    log_audit("network.wifi_primary", {"iface": body.iface})
    return result


@app.post("/api/network/wifi/priority")
def network_wifi_priority(body: WifiPriorityBody, _: None = Depends(require_session)) -> dict[str, Any]:
    result = wifi_service.set_wifi_priority(body.order)
    if not result.get("ok"):
        raise HTTPException(status_code=int(result.get("status", 400)), detail=result.get("error"))
    log_audit("network.wifi_priority", {"order": body.order})
    return result


# --- OpenVPN client -----------------------------------------------------------


@app.get("/api/vpn/profiles")
def vpn_profiles(_: None = Depends(require_session)) -> dict[str, Any]:
    return vpn_service.list_profiles()


@app.post("/api/vpn/profiles")
async def vpn_upload_profile(
    request: Request,
    name: str,
    _: None = Depends(require_session),
) -> dict[str, Any]:
    body = await request.body()
    result = vpn_service.save_profile(name, body)
    if not result.get("ok"):
        raise HTTPException(status_code=int(result.get("status", 400)), detail=result.get("error"))
    log_audit("vpn.profile_upload", {"name": name, "bytes": len(body)})
    return result


@app.delete("/api/vpn/profiles/{name}")
def vpn_delete_profile(name: str, _: None = Depends(require_session)) -> dict[str, Any]:
    result = vpn_service.delete_profile(name)
    if not result.get("ok"):
        raise HTTPException(status_code=int(result.get("status", 400)), detail=result.get("error"))
    log_audit("vpn.profile_delete", {"name": name})
    return result


@app.get("/api/vpn/profiles/{name}/view")
def vpn_view_profile(name: str, _: None = Depends(require_session)) -> dict[str, Any]:
    result = vpn_service.view_profile(name)
    if not result.get("ok"):
        raise HTTPException(status_code=int(result.get("status", 400)), detail=result.get("error"))
    return result


@app.get("/api/vpn/status")
def vpn_status(_: None = Depends(require_session)) -> dict[str, Any]:
    return vpn_service.get_status()


@app.post("/api/vpn/connect")
def vpn_connect(body: VpnConnectBody, _: None = Depends(require_session)) -> dict[str, Any]:
    result = vpn_service.connect(
        body.profile,
        redirect_gateway=body.redirect_gateway,
        username=body.username,
        password=body.password,
        auto_reconnect=body.auto_reconnect,
    )
    if not result.get("ok"):
        raise HTTPException(status_code=int(result.get("status", 400)), detail=result.get("error"))
    # Never log credentials.
    log_audit("vpn.connect", {"profile": body.profile, "redirect_gateway": body.redirect_gateway, "auto_reconnect": body.auto_reconnect})
    return result


@app.post("/api/vpn/auto-reconnect")
def vpn_auto_reconnect(body: VpnAutoReconnectBody, _: None = Depends(require_session)) -> dict[str, Any]:
    result = vpn_service.set_auto_reconnect(body.on)
    if not result.get("ok"):
        raise HTTPException(status_code=int(result.get("status", 400)), detail=result.get("error"))
    log_audit("vpn.auto_reconnect", {"on": body.on})
    return result


@app.post("/api/vpn/disconnect")
def vpn_disconnect(_: None = Depends(require_session)) -> dict[str, Any]:
    result = vpn_service.disconnect()
    if not result.get("ok"):
        raise HTTPException(status_code=int(result.get("status", 400)), detail=result.get("error"))
    log_audit("vpn.disconnect", {})
    return result


@app.post("/api/vpn/diagnose")
def vpn_diagnose(
    host: str = "192.168.1.203",
    port: int = 1883,
    _: None = Depends(require_session),
) -> dict[str, Any]:
    result = vpn_service.diagnose(target_host=host, target_port=port)
    if not result.get("ok"):
        raise HTTPException(status_code=int(result.get("status", 502)), detail=result.get("error"))
    log_audit("vpn.diagnose", {"host": host, "port": port, "reachable": result.get("reachable")})
    return result


@app.get("/api/detection-policy/applied")
def detection_policy_applied(_: None = Depends(require_session)) -> dict[str, Any]:
    return build_applied_detection_policy()


# --- Baseline lifecycle (MVP-1: pcap → candidate → approve / rollback) ------


class BaselineRollbackBody(BaseModel):
    version: str = Field(..., max_length=64)


@app.get("/api/baseline")
def baseline_state(_: None = Depends(require_session)) -> dict[str, Any]:
    return baseline_service.get_state()


@app.get("/api/baseline/candidate")
def baseline_candidate(_: None = Depends(require_session)) -> dict[str, Any]:
    cand = baseline_service.get_candidate()
    if cand is None:
        raise HTTPException(status_code=404, detail="尚無候選 baseline")
    return cand


@app.post("/api/baseline/learn")
async def baseline_learn(
    request: Request,
    filename: str = "capture.pcap",
    limit: int = 0,
    _: None = Depends(require_session),
) -> dict[str, Any]:
    # Stream the upload straight to disk so RAM stays flat regardless of size.
    max_bytes = baseline_service.max_pcap_bytes()
    host_pcap, fname = baseline_service.upload_target(filename)
    written = 0
    try:
        with open(host_pcap, "wb") as fh:
            async for chunk in request.stream():
                if not chunk:
                    continue
                written += len(chunk)
                if written > max_bytes:
                    raise HTTPException(status_code=413, detail=f"pcap 超過 {max_bytes // 1024 // 1024}MB 上限")
                fh.write(chunk)
    except HTTPException:
        host_pcap.unlink(missing_ok=True)
        raise
    except Exception:
        host_pcap.unlink(missing_ok=True)
        raise
    if written == 0:
        host_pcap.unlink(missing_ok=True)
        raise HTTPException(status_code=400, detail="空的 pcap 內容")

    result = baseline_service.run_learn(fname, limit=limit)
    if not result.get("ok"):
        raise HTTPException(status_code=int(result.get("status", 500)), detail=result.get("error"))
    log_audit("baseline.learn", {
        "filename": filename, "bytes": written,
        "auto_limited": result.get("auto_limited"),
        "stats": result.get("candidate", {}).get("stats", {}),
    })
    return result


@app.post("/api/baseline/approve")
def baseline_approve(_: None = Depends(require_session)) -> dict[str, Any]:
    result = baseline_service.approve_candidate()
    if not result.get("ok"):
        raise HTTPException(status_code=int(result.get("status", 500)), detail=result.get("error"))
    log_audit("baseline.approve", {"version": result.get("version")})
    return result


@app.post("/api/baseline/rollback")
def baseline_rollback(body: BaselineRollbackBody, _: None = Depends(require_session)) -> dict[str, Any]:
    result = baseline_service.rollback(body.version)
    if not result.get("ok"):
        raise HTTPException(status_code=int(result.get("status", 500)), detail=result.get("error"))
    log_audit("baseline.rollback", {"from": body.version, "version": result.get("version")})
    return result


class AssetIdentityBody(BaseModel):
    ip: str = Field(..., max_length=64)
    vendor: Optional[str] = Field(None, max_length=128)
    model: Optional[str] = Field(None, max_length=128)
    firmware: Optional[str] = Field(None, max_length=128)


class AssetProbeBody(BaseModel):
    ip: str = Field(..., max_length=64)


@app.get("/api/assets/inventory")
def assets_inventory(_: None = Depends(require_session)) -> dict[str, Any]:
    return asset_probe_service.get_inventory()


@app.put("/api/assets/identity")
def assets_identity(body: AssetIdentityBody, _: None = Depends(require_session)) -> dict[str, Any]:
    result = asset_probe_service.set_identity(body.ip, vendor=body.vendor, model=body.model, firmware=body.firmware)
    if not result.get("ok"):
        raise HTTPException(status_code=int(result.get("status", 500)), detail=result.get("error"))
    log_audit("assets.identity_set", {"ip": body.ip})
    return result


@app.post("/api/assets/probe")
def assets_probe(body: AssetProbeBody, _: None = Depends(require_session)) -> dict[str, Any]:
    result = asset_probe_service.probe(body.ip)
    if not result.get("ok"):
        raise HTTPException(status_code=int(result.get("status", 500)), detail=result.get("error"))
    log_audit("assets.probe", {"ip": body.ip, "reachable": result.get("probe", {}).get("reachable")})
    return result


@app.get("/api/baseline/drift")
def baseline_drift(_: None = Depends(require_session)) -> dict[str, Any]:
    return baseline_service.compute_drift()


@app.post("/api/baseline/approve-drift")
def baseline_approve_drift(_: None = Depends(require_session)) -> dict[str, Any]:
    result = baseline_service.approve_drift()
    if not result.get("ok"):
        raise HTTPException(status_code=int(result.get("status", 500)), detail=result.get("error"))
    log_audit("baseline.approve_drift", {"version": result.get("version")})
    return result


@app.get("/api/traffic/live")
def traffic_live(_: None = Depends(require_session)) -> dict[str, Any]:
    return read_live_traffic(store)


@app.get("/api/lab/traffic/status")
def lab_traffic_status(_: None = Depends(require_session)) -> dict[str, Any]:
    return build_lab_traffic_status(store)


@app.post("/api/lab/traffic/actions")
def lab_traffic_actions(body: LabTrafficActionBody, _: None = Depends(require_session)) -> dict[str, Any]:
    if not body.preset and not body.action:
        raise HTTPException(status_code=400, detail="action or preset required")
    try:
        result = apply_lab_traffic_action(
            action=body.action,
            targets=body.targets,
            preset=body.preset,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if result.get("error"):
        raise HTTPException(status_code=503, detail=result["error"])
    log_audit(
        "lab.traffic",
        {
            "action": body.action,
            "targets": body.targets,
            "preset": body.preset,
            "ok": result.get("ok"),
            "results": result.get("results"),
        },
    )
    if not result.get("ok"):
        raise HTTPException(status_code=503, detail="One or more docker actions failed")
    return result


@app.post("/api/sensel/ping")
def sensel_ping(_: None = Depends(require_session)) -> dict[str, Any]:
    config = store.load()
    try:
        result = ping_sensel(config)
        return {"ok": True, "result": result}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


@app.post("/api/register/test")
def register_test(body: RegisterTestBody, _: None = Depends(require_session)) -> dict[str, Any]:
    config = store.load()
    if body.save_first:
        config = store.load()
    try:
        result = register_sensor(config)
        tenant_id = str(result.get("tenant_id") or result.get("mqtt_tenant_id") or "")
        store.record_register_result(ok=True, tenant_id=tenant_id or None)
        _maybe_restart_agent()
        return {
            "ok": True,
            "tenant_id": tenant_id,
            "workspace_id": result.get("workspace_id"),
            "sensor_id": result.get("sensor_id"),
            "message": "註冊成功，感測器已綁定企業 tenant",
        }
    except Exception as exc:
        store.record_register_result(ok=False, error=str(exc)[:500])
        return {"ok": False, "error": str(exc)}


@app.post("/api/agent/restart")
def restart_agent(_: None = Depends(require_session)) -> dict[str, Any]:
    ok, detail = _restart_agent()
    if not ok:
        raise HTTPException(status_code=503, detail=detail)
    log_audit("docker.restart", {"container": os.environ.get("EDGE_AGENT_CONTAINER", "sensel-edge-agent")})
    return {"ok": True, "message": detail}


@app.get("/api/edgex/platform")
def edgex_platform(_: None = Depends(require_session)) -> dict[str, Any]:
    return build_platform()


@app.get("/api/edgex/protocols")
def edgex_protocols(_: None = Depends(require_session)) -> dict[str, Any]:
    return build_protocol_matrix()


@app.get("/api/edgex/devices")
def edgex_devices(_: None = Depends(require_session)) -> dict[str, Any]:
    return list_devices()


@app.get("/api/edgex/devices/{device_name}/readings")
def edgex_device_readings(
    device_name: str,
    limit: int = 10,
    _: None = Depends(require_session),
) -> dict[str, Any]:
    return get_device_readings(device_name, limit=limit)


@app.post("/api/edgex/actions/restart/{container}")
def edgex_restart_container(container: str, _: None = Depends(require_session)) -> dict[str, Any]:
    ok, detail = restart_edgex_container(container)
    if not ok:
        raise HTTPException(status_code=400 if "not allowed" in detail.lower() else 503, detail=detail)
    log_audit("docker.restart", {"container": container})
    return {"ok": True, "message": detail}


@app.post("/api/edgex/actions/start/{container}")
def edgex_start_container(container: str, _: None = Depends(require_session)) -> dict[str, Any]:
    ok, detail = start_edgex_container(container)
    if not ok:
        raise HTTPException(status_code=400 if "not allowed" in detail.lower() else 503, detail=detail)
    log_audit("docker.start", {"container": container})
    return {"ok": True, "message": detail}


@app.get("/api/edgex/actions/logs/{container}")
def edgex_container_logs(
    container: str,
    tail: int = 200,
    _: None = Depends(require_session),
) -> dict[str, Any]:
    ok, text = container_logs(container, tail=tail)
    if not ok:
        raise HTTPException(status_code=400 if "not allowed" in text.lower() else 503, detail=text)
    return {"ok": True, "container": container, "logs": text}


@app.get("/api/edgex/config/devices")
def edgex_config_devices_list(_: None = Depends(require_session)) -> dict[str, Any]:
    return list_config_devices()


@app.post("/api/edgex/config/devices")
def edgex_config_devices_upsert(body: DeviceConfigBody, _: None = Depends(require_session)) -> dict[str, Any]:
    try:
        result = upsert_config_device(body.model_dump(exclude_none=True))
        log_audit("edgex.device_upsert", {"name": result.get("name"), "protocol": result.get("protocol")})
        return result
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.delete("/api/edgex/config/devices/{device_name}")
def edgex_config_devices_delete(device_name: str, _: None = Depends(require_session)) -> dict[str, Any]:
    try:
        result = delete_config_device(device_name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not result.get("ok"):
        raise HTTPException(status_code=404, detail=result.get("error", "not found"))
    log_audit("edgex.device_delete", {"name": device_name})
    return result


@app.post("/api/edgex/diagnostics/connect")
def edgex_diagnostics_connect(body: ConnectivityBody, _: None = Depends(require_session)) -> dict[str, Any]:
    return probe_connectivity(body.protocol, body.host, body.port)


@app.get("/api/edgex/diagnostics/suite")
def edgex_diagnostics_suite(_: None = Depends(require_session)) -> dict[str, Any]:
    return run_connectivity_suite()


@app.get("/api/edgex/wizard/templates")
def edgex_wizard_templates(_: None = Depends(require_session)) -> dict[str, Any]:
    return get_wizard_templates()


@app.get("/api/edgex/phase2/status")
def edgex_phase2_status(_: None = Depends(require_session)) -> dict[str, Any]:
    return phase2_status()


@app.post("/api/edgex/phase2/enable")
def edgex_phase2_enable(_: None = Depends(require_session)) -> dict[str, Any]:
    result = enable_phase2_services()
    if not result.get("ok"):
        raise HTTPException(status_code=503, detail=result.get("error", "enable failed"))
    log_audit("edgex.phase2_enable", {})
    return result


@app.get("/api/edgex/discovery")
def edgex_discovery(_: None = Depends(require_session)) -> dict[str, Any]:
    return build_discovery(store)


@app.get("/api/audit/recent")
def audit_recent(limit: int = 30, _: None = Depends(require_session)) -> dict[str, Any]:
    entries = read_audit_recent(limit=min(limit, 100))
    return {"count": len(entries), "entries": entries}


@app.get("/api/events/recent")
def recent_events(limit: int = 50, _: None = Depends(require_session)) -> dict[str, Any]:
    assets = Path(os.environ.get("ASSETS_DIR", "/data/assets"))
    events = read_jsonl_tail(assets / "security-events.jsonl", limit=min(limit, 200))
    device_payload = list_devices(enrich_telemetry=False)
    ip_map = build_ip_device_map(device_payload.get("devices") or [])
    enriched = enrich_events(events, ip_map)
    return {"count": len(enriched), "events": enriched}


@app.post("/api/test-event")
def emit_test_event(_: None = Depends(require_session)) -> dict[str, Any]:
    """Emit a synthetic OT security event into the REAL upload pipeline so the
    operator can confirm end-to-end northbound delivery (edge → SenseL).

    The event is appended to the same ``security-events.jsonl`` the edge-agent
    tails, so it travels the exact same HTTP + northbound-MQTT path as a genuine
    detection. It is flagged ``synthetic`` so the platform can tell it apart
    from real findings.
    """
    config = store.load()
    assets = Path(os.environ.get("ASSETS_DIR", "/data/assets"))
    events_file = assets / "security-events.jsonl"
    now = datetime.now(timezone.utc).isoformat()
    event = {
        "event_id": f"test-{uuid.uuid4().hex[:12]}",
        "site_id": config.site_id,
        "sensor_id": config.sensor_id,
        "asset_id": "console-test",
        "event_type": "console_test_event",
        "severity": "high",
        "risk_score": 75,
        "protocol": "synthetic",
        "src_ip": "203.0.113.10",
        "dst_ip": "203.0.113.20",
        "dst_port": 502,
        "rule_id": "OT-TEST-000",
        "description": "Edge Console 測試事件（synthetic）— 驗證北向上傳鏈路",
        "evidence": {"synthetic": True, "source": "edge-console", "note": "manual connectivity test"},
        "synthetic": True,
        "timestamp": now,
    }
    try:
        events_file.parent.mkdir(parents=True, exist_ok=True)
        with events_file.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, ensure_ascii=False) + "\n")
    except OSError as exc:
        raise HTTPException(
            status_code=503,
            detail=f"無法寫入事件檔（請確認 data/assets 為可寫掛載）：{exc}",
        ) from exc
    log_audit("test_event.emit", {"event_id": event["event_id"], "rule_id": event["rule_id"]})
    northbound_ready = bool(config.mqtt_enabled and config.last_register_ok)
    message = "測試事件已寫入，Edge Agent 會在數秒內上傳至 SenseL。"
    if not northbound_ready:
        message += "（注意：北向尚未啟用或感測器未註冊，事件目前僅在本機可見）"
    return {
        "ok": True,
        "event": event,
        "northbound_ready": northbound_ready,
        "message": message,
    }


@app.get("/api/coverage")
def coverage(_: None = Depends(require_session)) -> dict[str, Any]:
    """Edge BAS coverage tally (per-rule / per-ATT&CK, pre-aggregation).

    Served straight from the packet-sensor's ``coverage-counters.json`` so the
    raw detection volume is not lost to Control-Plane episode aggregation.
    """
    assets = Path(os.environ.get("ASSETS_DIR", "/data/assets"))
    path = assets / "coverage-counters.json"
    if not path.exists():
        return {"available": False, "schema": "ot-edge.coverage.v1", "techniques": {}, "rules": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"available": False, "schema": "ot-edge.coverage.v1", "techniques": {}, "rules": {}}
    data["available"] = True
    return data


def _restart_agent() -> tuple[bool, str]:
    return _restart_container(os.environ.get("EDGE_AGENT_CONTAINER", "sensel-edge-agent"))


def _restart_container(container: str) -> tuple[bool, str]:
    if os.environ.get("EDGE_CONSOLE_DOCKER_RESTART", "").lower() not in ("1", "true", "yes"):
        return False, f"Docker restart disabled; restart {container} manually"
    sock = Path("/var/run/docker.sock")
    if not sock.exists():
        return False, "Docker socket not mounted"
    try:
        subprocess.run(
            ["docker", "restart", container],
            check=True,
            capture_output=True,
            text=True,
            timeout=60,
        )
        return True, f"Restarted {container}"
    except subprocess.CalledProcessError as exc:
        return False, (exc.stderr or exc.stdout or str(exc))[:300]
    except FileNotFoundError:
        return False, "docker CLI not available"


def _maybe_restart_agent() -> None:
    if os.environ.get("EDGE_CONSOLE_AUTO_RESTART_AGENT", "").lower() in ("1", "true", "yes"):
        _restart_agent()


if STATIC_DIR.is_dir():
    app.mount("/assets", StaticFiles(directory=STATIC_DIR), name="assets")


@app.get("/")
def index() -> FileResponse:
    index_path = STATIC_DIR / "index.html"
    if not index_path.is_file():
        raise HTTPException(status_code=404, detail="UI not found")
    return FileResponse(index_path)


@app.get("/style.css")
def style_css() -> FileResponse:
    return FileResponse(STATIC_DIR / "style.css")


@app.get("/tokens.css")
def tokens_css() -> FileResponse:
    return FileResponse(STATIC_DIR / "tokens.css")


@app.get("/app.js")
def app_js() -> FileResponse:
    return FileResponse(STATIC_DIR / "app.js")
