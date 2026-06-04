"""SenseL Edge Console — local setup wizard and appliance dashboard."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any, Optional

from fastapi import Cookie, Depends, FastAPI, HTTPException, Response
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
    get_device_readings,
    list_devices,
    restart_edgex_container,
)
from src.audit_service import log_audit, read_audit_recent
from src.discovery_service import build_discovery, build_ip_device_map, enrich_events
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
store = ConfigStore()

app = FastAPI(title="SenseL Edge Console", version=APP_VERSION)


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


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "edge-console", "version": APP_VERSION}


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
