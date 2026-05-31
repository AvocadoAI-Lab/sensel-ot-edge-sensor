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
from src.status_service import build_status, _read_jsonl_tail

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
        return {"ok": True}
    if not verify_password(body.password):
        raise HTTPException(status_code=401, detail="Invalid password")
    create_session(response)
    return {"ok": True}


@app.post("/api/auth/logout")
def logout(response: Response, _: None = Depends(require_session)) -> dict[str, bool]:
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
    return {"ok": True}


@app.post("/api/capture/reload")
def reload_capture(_: None = Depends(require_session)) -> dict[str, Any]:
    ok, detail = _restart_container(os.environ.get("PACKET_SENSOR_CONTAINER", "sensel-packet-sensor"))
    if not ok:
        raise HTTPException(status_code=503, detail=detail)
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
    return {"ok": True, "message": detail}


@app.get("/api/events/recent")
def recent_events(limit: int = 50, _: None = Depends(require_session)) -> dict[str, Any]:
    assets = Path(os.environ.get("ASSETS_DIR", "/data/assets"))
    events = _read_jsonl_tail(assets / "security-events.jsonl", limit=min(limit, 200))
    return {"count": len(events), "events": events}


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


@app.get("/app.js")
def app_js() -> FileResponse:
    return FileResponse(STATIC_DIR / "app.js")
