#!/usr/bin/env python3
"""Lab detect mode + topology_delta MQTT E2E (PRD §6.1 Phase 2).

Transitions sensor to detect (if needed), waits for Pi delta publish, then runs verify gate.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]

BASE = os.environ.get("CONTROL_PLANE_BASE_URL", "http://192.168.1.108:8081").rstrip("/")
EDGE = os.environ.get("EDGE_CONSOLE_URL", "http://192.168.1.124:8090").rstrip("/")
WS = int(os.environ.get("WORKSPACE_ID", "6"))
TENANT = os.environ.get("TENANT_ID", "company-a9ae1234648ee138")
SENSOR = os.environ.get("BASELINE_SENSOR_ID", "ot-edge-001")
EMAIL = os.environ.get("PORTAL_EMAIL", "")
PASSWORD = os.environ.get("PORTAL_PASSWORD", "")
EDGE_SSH_HOST = os.environ.get("EDGE_SSH_HOST", "192.168.1.124")
EDGE_SSH_USER = os.environ.get("EDGE_SSH_USER", "edgex")
EDGE_DELTA_STATE = os.environ.get(
    "EDGE_TOPOLOGY_SNAPSHOT_STATE_PATH",
    "/home/edgex/sensel-ot-edge-sensor/data/agent/topology-snapshot-state.json",
)
WAIT_SEC = int(os.environ.get("DETECT_DELTA_WAIT_SEC", "360"))
POLL_SEC = int(os.environ.get("DETECT_DELTA_POLL_SEC", "15"))


def api(method: str, path: str, token: str, body: dict | None = None) -> Any:
    url = BASE + path
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Workspace-Id": str(WS),
        "Accept": "application/json",
        "Accept-Language": "zh-TW",
    }
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body, ensure_ascii=False).encode()
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=60) as resp:
        raw = resp.read().decode()
        return json.loads(raw) if raw.strip() else {}


def plain(url: str) -> Any:
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode())


def login() -> str:
    token = (os.environ.get("PORTAL_BEARER_TOKEN") or "").strip()
    if token:
        return token
    if not EMAIL or not PASSWORD:
        raise RuntimeError("Set PORTAL_BEARER_TOKEN or PORTAL_EMAIL/PORTAL_PASSWORD")
    req = urllib.request.Request(
        BASE + "/api/v1/smb/auth/login",
        data=json.dumps({"email": EMAIL, "password": PASSWORD}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return str(json.loads(resp.read().decode())["access_token"])


def edge_mode() -> str:
    st = plain(f"{EDGE}/api/status")
    op = st.get("operational_mode")
    if isinstance(op, dict):
        return str(op.get("operational_mode") or "")
    return str(op or "")


def read_pi_delta_state() -> dict[str, Any]:
    sshpass = os.environ.get("PI_SSHPASS", os.environ.get("SSHPASS", "edgex"))
    cmd = [
        "sshpass",
        "-p",
        sshpass,
        "ssh",
        "-o",
        "StrictHostKeyChecking=accept-new",
        f"{EDGE_SSH_USER}@{EDGE_SSH_HOST}",
        f"cat {EDGE_DELTA_STATE}",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=25)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip()[:300] or "ssh failed")
    return json.loads(proc.stdout)


def stop_active_session(token: str) -> str | None:
    ot = f"/api/v1/smb/workspaces/{WS}/ot-security"
    sessions = api("GET", f"{ot}/sessions", token)
    items = sessions.get("items") if isinstance(sessions, dict) else []
    for row in items or []:
        if not isinstance(row, dict):
            continue
        if str(row.get("sensor_id") or "") != SENSOR:
            continue
        if str(row.get("status") or "") not in ("active", "running", "observe", "learning"):
            continue
        sid = str(row.get("id") or "").strip()
        if not sid:
            continue
        stopped = api("POST", f"{ot}/sessions/{urllib.parse.quote(sid)}/stop", token)
        return str(stopped.get("profile_id") or sid)
    return None


def pick_apply_profile(token: str) -> str:
    ot = f"/api/v1/smb/workspaces/{WS}/ot-security"
    profiles = api("GET", f"{ot}/baseline-profiles?sensor_id={urllib.parse.quote(SENSOR)}", token)
    items = profiles.get("items") if isinstance(profiles, dict) else []
    for status in ("approved", "applied", "draft"):
        for row in items or []:
            if not isinstance(row, dict):
                continue
            if str(row.get("status") or "") != status:
                continue
            pid = str(row.get("id") or "").strip()
            if pid:
                return pid
    raise RuntimeError("no baseline profile available for detect apply")


def ensure_detect_mode(token: str) -> str:
    ot = f"/api/v1/smb/workspaces/{WS}/ot-security"
    state = api("GET", f"{ot}/sensors/{urllib.parse.quote(SENSOR)}/operational-state", token)
    mode = str(state.get("mode") or "")
    emode = edge_mode()
    if mode == "detect" and emode == "detect":
        print(f"OK  already in detect mode profile={state.get('baseline_profile_id')} edge={emode}")
        return str(state.get("baseline_profile_id") or "")

    print(f"==> transition to detect (portal={mode or '?'} edge={emode or '?'})")
    stopped = stop_active_session(token)
    if stopped:
        print(f"OK  stopped active session profile_hint={stopped}")

    profile_id = pick_apply_profile(token)
    row = None
    for item in api("GET", f"{ot}/baseline-profiles?sensor_id={urllib.parse.quote(SENSOR)}", token).get("items") or []:
        if str(item.get("id") or "") == profile_id:
            row = item
            break
    status = str((row or {}).get("status") or "")
    if status == "draft":
        api("POST", f"{ot}/baseline-profiles/{urllib.parse.quote(profile_id)}/approve", token)
        print(f"OK  approved draft profile {profile_id}")

    applied = api("POST", f"{ot}/baseline-profiles/{urllib.parse.quote(profile_id)}/apply", token)
    print(f"OK  applied profile {profile_id} mqtt={applied.get('operational_mqtt_topic')}")
    try:
        op = api(
            "POST",
            f"{ot}/sensors/{urllib.parse.quote(SENSOR)}/operational-mode",
            token,
            {"baseline_profile_id": profile_id},
        )
        print(f"OK  set operational-mode detect mqtt={op.get('mqtt_topic')}")
    except urllib.error.HTTPError as exc:
        if exc.code not in (409, 503):
            raise

    deadline = time.time() + 90
    while time.time() < deadline:
        mode = str(
            api("GET", f"{ot}/sensors/{urllib.parse.quote(SENSOR)}/operational-state", token).get("mode") or ""
        )
        emode = edge_mode()
        if mode == "detect" and emode == "detect":
            print(f"OK  detect mode confirmed portal={mode} edge={emode}")
            return profile_id
        time.sleep(5)
    raise TimeoutError(f"detect mode not reached portal={mode!r} edge={edge_mode()!r}")


def wait_for_delta_publish() -> dict[str, Any]:
    deadline = time.time() + WAIT_SEC
    last_err = ""
    while time.time() < deadline:
        try:
            state = read_pi_delta_state()
            mode = str(state.get("operational_mode") or "")
            delta = state.get("last_topology_delta")
            published_at = state.get("last_delta_publish_at")
            print(
                f"  poll mode={mode} delta={delta!r} "
                f"published_at={published_at or '-'}"
            )
            if mode == "detect" and isinstance(delta, dict) and published_at:
                return state
        except Exception as exc:
            last_err = str(exc)
            print(f"  poll warn: {exc}")
        time.sleep(POLL_SEC)
    raise TimeoutError(f"topology delta not published within {WAIT_SEC}s ({last_err})")


def run_verify_gate() -> int:
    verify_py = ROOT / "scripts" / "verify_baseline_live_learning_lab.py"
    cmd = [
        sys.executable,
        str(verify_py),
        "--expect-mode",
        "detect",
        "--expect-topology",
        "--expect-topology-views",
        "--expect-topology-delta-edge",
        "--expect-edr-match",
        "--edr-match-scenario",
        os.environ.get("EDR_MATCH_SCENARIO", "windows-hmi"),
        "--sensor-id",
        SENSOR,
        "--min-topology-assets",
        "2",
        "--min-topology-conduits",
        "1",
    ]
    env = os.environ.copy()
    proc = subprocess.run(cmd, cwd=str(ROOT), env=env)
    return int(proc.returncode)


def main() -> int:
    print("==> Detect topology_delta lab E2E")
    try:
        token = login()
        print("OK  Portal login")
    except Exception as exc:
        print(f"FAIL login: {exc}", file=sys.stderr)
        return 1

    try:
        profile_id = ensure_detect_mode(token)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")[:400]
        print(f"FAIL detect transition HTTP {exc.code}: {body}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"FAIL detect transition: {exc}", file=sys.stderr)
        return 1

    print(f"==> wait Pi topology_delta publish (max {WAIT_SEC}s)")
    try:
        state = wait_for_delta_publish()
        print(
            f"OK  Pi delta state mode={state.get('operational_mode')} "
            f"delta={state.get('last_topology_delta')}"
        )
    except Exception as exc:
        print(f"FAIL wait delta: {exc}", file=sys.stderr)
        return 1

    print("==> verify gate")
    rc = run_verify_gate()
    if rc == 0:
        print(f"\n==> DETECT TOPOLOGY_DELTA PASSED (profile={profile_id})")
    else:
        print("\n==> DETECT TOPOLOGY_DELTA FAILED (verify gate)", file=sys.stderr)
    return rc


if __name__ == "__main__":
    sys.exit(main())
