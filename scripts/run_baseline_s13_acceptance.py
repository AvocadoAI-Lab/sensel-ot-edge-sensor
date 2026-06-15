#!/usr/bin/env python3
"""Automate PRD §13 baseline live learning lab acceptance via Portal BFF."""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

BASE = os.environ.get("CONTROL_PLANE_BASE_URL", "http://192.168.1.108:8081").rstrip("/")
LAYERC = os.environ.get("LAYERC_URL", "http://192.168.1.203:8001").rstrip("/")
EDGE = os.environ.get("EDGE_CONSOLE_URL", "http://192.168.1.124:8090").rstrip("/")
WS = int(os.environ.get("WORKSPACE_ID", "6"))
TENANT = os.environ.get("TENANT_ID", "company-a9ae1234648ee138")
SENSOR = os.environ.get("BASELINE_SENSOR_ID", "ot-edge-001")
EMAIL = os.environ.get("PORTAL_EMAIL", "ericmao2023@outlook.com")
PASSWORD = os.environ.get("PORTAL_PASSWORD", "LabBaseline2026!")
MIN_TICKS = int(os.environ.get("S13_MIN_TICKS", "3"))
TICK_WAIT_SEC = int(os.environ.get("S13_TICK_WAIT_SEC", "70"))


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
    req = urllib.request.Request(
        BASE + "/api/v1/smb/auth/login",
        data=json.dumps({"email": EMAIL, "password": PASSWORD}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return str(json.loads(resp.read().decode())["access_token"])


def cta_detected() -> int:
    cta = plain(f"{LAYERC}/api/cta/coverage?tenant_id={TENANT}")
    return int((cta.get("summary") or {}).get("detected") or 0)


def edge_mode() -> str:
    st = plain(f"{EDGE}/api/status")
    op = st.get("operational_mode")
    if isinstance(op, dict):
        return str(op.get("operational_mode") or "")
    return str(op or "")


def wait_ticks(token: str, session_id: str, need: int, label: str) -> int:
    ot = f"/api/v1/smb/workspaces/{WS}/ot-security"
    deadline = time.time() + need * TICK_WAIT_SEC + 120
    last = 0
    while time.time() < deadline:
        ticks = api("GET", f"{ot}/sessions/{urllib.parse.quote(session_id)}/ticks", token)
        items = ticks.get("items") if isinstance(ticks, dict) else []
        count = len(items) if isinstance(items, list) else 0
        if count != last:
            print(f"  [{label}] ticks={count}/{need}")
            last = count
        if count >= need:
            return count
        time.sleep(15)
    raise TimeoutError(f"{label}: only {last}/{need} ticks after timeout")


def main() -> int:
    ot = f"/api/v1/smb/workspaces/{WS}/ot-security"
    print("==> §13 Baseline Live Learning acceptance")
    token = login()
    print("OK  Portal login")

    cta_before = cta_detected()
    print(f"OK  CTA detected baseline={cta_before}")

    print("==> Step 1: start listen session")
    start = api(
        "POST",
        f"{ot}/sensors/{urllib.parse.quote(SENSOR)}/observe-sessions",
        token,
        {"capture_interface": "eth0", "min_ticks_required": MIN_TICKS},
    )
    session = start.get("session") or {}
    session_id = str(session.get("id") or "")
    if not session_id:
        print("FAIL no session_id", start, file=sys.stderr)
        return 1
    print(f"OK  session={session_id} kind={session.get('kind')} status={session.get('status')}")

    print("==> Step 5: probe 409 duplicate session")
    try:
        api(
            "POST",
            f"{ot}/sensors/{urllib.parse.quote(SENSOR)}/observe-sessions",
            token,
            {"capture_interface": "eth0", "min_ticks_required": MIN_TICKS},
        )
        print("FAIL second observe should 409", file=sys.stderr)
        return 1
    except urllib.error.HTTPError as exc:
        if exc.code != 409:
            print(f"FAIL expected 409 got {exc.code}", file=sys.stderr)
            return 1
    print("OK  duplicate observe -> 409")

    time.sleep(10)
    mode = edge_mode()
    print(f"OK  Edge mode after start: {mode}")
    if mode != "listen":
        print(f"WARN expected listen, got {mode!r}", file=sys.stderr)

    print("==> Step 1: wait observe ticks (listen)")
    wait_ticks(token, session_id, MIN_TICKS, "listen")
    cta_mid = cta_detected()
    if cta_mid > cta_before:
        print(f"FAIL CTA detected grew during listen: {cta_before} -> {cta_mid}", file=sys.stderr)
        return 1
    print(f"OK  CTA stable during listen ({cta_before} -> {cta_mid})")

    print("==> Step 2: promote to learning")
    promoted = api(
        "POST",
        f"{ot}/observe-sessions/{urllib.parse.quote(session_id)}/promote-to-learning",
        token,
    )
    ps = promoted.get("session") or {}
    print(f"OK  promoted status={ps.get('status')} kind={ps.get('kind')}")
    time.sleep(15)
    print(f"OK  Edge mode: {edge_mode()}")

    print("==> Step 2: wait ticks (learning)")
    wait_ticks(token, session_id, MIN_TICKS * 2, "learning")
    cta_learn = cta_detected()
    if cta_learn > cta_before:
        print(f"FAIL CTA grew during learning: {cta_before} -> {cta_learn}", file=sys.stderr)
        return 1
    print(f"OK  CTA stable during learning ({cta_learn})")

    print("==> Step 3: stop session -> draft profile")
    stopped = api("POST", f"{ot}/sessions/{urllib.parse.quote(session_id)}/stop", token)
    profile_id = str(stopped.get("profile_id") or "")
    print(f"OK  stopped profile_id={profile_id or '(pending)'}")
    if not profile_id:
        profiles = api("GET", f"{ot}/baseline-profiles", token)
        for row in profiles.get("items") or []:
            if str(row.get("status") or "") == "draft":
                profile_id = str(row.get("id") or "")
                break
    if not profile_id:
        print("FAIL no draft profile after stop", file=sys.stderr)
        return 1

    print("==> Step 3: approve + apply -> detect")
    api("POST", f"{ot}/baseline-profiles/{urllib.parse.quote(profile_id)}/approve", token)
    print(f"OK  approved profile {profile_id}")
    applied = api("POST", f"{ot}/baseline-profiles/{urllib.parse.quote(profile_id)}/apply", token)
    print(f"OK  apply mqtt={applied.get('operational_mqtt_topic')}")

    time.sleep(20)
    state = api(
        "GET",
        f"{ot}/sensors/{urllib.parse.quote(SENSOR)}/operational-state",
        token,
    )
    mode = str(state.get("mode") or "")
    got_profile = str(state.get("baseline_profile_id") or "")
    print(f"OK  operational-state mode={mode} profile={got_profile}")
    if mode != "detect":
        print(f"FAIL expected detect got {mode!r}", file=sys.stderr)
        return 1
    if got_profile != profile_id:
        print(f"WARN profile id mismatch portal={got_profile} expected={profile_id}", file=sys.stderr)

    emode = edge_mode()
    print(f"OK  Edge Console mode={emode}")
    if emode != "detect":
        print(f"WARN Edge Console mode={emode!r}", file=sys.stderr)

    print("==> Step 4: event metadata (best-effort)")
    events = api("GET", f"{ot}/events?limit=30", token)
    found_meta = False
    for ev in events.get("items") or []:
        raw = ev.get("raw_event") if isinstance(ev.get("raw_event"), dict) else {}
        payload = raw.get("payload") if isinstance(raw.get("payload"), dict) else {}
        episode = payload.get("episode") if isinstance(payload.get("episode"), dict) else {}
        ctx = episode.get("context") if isinstance(episode.get("context"), dict) else {}
        if ctx.get("baseline_profile_id") or raw.get("baseline_profile_id"):
            found_meta = True
            print(f"OK  event metadata baseline_profile_id present")
            break
    if not found_meta:
        print("WARN no event with baseline_profile_id yet (detect traffic may need more time)")

    print("\n==> §13 CORE PASSED")
    print(f"    profile_id={profile_id}")
    print(f"    CTA detected: {cta_before} -> {cta_detected()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
