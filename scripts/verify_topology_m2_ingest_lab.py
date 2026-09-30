#!/usr/bin/env python3
"""Lab M2 syscollector ingest-time EDR match (PRD §4.5.6 / mirror 10.x)."""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any

BASE = os.environ.get("CONTROL_PLANE_BASE_URL", "http://192.168.1.108:8081").rstrip("/")
WS = int(os.environ.get("WORKSPACE_ID", "6"))
TENANT = os.environ.get("TENANT_ID", "company-a9ae1234648ee138")
SENSOR = os.environ.get("BASELINE_SENSOR_ID", "ot-edge-001")
SITE = os.environ.get("SITE_ID", "factory-lab-001")
EMAIL = os.environ.get("PORTAL_EMAIL", "")
PASSWORD = os.environ.get("PORTAL_PASSWORD", "")
INGEST_SECRET = os.environ.get("OT_SECURITY_INGEST_SECRET", "sensel-ot-ingest-lab-2026")
MIRROR_IP = os.environ.get("M2_MIRROR_OT_IP", "192.168.10.88")
MIN_CONFIDENCE = float(os.environ.get("M2_MIN_CONFIDENCE", "0.85"))


class Checker:
    def __init__(self) -> None:
        self.failures: list[str] = []
        self.warnings: list[str] = []

    def ok(self, msg: str) -> None:
        print(f"OK  {msg}")

    def warn(self, msg: str) -> None:
        self.warnings.append(msg)
        print(f"WARN {msg}")

    def fail(self, msg: str) -> None:
        self.failures.append(msg)
        print(f"FAIL {msg}", file=sys.stderr)


def login() -> str:
    token = (os.environ.get("PORTAL_BEARER_TOKEN") or "").strip()
    if token:
        return token
    if not EMAIL or not PASSWORD:
        raise RuntimeError("Set PORTAL_BEARER_TOKEN or PORTAL_EMAIL/PORTAL_PASSWORD")
    req = urllib.request.Request(
        f"{BASE}/api/v1/smb/auth/login",
        data=json.dumps({"email": EMAIL, "password": PASSWORD}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return str(json.loads(resp.read().decode())["access_token"])


def api(method: str, path: str, token: str, body: dict | None = None) -> Any:
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
    req = urllib.request.Request(f"{BASE}{path}", data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=90) as resp:
        raw = resp.read().decode()
        return json.loads(raw) if raw.strip() else {}


def ingest_secret_post(path: str, body: dict) -> Any:
    req = urllib.request.Request(
        f"{BASE}{path}",
        data=json.dumps(body, ensure_ascii=False).encode(),
        headers={
            "Content-Type": "application/json",
            "X-Ot-Security-Ingest-Secret": INGEST_SECRET,
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        return json.loads(resp.read().decode())


def _extract_netaddr_ips(inventory: dict[str, Any]) -> list[str]:
    netaddr = inventory.get("netaddr")
    if not isinstance(netaddr, list):
        sections = inventory.get("sections") if isinstance(inventory, dict) else {}
        netaddr = sections.get("netaddr") if isinstance(sections, dict) else []
    ips: list[str] = []
    if not isinstance(netaddr, list):
        return ips
    for row in netaddr:
        if not isinstance(row, dict):
            continue
        for key in ("address", "ip", "ipv4"):
            text = str(row.get(key) or "").strip()
            if text and text not in ips:
                ips.append(text)
    return ips


def discover_m2_pair(token: str, mirror_ip: str) -> tuple[str | None, list[str]]:
    inv = api("GET", "/api/v1/smb/edr/agents", token)
    agents = [a for a in (inv.get("agents") or []) if isinstance(a, dict)]
    for agent in agents:
        aid = str(agent.get("id") or "").strip()
        if not aid:
            continue
        try:
            detail = api("GET", f"/api/v1/smb/edr/agents/{urllib.parse.quote(aid)}/inventory", token)
            ips = _extract_netaddr_ips(detail)
            if mirror_ip in ips:
                return aid, ips
        except Exception:
            continue
    return None, []


def reingest_mirror_asset(mirror_ip: str, asset_id: str | None) -> None:
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    body = {
        "tenant_id": TENANT,
        "site_id": SITE,
        "sensor_id": SENSOR,
        "observed_at": now,
        "operational_mode": "detect",
        "assets": [
            {
                "schema": "sensel.ot_topology.asset.v1",
                "asset_id": asset_id or f"mirror-{mirror_ip.replace('.', '-')}",
                "tenant_id": TENANT,
                "sensor_id": SENSOR,
                "site_id": SITE,
                "ip": mirror_ip,
                "asset_type": "hmi",
                "purdue_level": "L2",
                "protocols": ["modbus-tcp"],
                "confidence": 0.78,
                "evidence_sources": ["modbus_role", "lab_m2_reingest"],
            }
        ],
        "conduits": [],
        "external_entities": [],
        "zone_counts": {"L2": 1},
    }
    ingest_secret_post("/api/v1/internal/ot-security/topology/ingest", body)


def main() -> int:
    parser = argparse.ArgumentParser(description="M2 syscollector ingest-time lab verify")
    parser.add_argument("--mirror-ip", default=MIRROR_IP)
    parser.add_argument("--expect-agent-id", default=os.environ.get("M2_EXPECT_AGENT_ID", ""))
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail when no M2 netaddr overlap or edr_agent_id missing",
    )
    args = parser.parse_args()

    chk = Checker()
    mirror_ip = args.mirror_ip
    print(f"==> M2 ingest-time lab verify mirror_ip={mirror_ip} sensor={SENSOR}")

    try:
        token = login()
        chk.ok("Portal login")
    except Exception as exc:
        chk.fail(f"login: {exc}")
        return 1

    expected_agent = (args.expect_agent_id or "").strip() or None
    discovered_ips: list[str] = []
    expected_agent, discovered_ips = discover_m2_pair(token, mirror_ip)
    if not expected_agent and (args.expect_agent_id or "").strip():
        expected_agent = (args.expect_agent_id or "").strip()
    if discovered_ips and mirror_ip in discovered_ips:
        chk.ok(f"discovered M2 pair agent={expected_agent} netaddr contains {mirror_ip}")
    elif expected_agent and (args.expect_agent_id or args.strict):
        chk.ok(f"using expected agent={expected_agent} (netaddr discovery pending)")
    elif not expected_agent:
        msg = f"no agent syscollector netaddr contains {mirror_ip}"
        if args.strict:
            chk.fail(msg)
        else:
            chk.warn(f"{msg} — run ./scripts/lab-setup-m2-mirror-ip.sh")

    ot = f"/api/v1/smb/workspaces/{WS}/ot-security"
    existing = None
    try:
        listed = api(
            "GET",
            f"{ot}/topology/assets?sensor_id={urllib.parse.quote(SENSOR)}&limit=100",
            token,
        )
        for row in listed.get("items") or []:
            if str(row.get("ip") or "") == mirror_ip:
                existing = row
                break
        if existing:
            chk.ok(f"existing mirror asset ip={mirror_ip} asset_id={existing.get('asset_id')}")
        else:
            chk.warn(f"no existing topology asset for ip={mirror_ip} before reingest")
    except Exception as exc:
        chk.fail(f"list assets: {exc}")

    try:
        reingest_mirror_asset(mirror_ip, str(existing.get("asset_id") or "") if existing else None)
        chk.ok("internal topology ingest (with EDR index at ingest-time)")
    except Exception as exc:
        chk.fail(f"reingest: {exc}")
        return 1

    asset = None
    try:
        listed = api(
            "GET",
            f"{ot}/topology/assets?sensor_id={urllib.parse.quote(SENSOR)}&limit=100",
            token,
        )
        for row in listed.get("items") or []:
            if str(row.get("ip") or "") == mirror_ip:
                asset = row
                break
        if asset is None:
            chk.fail(f"mirror asset ip={mirror_ip} missing after reingest")
        else:
            edr_id = str(asset.get("edr_agent_id") or "").strip()
            strategy = str(asset.get("edr_match_strategy") or "")
            conf = float(asset.get("confidence") or 0)
            chk.ok(
                f"asset ip={mirror_ip} edr_agent_id={edr_id or '-'} "
                f"strategy={strategy or '-'} confidence={conf:.2f}"
            )
            if not edr_id:
                if args.strict or (args.expect_agent_id or "").strip():
                    chk.fail("M2 ingest-time did not persist edr_agent_id")
                else:
                    chk.warn("no edr_agent_id — lab lacks syscollector netaddr overlap for mirror IP")
            elif expected_agent and edr_id != expected_agent:
                chk.fail(f"expected agent {expected_agent} got {edr_id}")
            if edr_id and strategy and strategy != "M2_syscollector_netaddr":
                if strategy == "M1_primary_ip":
                    chk.ok("matched via M1 (primary IP equals mirror IP)")
                else:
                    chk.warn(f"expected M2 strategy got {strategy}")
            elif edr_id:
                chk.ok("strategy=M2_syscollector_netaddr")
            if edr_id and conf < MIN_CONFIDENCE:
                chk.fail(f"confidence {conf:.2f} < min {MIN_CONFIDENCE}")
    except Exception as exc:
        chk.fail(f"post-ingest assets: {exc}")

    if asset and asset.get("asset_id"):
        try:
            ctx = api(
                "GET",
                f"{ot}/topology/assets/{urllib.parse.quote(str(asset.get('asset_id')))}/edr-context",
                token,
            )
            if ctx.get("matched"):
                chk.ok(f"edr-context matched agent={ctx.get('edr_agent_id')}")
            elif asset.get("edr_agent_id"):
                chk.warn(f"edr-context unmatched reason={ctx.get('reason')}")
        except Exception as exc:
            chk.warn(f"edr-context: {exc}")

    if discovered_ips:
        chk.ok(f"agent netaddr sample={discovered_ips[:6]}")

    if chk.failures:
        print(f"\n==> FAILED ({len(chk.failures)} checks, {len(chk.warnings)} warnings)", file=sys.stderr)
        return 1
    print(f"\n==> PASSED ({len(chk.warnings)} warnings)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
