#!/usr/bin/env python3
"""Lab CVE context gate — edr-context vulnerability_summary + graph vuln_badge (PRD Phase 2)."""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
from typing import Any

from topology_edr_lab_checks import run_cve_context_checks

BASE = os.environ.get("CONTROL_PLANE_BASE_URL", "http://192.168.1.108:8081").rstrip("/")
WS = int(os.environ.get("WORKSPACE_ID", "6"))
TENANT = os.environ.get("TENANT_ID", "company-a9ae1234648ee138")
SENSOR = os.environ.get("BASELINE_SENSOR_ID", "ot-edge-001")
EMAIL = os.environ.get("PORTAL_EMAIL", "")
PASSWORD = os.environ.get("PORTAL_PASSWORD", "")


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


def api_request(*, base: str, path: str, token: str, workspace_id: int) -> Any:
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Workspace-Id": str(workspace_id),
        "Accept": "application/json",
        "Accept-Language": "zh-TW",
    }
    req = urllib.request.Request(f"{base.rstrip('/')}{path}", headers=headers, method="GET")
    with urllib.request.urlopen(req, timeout=90) as resp:
        raw = resp.read().decode()
        return json.loads(raw) if raw.strip() else {}


def main() -> int:
    parser = argparse.ArgumentParser(description="OT Topology CVE context Lab gate")
    parser.add_argument("--sensor-id", default=SENSOR)
    parser.add_argument(
        "--expect-agent-id",
        default=os.environ.get("CVE_EXPECT_AGENT_ID", "004"),
        help="Preferred EDR agent for CVE checks (default windows-hmi 004)",
    )
    parser.add_argument(
        "--min-vuln-total",
        type=int,
        default=int(os.environ.get("CVE_MIN_VULN_TOTAL", "1") or "1"),
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail when indexer has no vulnerability data",
    )
    parser.add_argument(
        "--skip-graph-badge",
        action="store_true",
        help="Only verify edr-context, skip graph vuln_badge",
    )
    args = parser.parse_args()

    chk = Checker()
    print("==> Topology CVE context Lab gate")
    print(
        f"    base={BASE} ws={WS} sensor={args.sensor_id} "
        f"agent={args.expect_agent_id or '-'} min_vuln={args.min_vuln_total} strict={args.strict}"
    )

    try:
        token = login()
        chk.ok("portal login")
    except Exception as exc:
        chk.fail(f"login: {exc}")
        print("\n==> CVE CONTEXT GATE FAILED", file=sys.stderr)
        return 1

    run_cve_context_checks(
        chk,
        base=BASE,
        workspace_id=WS,
        tenant_id=TENANT,
        sensor_id=args.sensor_id,
        token=token,
        api_request=api_request,
        expected_agent_id=args.expect_agent_id,
        min_vuln_total=args.min_vuln_total,
        expect_graph_badge=not args.skip_graph_badge,
        strict=args.strict,
    )

    if chk.failures:
        print(f"\n==> CVE CONTEXT GATE FAILED ({len(chk.failures)} failures)", file=sys.stderr)
        return 1
    if chk.warnings:
        print(f"\n==> CVE CONTEXT GATE PASSED WITH WARNINGS ({len(chk.warnings)})")
    else:
        print("\n==> CVE CONTEXT GATE PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
