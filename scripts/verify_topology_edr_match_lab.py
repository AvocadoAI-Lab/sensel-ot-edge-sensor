#!/usr/bin/env python3
"""Lab EDR × OT topology match verification (PRD §4.5 / §11.2 #6)."""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
from typing import Any

from topology_edr_lab_checks import SCENARIOS, run_edr_match_checks


def _env(name: str, default: str = "") -> str:
    return (os.environ.get(name) or default).strip()


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


def login(base: str, email: str, password: str) -> str:
    token = _env("PORTAL_BEARER_TOKEN")
    if token:
        return token
    if not email or not password:
        raise RuntimeError("Set PORTAL_BEARER_TOKEN or PORTAL_EMAIL/PORTAL_PASSWORD")
    req = urllib.request.Request(
        f"{base.rstrip('/')}/api/v1/smb/auth/login",
        data=json.dumps({"email": email, "password": password}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return str(json.loads(resp.read().decode())["access_token"])


def api_request(
    *,
    base: str,
    path: str,
    token: str,
    workspace_id: int,
    method: str = "GET",
    body: dict | None = None,
) -> Any:
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Workspace-Id": str(workspace_id),
        "Accept": "application/json",
        "Accept-Language": "zh-TW",
    }
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body, ensure_ascii=False).encode()
    req = urllib.request.Request(f"{base.rstrip('/')}{path}", data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=60) as resp:
        raw = resp.read().decode()
        return json.loads(raw) if raw.strip() else {}


def main() -> int:
    parser = argparse.ArgumentParser(description="Topology EDR match lab verify")
    parser.add_argument(
        "--scenario",
        choices=sorted(SCENARIOS),
        default=_env("EDR_MATCH_SCENARIO", "ubuntu108"),
        help="Lab preset: ubuntu108 (M1 @ 108) or windows-hmi (PRD ≥0.9 @ 235)",
    )
    parser.add_argument("--base-url", default=_env("CONTROL_PLANE_BASE_URL", "http://192.168.1.108:8081"))
    parser.add_argument("--workspace-id", type=int, default=int(_env("WORKSPACE_ID", "6") or "6"))
    parser.add_argument("--tenant-id", default=_env("TENANT_ID", "company-a9ae1234648ee138"))
    parser.add_argument("--sensor-id", default=_env("BASELINE_SENSOR_ID", "ot-edge-001"))
    parser.add_argument("--site-id", default=_env("SITE_ID", "factory-lab-001"))
    parser.add_argument("--email", default=_env("PORTAL_EMAIL", ""))
    parser.add_argument("--password", default=_env("PORTAL_PASSWORD", ""))
    parser.add_argument("--ingest-secret", default=_env("OT_SECURITY_INGEST_SECRET", "sensel-ot-ingest-lab-2026"))
    parser.add_argument("--no-edr-context", action="store_true")
    parser.add_argument("--all-scenarios", action="store_true", help="Run ubuntu108 then windows-hmi")
    args = parser.parse_args()

    chk = Checker()
    scenario_names = list(SCENARIOS) if args.all_scenarios else [args.scenario]
    print(f"==> Topology EDR match lab verify scenarios={scenario_names} tenant={args.tenant_id}")

    try:
        token = login(args.base_url, args.email, args.password)
        chk.ok("Portal login")
    except Exception as exc:
        chk.fail(f"login: {exc}")
        return 1

    for name in scenario_names:
        scenario = SCENARIOS[name]
        print(f"--- scenario={scenario.name} target_ip={scenario.target_ip} min_conf={scenario.min_confidence}")
        run_edr_match_checks(
            chk,
            base=args.base_url,
            workspace_id=args.workspace_id,
            tenant_id=args.tenant_id,
            sensor_id=args.sensor_id,
            site_id=args.site_id,
            token=token,
            scenario=scenario,
            ingest_secret=args.ingest_secret,
            api_request=api_request,
            expect_edr_context=not args.no_edr_context,
        )

    if chk.failures:
        print(f"\n==> FAILED ({len(chk.failures)} checks, {len(chk.warnings)} warnings)", file=sys.stderr)
        return 1
    print(f"\n==> PASSED ({len(chk.warnings)} warnings)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
