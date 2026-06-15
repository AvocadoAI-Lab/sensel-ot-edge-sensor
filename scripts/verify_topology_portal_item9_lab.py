#!/usr/bin/env python3
"""Lab Portal + topology item 9 verify — static bundle + API vuln badge/context."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import urllib.parse
import urllib.request
from typing import Any

BASE = os.environ.get("CONTROL_PLANE_BASE_URL", "http://192.168.1.108:8081").rstrip("/")
WS = int(os.environ.get("WORKSPACE_ID", "6"))
SENSOR = os.environ.get("BASELINE_SENSOR_ID", "ot-edge-001")
EMAIL = os.environ.get("PORTAL_EMAIL", "")
PASSWORD = os.environ.get("PORTAL_PASSWORD", "")
SSH_HOST = os.environ.get("M2_LAB_SSH_HOST", "192.168.1.108")
SSH_USER = os.environ.get("M2_LAB_SSH_USER", "ubuntu")
SSH_PASS = os.environ.get("SSHPASS", "")
EXPECT_AGENT = os.environ.get("CVE_EXPECT_AGENT_ID", "004")
REMOTE_STATIC = os.environ.get(
    "PORTAL_STATIC_DIR",
    "/home/ubuntu/guacamole-ai/sensel_control_plane/static/smb-portal",
)


class Checker:
    def __init__(self) -> None:
        self.failures: list[str] = []

    def ok(self, msg: str) -> None:
        print(f"OK  {msg}")

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


def api_get(path: str, token: str) -> Any:
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Workspace-Id": str(WS),
        "Accept": "application/json",
    }
    req = urllib.request.Request(f"{BASE}{path}", headers=headers, method="GET")
    with urllib.request.urlopen(req, timeout=90) as resp:
        return json.loads(resp.read().decode())


def ssh_cat(path: str) -> str:
    proc = subprocess.run(
        [
            "sshpass",
            "-p",
            SSH_PASS,
            "ssh",
            "-o",
            "StrictHostKeyChecking=accept-new",
            f"{SSH_USER}@{SSH_HOST}",
            f"cat {path}",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "ssh cat failed")
    return proc.stdout


def ssh_ls_assets(pattern: str) -> list[str]:
    proc = subprocess.run(
        [
            "sshpass",
            "-p",
            SSH_PASS,
            "ssh",
            "-o",
            "StrictHostKeyChecking=accept-new",
            f"{SSH_USER}@{SSH_HOST}",
            f"ls {REMOTE_STATIC}/assets/{pattern} 2>/dev/null || true",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    return [line.strip() for line in (proc.stdout or "").splitlines() if line.strip()]


def main() -> int:
    chk = Checker()
    print("==> Portal + topology item 9 verify")
    print(f"    base={BASE} agent={EXPECT_AGENT} static={REMOTE_STATIC}")

    if not SSH_PASS:
        chk.fail("SSHPASS required for static bundle check")
    else:
        try:
            bundles = ssh_ls_assets("OtSecurityProtectionSection-*.js")
            if not bundles:
                chk.fail("remote assets missing OtSecurityProtectionSection bundle")
            else:
                bundle_name = os.path.basename(bundles[0])
                chk.ok(f"portal assets include {bundle_name}")
                bundle = ssh_cat(f"{REMOTE_STATIC}/assets/{bundle_name}")
                for needle in ("vuln_badge", "#ef4444", "CVE"):
                    if needle not in bundle:
                        chk.fail(f"bundle missing {needle}")
                if not any(f for f in chk.failures if "bundle missing" in f):
                    chk.ok("portal bundle contains vuln badge + CVE UI markers")
        except Exception as exc:
            chk.fail(f"portal static: {exc}")

    try:
        token = login()
        chk.ok("portal login")
    except Exception as exc:
        chk.fail(f"login: {exc}")
        print("\n==> PORTAL ITEM9 VERIFY FAILED", file=sys.stderr)
        return 1

    ot = f"/api/v1/smb/workspaces/{WS}/ot-security"
    try:
        graph = api_get(f"{ot}/topology?sensor_id={urllib.parse.quote(SENSOR)}", token)
        node = next(
            (n for n in (graph.get("nodes") or []) if str(n.get("edr_agent_id") or "") == EXPECT_AGENT),
            None,
        )
        if node is None:
            chk.fail(f"graph missing node edr_agent_id={EXPECT_AGENT}")
        else:
            badge = node.get("vuln_badge") or {}
            total = int(badge.get("total") or 0)
            if total < 1:
                chk.fail(f"graph vuln_badge.total={total} for agent {EXPECT_AGENT}")
            else:
                chk.ok(
                    f"graph node {node.get('label')} vuln_badge total={total} "
                    f"critical={badge.get('critical')} high={badge.get('high')}"
                )
    except Exception as exc:
        chk.fail(f"graph: {exc}")

    try:
        assets = api_get(f"{ot}/topology/assets?sensor_id={urllib.parse.quote(SENSOR)}&limit=200", token)
        row = next(
            (a for a in (assets.get("items") or []) if str(a.get("edr_agent_id") or "") == EXPECT_AGENT),
            None,
        )
        if not row:
            chk.fail(f"no topology asset for agent {EXPECT_AGENT}")
        else:
            ctx = api_get(
                f"{ot}/topology/assets/{urllib.parse.quote(str(row.get('asset_id')))}/edr-context",
                token,
            )
            summary = ctx.get("vulnerability_summary") or {}
            total = int(summary.get("total") or 0)
            if total < 1:
                chk.fail(f"edr-context vulnerability_summary.total={total}")
            else:
                top = (summary.get("top_cves") or [])[:2]
                cves = ", ".join(str(x.get("cve") or "") for x in top if isinstance(x, dict))
                chk.ok(f"edr-context CVE summary total={total} top={cves or '-'}")
                if not ctx.get("narrative_zh"):
                    chk.fail("edr-context narrative_zh missing")
                else:
                    chk.ok("edr-context narrative_zh present")
    except Exception as exc:
        chk.fail(f"edr-context: {exc}")

    if chk.failures:
        print(f"\n==> PORTAL ITEM9 VERIFY FAILED ({len(chk.failures)})", file=sys.stderr)
        return 1
    print("\n==> PORTAL ITEM9 VERIFY PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
