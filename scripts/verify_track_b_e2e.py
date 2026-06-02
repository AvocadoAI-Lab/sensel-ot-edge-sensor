#!/usr/bin/env python3
"""
Track B Lab E2E verification (B-S4): feed → Pi cache → OT-019 → sighting → correlate.

Usage:
  export SMB_INTEL_API_KEY='...'
  export POLICY_SYNC_TENANT_ID=sensel-platform
  ./scripts/verify-track-b-e2e.sh

  # Require intel correlation (run seed-track-b-lab-ioc.sh first)
  ./scripts/verify-track-b-e2e.sh --expect-correlate --probe-ip 203.0.113.99
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class CheckResult:
    code: str
    ok: bool
    detail: str
    required: bool = True


@dataclass
class Report:
    checks: list[CheckResult] = field(default_factory=list)

    def add(self, code: str, ok: bool, detail: str, *, required: bool = True) -> None:
        self.checks.append(CheckResult(code=code, ok=ok, detail=detail, required=required))

    def failed_required(self) -> list[CheckResult]:
        return [c for c in self.checks if c.required and not c.ok]

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "passed": len(self.failed_required()) == 0,
            "checks": [
                {"code": c.code, "ok": c.ok, "required": c.required, "detail": c.detail}
                for c in self.checks
            ],
        }


def _http_json(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    body: dict | None = None,
    timeout: float = 25.0,
) -> tuple[int, Any]:
    data = None
    req_headers = {"Accept": "application/json", **(headers or {})}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        req_headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=req_headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            try:
                return resp.status, json.loads(raw) if raw.strip() else {}
            except json.JSONDecodeError:
                return resp.status, raw
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            payload = json.loads(raw) if raw.strip() else {}
        except json.JSONDecodeError:
            payload = raw[:300]
        return exc.code, payload


def _feed_ipv4_items(feed: dict) -> list[dict]:
    items = []
    for item in feed.get("items") or []:
        if not isinstance(item, dict):
            continue
        ioc_type = str(item.get("ioc_type") or "").lower()
        if ioc_type in ("ipv4", "ip", "ipv4-addr"):
            items.append(item)
    return items


def _ssh_run(target: str, command: str, *, password: str | None = None, timeout: int = 30) -> tuple[int, str]:
    ssh_cmd = ["ssh", "-o", "StrictHostKeyChecking=no", target, command]
    env = os.environ.copy()
    if password:
        proc = subprocess.run(
            ["sshpass", "-e", "ssh", "-o", "StrictHostKeyChecking=no", target, command],
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**env, "SSHPASS": password},
        )
    else:
        proc = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=timeout)
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def check_feed(report: Report, base: str, tenant: str, api_key: str, test_ip: str) -> dict | None:
    url = f"{base}/api/v1/feed/{tenant}/blacklist.json"
    status, payload = _http_json("GET", url, headers={"X-API-Key": api_key})
    if status != 200 or not isinstance(payload, dict):
        report.add("B-1-feed", False, f"feed HTTP {status}: {payload}")
        return None

    ipv4_items = _feed_ipv4_items(payload)
    values = [str(i.get("value") or "") for i in ipv4_items]
    has_test = test_ip in values
    report.add(
        "B-1-feed",
        True,
        f"feed ok version={payload.get('version', payload.get('artifact_version', '?'))} "
        f"ipv4_items={len(ipv4_items)} test_ip_present={has_test}",
        required=True,
    )
    if not has_test:
        report.add(
            "B-1-feed-ip",
            False,
            f"test IP {test_ip} not in feed — run scripts/seed-track-b-lab-ioc.sh",
            required=False,
        )
    else:
        report.add("B-1-feed-ip", True, f"test IP {test_ip} present in feed", required=False)
    return payload


def check_pi_cache(report: Report, pi_target: str, test_ip: str, sshpass: str | None) -> None:
    if not pi_target:
        report.add("B-1-pi-cache", True, "skipped (PI_TARGET unset)", required=False)
        return

    cmd = (
        "docker exec sensel-edge-agent cat /app/data/ioc-cache.json 2>/dev/null "
        "|| cat ~/sensel-ot-edge-sensor/data/agent/ioc-cache.json 2>/dev/null || echo '{}'"
    )
    rc, out = _ssh_run(pi_target, cmd, password=sshpass)
    if rc != 0:
        report.add("B-1-pi-cache", False, f"ssh failed rc={rc}: {out[:200]}")
        return
    try:
        cache = json.loads(out)
    except json.JSONDecodeError:
        report.add("B-1-pi-cache", False, "ioc-cache.json not readable")
        return

    ipv4 = cache.get("ipv4") if isinstance(cache.get("ipv4"), dict) else {}
    count = len(ipv4)
    has_test = test_ip in ipv4
    report.add(
        "B-1-pi-cache",
        count > 0,
        f"cache entries={count} test_ip_cached={has_test} tenant={cache.get('tenant_id', '?')}",
    )


def check_ot019(report: Report, pi_target: str, sshpass: str | None) -> list[dict]:
    if not pi_target:
        report.add("B-2-ot019", True, "skipped (PI_TARGET unset)", required=False)
        return []

    cmd = (
        "grep '\"rule_id\": \"OT-019\"' ~/sensel-ot-edge-sensor/data/assets/security-events.jsonl "
        "2>/dev/null | tail -20 || true"
    )
    rc, out = _ssh_run(pi_target, cmd, password=sshpass)
    events: list[dict] = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    report.add(
        "B-2-ot019",
        len(events) > 0,
        f"OT-019 events found={len(events)}",
    )
    return events


def check_sightings(report: Report, base: str, api_key: str) -> list[dict]:
    url = f"{base}/api/v1/smb/sightings?limit=20"
    status, payload = _http_json("GET", url, headers={"X-API-Key": api_key})
    if status != 200 or not isinstance(payload, dict):
        report.add("B-3-sightings", False, f"sightings list HTTP {status}: {payload}")
        return []

    items = payload.get("items") or []
    ndr_cti = [
        i
        for i in items
        if isinstance(i, dict)
        and str(i.get("source_system") or "").lower() == "ndr"
        and "cti" in str(i.get("source_event_type") or "").lower()
    ]
    report.add(
        "B-3-sightings",
        len(ndr_cti) > 0,
        f"ndr cti sightings={len(ndr_cti)} total_listed={len(items)}",
    )
    return items


def check_correlate(
    report: Report,
    base: str,
    api_key: str,
    sightings: list[dict],
    *,
    expect: bool,
    probe_ip: str | None,
) -> None:
    matched_existing = [
        s for s in sightings if isinstance(s, dict) and s.get("matched_intel_id")
    ]
    if matched_existing:
        sample = matched_existing[0]
        report.add(
            "B-4-correlate",
            True,
            f"existing matched sighting value={sample.get('value')} "
            f"intel_id={sample.get('matched_intel_id')}",
        )
        return

    if not probe_ip:
        if expect:
            report.add(
                "B-4-correlate",
                False,
                "no matched_intel_id in recent sightings; use --probe-ip after seed",
            )
        else:
            report.add(
                "B-4-correlate",
                True,
                "no matched sightings yet (optional — run seed + --expect-correlate)",
                required=False,
            )
        return

    event_id = f"lab-b4-probe-{int(time.time())}"
    body = {
        "source_system": "manual",
        "raw_event": {
            "sighting_type": "ip",
            "value": probe_ip,
            "event_id": event_id,
            "asset_name": "track-b-lab-probe",
            "description": "Track B-S4 correlate probe",
        },
        "defaults": {"confidence": 90, "severity": 85},
    }
    url = f"{base}/api/v1/smb/sightings/ingest"
    status, payload = _http_json("POST", url, headers={"X-API-Key": api_key}, body=body)
    if status != 200 or not isinstance(payload, dict):
        report.add("B-4-correlate", False, f"probe ingest HTTP {status}: {payload}")
        return

    correlation = payload.get("correlation") if isinstance(payload.get("correlation"), dict) else {}
    matched = bool(correlation.get("matched"))
    intel_id = correlation.get("matched_intel_id")
    ok = matched if expect else True
    report.add(
        "B-4-correlate",
        ok,
        f"probe ip={probe_ip} matched={matched} intel_id={intel_id}",
        required=expect,
    )


def check_cooldown(report: Report, ot019_events: list[dict]) -> None:
    if len(ot019_events) < 2:
        report.add("B-5-cooldown", True, "insufficient OT-019 samples for cooldown check", required=False)
        return

    by_ioc: dict[str, int] = {}
    for ev in ot019_events:
        evidence = ev.get("evidence") if isinstance(ev.get("evidence"), dict) else {}
        ioc = str(evidence.get("ioc_value") or "")
        if ioc:
            by_ioc[ioc] = by_ioc.get(ioc, 0) + 1

    # Heuristic: many OT-019 lines but bounded unique event_ids per ioc is OK;
    # packet-sensor cooldown should keep OT-019 rate lower than raw packet rate.
    max_dup = max(by_ioc.values()) if by_ioc else 0
    report.add(
        "B-5-cooldown",
        max_dup <= 50,
        f"OT-019 per ioc in sample max={max_dup} (cooldown limits spam)",
        required=False,
    )


def check_queue(report: Report, pi_target: str, sshpass: str | None) -> None:
    if not pi_target:
        report.add("B-6-queue", True, "skipped (PI_TARGET unset)", required=False)
        return

    cmd = (
        "docker exec sensel-edge-agent cat /app/data/sighting-queue.jsonl 2>/dev/null "
        "|| cat ~/sensel-ot-edge-sensor/data/agent/sighting-queue.jsonl 2>/dev/null || true"
    )
    rc, out = _ssh_run(pi_target, cmd, password=sshpass)
    lines = [ln for ln in out.splitlines() if ln.strip()]
    report.add(
        "B-6-queue",
        len(lines) == 0,
        f"pending queue lines={len(lines)}",
        required=False,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Track B Lab E2E verification (B-S4)")
    parser.add_argument("--base-url", default=os.environ.get("SENSEL_API_URL", "http://192.168.1.108:8081"))
    parser.add_argument("--tenant", default=os.environ.get("POLICY_SYNC_TENANT_ID", "sensel-platform"))
    parser.add_argument("--api-key", default=os.environ.get("SMB_INTEL_API_KEY", ""))
    parser.add_argument("--test-ip", default=os.environ.get("TRACK_B_TEST_IOC_IP", "203.0.113.99"))
    parser.add_argument("--pi-target", default=os.environ.get("PI_TARGET", "edgex@192.168.1.123"))
    parser.add_argument("--sshpass", default=os.environ.get("SSHPASS", ""))
    parser.add_argument("--expect-correlate", action="store_true")
    parser.add_argument("--probe-ip", default=os.environ.get("TRACK_B_PROBE_IP", ""))
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    if not args.api_key:
        print("SMB_INTEL_API_KEY required", file=sys.stderr)
        return 2

    base = args.base_url.rstrip("/")
    report = Report()

    check_feed(report, base, args.tenant, args.api_key, args.test_ip)
    check_pi_cache(report, args.pi_target, args.test_ip, args.sshpass or None)
    ot019 = check_ot019(report, args.pi_target, args.sshpass or None)
    sightings = check_sightings(report, base, args.api_key)
    probe_ip = args.probe_ip or (args.test_ip if args.expect_correlate else "")
    check_correlate(
        report,
        base,
        args.api_key,
        sightings,
        expect=args.expect_correlate,
        probe_ip=probe_ip or None,
    )
    check_cooldown(report, ot019)
    check_queue(report, args.pi_target, args.sshpass or None)

    result = report.to_dict()
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"Track B E2E @ {result['timestamp']}")
        for check in report.checks:
            mark = "PASS" if check.ok else "FAIL"
            req = "required" if check.required else "optional"
            print(f"  [{mark}] {check.code} ({req}): {check.detail}")

    failed = report.failed_required()
    if failed:
        print(f"\nTrack B E2E FAILED — {len(failed)} required check(s)", file=sys.stderr)
        return 1

    print("\nTrack B E2E passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
