#!/usr/bin/env python3
"""Suricata NDR bridge E2E verification (v0.1).

Self-contained checks for the Suricata -> SenseL edge path:
  1. ingest    — packet-sensor SuricataEveSource maps eve.json -> SecurityEvent
                 (and skips non-alert EVE records)
  2. schema     — mapped event satisfies schemas/security-event.schema.json
  3. sighting   — CTI-range Suricata alert builds an SMB sightings ingest payload
  4. sighting-  — non-CTI Suricata alert does NOT build a sighting (negative)
     negative

Each service is exercised in its own working directory so the duplicate
``src`` package names do not collide. No running stack is required.

Usage:
  ./scripts/verify-suricata-e2e.sh
  python3 scripts/verify_suricata_e2e.py --json
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
PACKET_SENSOR_DIR = REPO_ROOT / "services" / "packet-sensor"
EDGE_AGENT_DIR = REPO_ROOT / "services" / "sensel-edge-agent"
SCHEMA_PATH = REPO_ROOT / "schemas" / "security-event.schema.json"

CTI_SID = 9000002
NON_CTI_SID = 1000001

_SAMPLE_ALERT = {
    "timestamp": "2026-06-18T10:30:00.123456+0000",
    "flow_id": 1234567890,
    "event_type": "alert",
    "src_ip": "10.10.1.20",
    "src_port": 55321,
    "dest_ip": "198.51.100.7",
    "dest_port": 8443,
    "proto": "TCP",
    "app_proto": "tls",
    "alert": {
        "action": "allowed",
        "gid": 1,
        "signature_id": CTI_SID,
        "rev": 1,
        "signature": "SENSEL CTI malware C2",
        "category": "A Network Trojan was detected",
        "severity": 1,
    },
}

# A non-alert EVE record that must be skipped by the bridge.
_SAMPLE_FLOW = {
    "timestamp": "2026-06-18T10:30:01.000000+0000",
    "flow_id": 222,
    "event_type": "flow",
    "src_ip": "10.10.1.20",
    "dest_ip": "10.10.1.100",
    "proto": "TCP",
}


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


_INGEST_CODE = """
import json, tempfile, os
from src.detection.external_engine.suricata_source import SuricataEveSource

records = json.loads(os.environ["SURICATA_SAMPLE"])
with tempfile.TemporaryDirectory() as d:
    src = os.path.join(d, "eve.json")
    out = os.path.join(d, "assets")
    os.makedirs(out)
    with open(src, "w") as fh:
        for rec in records:
            fh.write(json.dumps(rec) + "\\n")
    source = SuricataEveSource(
        eve_json_path=src,
        output_dir=out,
        offset_path=os.path.join(d, "offset"),
        site_id="factory-a",
        sensor_id="ndr-edge-001",
    )
    written = source.poll_once()
    lines = open(source.output_path).read().splitlines()
    print("RESULT:" + json.dumps({"written": written, "event": json.loads(lines[0]) if lines else None}))
"""


_SIGHTING_CODE = """
import json, os
from src.config.settings import (
    AppConfig, SensorIdentity, SenselConfig, SightingReportConfig,
)
from src.sighting.reporter import build_sighting_ingest_payload

cfg = AppConfig(
    sensor=SensorIdentity(id="ndr-edge-001", site_id="factory-a"),
    sensel=SenselConfig(api_url="http://x", api_key="k"),
    sighting_report=SightingReportConfig(
        suricata_sighting_enabled=True,
        snort_cti_sid_min=9000000,
        snort_cti_sid_max=9999999,
    ),
)
event = json.loads(os.environ["SURICATA_EVENT"])
payload = build_sighting_ingest_payload(event, cfg)
print("RESULT:" + json.dumps({"payload": payload}))
"""


def _parse_result(out: str) -> dict | None:
    for line in out.splitlines():
        if line.startswith("RESULT:"):
            try:
                return json.loads(line[len("RESULT:") :])
            except json.JSONDecodeError:
                return None
    return None


def check_ingest(report: Report) -> dict | None:
    # Feed an alert interleaved with a flow record to confirm non-alert filtering.
    sample = [_SAMPLE_ALERT, _SAMPLE_FLOW]
    proc = subprocess.run(
        [sys.executable, "-c", _INGEST_CODE],
        cwd=str(PACKET_SENSOR_DIR),
        capture_output=True,
        text=True,
        timeout=60,
        env={**os.environ, "SURICATA_SAMPLE": json.dumps(sample)},
    )
    out = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode != 0:
        report.add("U-1-ingest", False, f"bridge run failed rc={proc.returncode}: {out[:300]}")
        return None
    result = _parse_result(out)
    if not result or not result.get("event"):
        report.add("U-1-ingest", False, f"no event produced: {out[:300]}")
        return None

    event = result["event"]
    ok = (
        result.get("written") == 1  # alert mapped, flow record skipped
        and event.get("rule_id") == f"suricata-1-{CTI_SID}"
        and event.get("severity") == "high"
        and event.get("protocol") == "tcp"
        and event.get("dst_ip") == "198.51.100.7"
        and event.get("dst_port") == 8443
        and (event.get("evidence") or {}).get("engine") == "suricata"
    )
    report.add(
        "U-1-ingest",
        ok,
        f"written={result.get('written')} (flow skipped) rule_id={event.get('rule_id')} "
        f"severity={event.get('severity')} proto={event.get('protocol')} "
        f"dst={event.get('dst_ip')}:{event.get('dst_port')}",
    )
    return event


def check_schema(report: Report, event: dict | None) -> None:
    if event is None:
        report.add("U-2-schema", False, "no event to validate")
        return
    try:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    except Exception as exc:
        report.add("U-2-schema", False, f"schema not readable: {exc}", required=False)
        return

    required = schema.get("required", [])
    missing = [f for f in required if f not in event or event.get(f) in (None, "")]
    sev_ok = event.get("severity") in {"low", "medium", "high", "critical"}
    rs = event.get("risk_score")
    rs_ok = isinstance(rs, int) and 0 <= rs <= 100
    ok = not missing and sev_ok and rs_ok
    report.add(
        "U-2-schema",
        ok,
        f"required_missing={missing} severity_ok={sev_ok} risk_score_ok={rs_ok}",
    )


def check_sighting(report: Report, event: dict | None) -> None:
    if event is None:
        report.add("U-3-sighting", False, "no event to map to sighting")
        return
    proc = subprocess.run(
        [sys.executable, "-c", _SIGHTING_CODE],
        cwd=str(EDGE_AGENT_DIR),
        capture_output=True,
        text=True,
        timeout=60,
        env={**os.environ, "SURICATA_EVENT": json.dumps(event)},
    )
    out = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode != 0:
        report.add("U-3-sighting", False, f"sighting build failed rc={proc.returncode}: {out[:300]}")
        return
    result = _parse_result(out)
    payload = (result or {}).get("payload")
    if not payload:
        report.add("U-3-sighting", False, f"no sighting payload built: {out[:300]}")
        return
    raw = payload.get("raw_event", {})
    ok = (
        raw.get("event_type") == "suricata_cti_observed"
        and raw.get("ioc_value") == "198.51.100.7"
        and raw.get("ioc_type") == "ipv4"
        and payload.get("defaults", {}).get("source_event_type") == "SURICATA_CTI_OBSERVED"
    )
    report.add(
        "U-3-sighting",
        ok,
        f"ioc={raw.get('ioc_value')} field={raw.get('matched_field')} "
        f"src_event={payload.get('defaults', {}).get('source_event_type')}",
    )


def check_sighting_negative(report: Report) -> None:
    # A non-CTI Suricata alert (out-of-range SID) must NOT produce a sighting.
    non_cti_event = {
        "event_type": "SURICATA_ALERT",
        "rule_id": f"suricata-1-{NON_CTI_SID}",
        "src_ip": "10.10.1.20",
        "dst_ip": "198.51.100.7",
        "risk_score": 60,
        "evidence": {"engine": "suricata", "sid": NON_CTI_SID, "gid": 1},
    }
    proc = subprocess.run(
        [sys.executable, "-c", _SIGHTING_CODE],
        cwd=str(EDGE_AGENT_DIR),
        capture_output=True,
        text=True,
        timeout=60,
        env={**os.environ, "SURICATA_EVENT": json.dumps(non_cti_event)},
    )
    out = (proc.stdout or "") + (proc.stderr or "")
    result = _parse_result(out)
    payload = (result or {}).get("payload") if result else "ERROR"
    ok = result is not None and payload is None
    report.add(
        "U-4-sighting-negative",
        ok,
        f"non-CTI sid={NON_CTI_SID} produced_sighting={payload is not None}",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Suricata NDR bridge E2E verification")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    report = Report()
    event = check_ingest(report)
    check_schema(report, event)
    check_sighting(report, event)
    check_sighting_negative(report)

    result = report.to_dict()
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"Suricata NDR E2E @ {result['timestamp']}")
        for check in report.checks:
            mark = "PASS" if check.ok else "FAIL"
            req = "required" if check.required else "optional"
            print(f"  [{mark}] {check.code} ({req}): {check.detail}")

    failed = report.failed_required()
    if failed:
        print(f"\nSuricata NDR E2E FAILED — {len(failed)} required check(s)", file=sys.stderr)
        return 1
    print("\nSuricata NDR E2E passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
