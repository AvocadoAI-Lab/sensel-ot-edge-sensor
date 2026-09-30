#!/usr/bin/env python3
"""PRD §11.2 full topology gate — detect delta + graph views + EDR match (Lab).

Orchestrates:
  1. Detect mode + Pi topology_delta publish wait (optional)
  2. Baseline verify gate: topology / views / delta-edge / windows-hmi EDR
  3. Optional M2 ingest + CVE context (PRD §11 extended)

Usage:
  cp .env.lab.example .env.lab
  ./scripts/verify-topology-full-gate-lab.sh

  # PRD §11 完整驗收（seed + M2 + CVE strict，跳過 delta wait）:
  ./scripts/verify-topology-full-gate-lab.sh --prd-11

  # Skip Pi delta wait when already published:
  ./scripts/verify-topology-full-gate-lab.sh --skip-delta-wait
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _env(name: str, default: str = "") -> str:
    return (os.environ.get(name) or default).strip()


def main() -> int:
    parser = argparse.ArgumentParser(description="OT Topology full Lab gate (PRD §11.2)")
    parser.add_argument(
        "--skip-delta-wait",
        action="store_true",
        help="Skip detect transition + Pi delta wait; run baseline gate only",
    )
    parser.add_argument(
        "--edr-scenario",
        choices=["ubuntu108", "windows-hmi"],
        default=_env("EDR_MATCH_SCENARIO", "windows-hmi"),
    )
    parser.add_argument("--sensor-id", default=_env("BASELINE_SENSOR_ID", "ot-edge-001"))
    parser.add_argument(
        "--seed-assets",
        action="store_true",
        help="Run seed_topology_lab_assets.py before gate (PRD §11.3 ≥10 assets)",
    )
    parser.add_argument(
        "--expect-m2-ingest",
        action="store_true",
        help="Run M2 mirror ingest verify after gate",
    )
    parser.add_argument(
        "--expect-cve-context",
        action="store_true",
        help="Run CVE edr-context + graph vuln_badge verify after gate",
    )
    parser.add_argument(
        "--cve-expect-agent-id",
        default=_env("CVE_EXPECT_AGENT_ID", "004"),
        help="EDR agent id for CVE gate (default 004 windows-hmi)",
    )
    parser.add_argument(
        "--cve-strict",
        action="store_true",
        help="Fail CVE gate when indexer has no vulnerability rows",
    )
    parser.add_argument(
        "--prd-11",
        action="store_true",
        help="PRD §11 full preset: --skip-delta-wait --seed-assets --expect-m2-ingest "
        "--expect-cve-context --cve-strict --min-topology-assets 10 --min-topology-conduits 5",
    )
    parser.add_argument("--min-topology-assets", type=int, default=int(_env("LAB_MIN_TOPOLOGY_ASSETS", "10") or "10"))
    parser.add_argument("--min-topology-conduits", type=int, default=int(_env("LAB_MIN_TOPOLOGY_CONDUITS", "5") or "5"))
    args = parser.parse_args()

    if args.prd_11:
        args.skip_delta_wait = True
        args.seed_assets = True
        args.expect_m2_ingest = True
        args.expect_cve_context = True
        args.cve_strict = True
        args.min_topology_assets = max(args.min_topology_assets, 10)
        args.min_topology_conduits = max(args.min_topology_conduits, 5)

    env = os.environ.copy()
    env["EDR_MATCH_SCENARIO"] = args.edr_scenario
    if args.sensor_id:
        env["BASELINE_SENSOR_ID"] = args.sensor_id

    print("==> Topology full gate (PRD §11.2 + §11.3)")
    print(
        f"    edr_scenario={args.edr_scenario} sensor={args.sensor_id} "
        f"skip_delta={args.skip_delta_wait} prd11={args.prd_11} "
        f"m2={args.expect_m2_ingest} cve={args.expect_cve_context} strict={args.cve_strict} "
        f"min_assets={args.min_topology_assets}"
    )

    if args.seed_assets:
        seed_py = ROOT / "scripts" / "seed_topology_lab_assets.py"
        print("==> Seed topology lab assets (§11.3)")
        proc = subprocess.run([sys.executable, str(seed_py)], cwd=str(ROOT), env=env)
        if proc.returncode != 0:
            print("\n==> FULL GATE FAILED (seed phase)", file=sys.stderr)
            return proc.returncode
        print("OK  seed phase passed")

    if not args.skip_delta_wait:
        delta_py = ROOT / "scripts" / "verify_detect_topology_delta_lab.py"
        print("==> Phase A: detect mode + topology_delta + integrated gate")
        proc = subprocess.run([sys.executable, str(delta_py)], cwd=str(ROOT), env=env)
        if proc.returncode != 0:
            print("\n==> FULL GATE FAILED (detect topology_delta phase)", file=sys.stderr)
            return proc.returncode
        print("OK  Phase A passed")
        return 0

    gate_py = ROOT / "scripts" / "verify_baseline_live_learning_lab.py"
    cmd = [
        sys.executable,
        str(gate_py),
        "--expect-mode",
        "detect",
        "--expect-topology",
        "--expect-topology-views",
        "--expect-topology-delta-edge",
        "--expect-edr-match",
        "--edr-match-scenario",
        args.edr_scenario,
        "--sensor-id",
        args.sensor_id,
        "--min-topology-assets",
        str(args.min_topology_assets),
        "--min-topology-conduits",
        str(args.min_topology_conduits),
    ]
    print("==> Phase B: baseline topology + EDR gate (no delta wait)")
    proc = subprocess.run(cmd, cwd=str(ROOT), env=env)
    if proc.returncode != 0:
        print("\n==> FULL GATE FAILED (baseline gate phase)", file=sys.stderr)
        return proc.returncode
    print("OK  baseline gate passed")

    if args.expect_m2_ingest:
        m2_py = ROOT / "scripts" / "verify_topology_m2_ingest_lab.py"
        print("==> Phase C: M2 ingest-time mirror verify")
        m2_cmd = [sys.executable, str(m2_py), "--strict", "--expect-agent-id", "003"]
        proc = subprocess.run(m2_cmd, cwd=str(ROOT), env=env)
        if proc.returncode != 0:
            print("\n==> FULL GATE FAILED (M2 ingest phase)", file=sys.stderr)
            return proc.returncode
        print("OK  M2 ingest phase passed")

    if args.expect_cve_context:
        cve_py = ROOT / "scripts" / "verify_topology_cve_context_lab.py"
        print("==> Phase D: CVE context + graph vuln_badge verify")
        cve_cmd = [
            sys.executable,
            str(cve_py),
            "--expect-agent-id",
            args.cve_expect_agent_id,
        ]
        if args.cve_strict:
            cve_cmd.append("--strict")
        proc = subprocess.run(cve_cmd, cwd=str(ROOT), env=env)
        if proc.returncode != 0:
            print("\n==> FULL GATE FAILED (CVE context phase)", file=sys.stderr)
            return proc.returncode
        print("OK  CVE context phase passed")

    print("\n==> FULL GATE PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
