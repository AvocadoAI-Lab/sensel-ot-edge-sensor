#!/usr/bin/env python3
"""E2E lab: unknown device → generic learning → live candidate approve → detect.

Does not read CIC profiling CSV. The live candidate is either:
  * supplied via --candidate, or
  * synthesised to mimic BaselineCollector live-observed output for a brand-new
    device talking to organisation-common destinations.
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

PI_HOST = "192.168.50.90"
PI_USER = "fju"
PC_MQTT_HOST = "192.168.50.134"
REMOTE_ROOT = "/home/fju/sensel-ot-edge-sensor"
REMOTE_PROFILE = f"{REMOTE_ROOT}/data/agent/baseline-profile.json"
REMOTE_MODE = f"{REMOTE_ROOT}/data/agent/operational-mode.json"
REMOTE_LIVE = f"{REMOTE_ROOT}/data/assets/baseline/live-observed.json"
from lab_paths import EDGEMED_ROOT
EDGE_REPO = Path(__file__).resolve().parents[1]


def ssh(command: str, *, password: str, timeout: int = 90) -> str:
    import paramiko

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        PI_HOST,
        username=PI_USER,
        password=password,
        timeout=20,
        look_for_keys=False,
        allow_agent=False,
    )
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    out = stdout.read().decode("utf-8", "replace")
    err = stderr.read().decode("utf-8", "replace")
    client.close()
    if err.strip():
        print(err.strip())
    return out


def _run(cmd: list[str], *, cwd: Path) -> None:
    print("==>", " ".join(cmd))
    result = subprocess.run(cmd, cwd=str(cwd), check=False)
    if result.returncode != 0:
        raise SystemExit(result.returncode)


def _read_json(raw: str) -> dict:
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"invalid JSON from Pi: {exc}\n{raw[:500]}") from exc
    if not isinstance(doc, dict):
        raise SystemExit("Pi JSON is not an object")
    return doc


def main() -> int:
    device_type = sys.argv[1] if len(sys.argv) > 1 else "unknown_medical_device"
    asset_id = sys.argv[2] if len(sys.argv) > 2 else "unknown-asset-01"
    password = sys.argv[3] if len(sys.argv) > 3 else "0000"

    print("==> Deploy edge-agent with operational-mode MQTT enabled")
    _run([sys.executable, str(EDGE_REPO / "scripts" / "_pi_deploy_mqtt_edge_agent.py")], cwd=EDGE_REPO)

    print("==> Step 1: onboard unknown device with generic observe-only profile")
    _run(
        [
            sys.executable,
            str(EDGEMED_ROOT / "scripts" / "publish_baseline_profile_mqtt.py"),
            "--device-type",
            device_type,
            "--asset-id",
            asset_id,
            "--mqtt-host",
            PC_MQTT_HOST,
        ],
        cwd=EDGEMED_ROOT,
    )
    time.sleep(2)

    print("==> Step 2: switch Edge to learning")
    _run(
        [
            sys.executable,
            str(EDGEMED_ROOT / "scripts" / "publish_operational_mode_mqtt.py"),
            "--mode",
            "learning",
            "--mqtt-host",
            PC_MQTT_HOST,
        ],
        cwd=EDGEMED_ROOT,
    )
    time.sleep(3)

    mode_doc = _read_json(ssh(f"cat {REMOTE_MODE} 2>/dev/null || echo '{{}}'", password=password))
    if mode_doc.get("mode") != "learning":
        raise SystemExit(f"FAIL: expected mode=learning, got {mode_doc.get('mode')!r}\n{mode_doc}")
    print(f"OK learning mode session={mode_doc.get('session_id')}")

    print("==> Step 3: write live-observed candidate onto Pi (no CIC)")
    sys.path.insert(0, str(EDGEMED_ROOT))
    from app.baseline_learning import synthesize_lab_live_candidate

    candidate = synthesize_lab_live_candidate()
    candidate_path = EDGEMED_ROOT / "artifacts" / "baseline-candidates" / "lab-live-candidate.json"
    candidate_path.parent.mkdir(parents=True, exist_ok=True)
    candidate_path.write_text(json.dumps(candidate, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    # Persist the same candidate on Pi as live-observed.json so Edge state matches.
    payload = json.dumps(candidate, ensure_ascii=False)
    ssh(
        f"echo '{password}' | sudo -S mkdir -p {REMOTE_ROOT}/data/assets/baseline && "
        f"echo '{password}' | sudo -S tee {REMOTE_LIVE} > /dev/null <<'EOF'\n"
        f"{payload}\n"
        f"EOF\n"
        f"echo '{password}' | sudo -S chown fju:fju {REMOTE_LIVE} && "
        f"python3 -c \"import json; print('wrote', json.load(open({REMOTE_LIVE!r}))['source'])\"",
        password=password,
    )

    print("==> Step 4: approve live learning and switch to detect")
    _run(
        [
            sys.executable,
            str(EDGEMED_ROOT / "scripts" / "approve_learned_baseline.py"),
            "--candidate",
            str(candidate_path),
            "--device-type",
            device_type,
            "--asset-id",
            asset_id,
            "--mqtt-host",
            PC_MQTT_HOST,
        ],
        cwd=EDGEMED_ROOT,
    )
    time.sleep(3)

    profile = _read_json(ssh(f"cat {REMOTE_PROFILE} 2>/dev/null || echo '{{}}'", password=password))
    mode_doc = _read_json(ssh(f"cat {REMOTE_MODE} 2>/dev/null || echo '{{}}'", password=password))

    observed = profile.get("observed") if isinstance(profile.get("observed"), dict) else {}
    provenance = observed.get("provenance") if isinstance(observed.get("provenance"), dict) else {}
    thresholds = observed.get("thresholds") if isinstance(observed.get("thresholds"), dict) else {}

    failures: list[str] = []
    if provenance.get("resolution") != "live_learning":
        failures.append(f"resolution={provenance.get('resolution')!r}")
    if provenance.get("stats_source") != "live_learning":
        failures.append(f"stats_source={provenance.get('stats_source')!r}")
    if "rate_p95_hint" in thresholds or "cic_profiling_stats" in observed:
        failures.append("borrowed CIC statistics present")
    if not observed.get("comm_pairs"):
        failures.append("learned comm_pairs missing")
    if mode_doc.get("mode") != "detect":
        failures.append(f"mode={mode_doc.get('mode')!r}")
    if mode_doc.get("baseline_profile_id") != profile.get("profile_id"):
        failures.append("mode baseline_profile_id mismatch")

    if failures:
        print("FAIL:", "; ".join(failures))
        print(json.dumps({"profile": profile, "mode": mode_doc}, ensure_ascii=False, indent=2)[:2000])
        return 1

    print(f"OK: learned profile_id={profile.get('profile_id')} version={profile.get('version')}")
    print(f"    resolution=live_learning mode=detect")
    print(f"    comm_pairs={len(observed.get('comm_pairs') or [])} forbidden={len((observed.get('iomt') or {}).get('forbidden_patterns') or [])}")
    print("    no CIC statistics; local learning approved")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
