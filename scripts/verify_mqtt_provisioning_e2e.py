#!/usr/bin/env python3
"""MQTT credential auto-land E2E verification (v0.2 Control Plane).

Self-contained checks for the edge side of per-sensor MQTT provisioning, i.e.
the Control Plane registration response carrying ``mqtt_username/password/
host/port`` and the edge applying + persisting it:

  1. apply    — attempt_registration applies register-response credentials to
                the live config (publisher + policy subscriber reads) and the
                northbound client, and persists them with 0600 perms
  2. reload   — load_config re-reads the persisted credentials on the next boot
                so the bus stays authenticated before registration completes
  3. noop     — a register response WITHOUT credentials leaves config untouched
                and writes no secret (older Control Plane / provisioning off)

The edge agent is exercised in its own working directory so the duplicate
``src`` package name does not collide. No running stack is required.

Usage:
  ./scripts/verify-mqtt-provisioning-e2e.sh
  python3 scripts/verify_mqtt_provisioning_e2e.py --json
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
EDGE_AGENT_DIR = REPO_ROOT / "services" / "sensel-edge-agent"

_REG_RESPONSE = {
    "tenant_id": "tenant-acme",
    "mqtt_username": "ndr-tenant-acme-ndr-x",
    "mqtt_password": "p4ss-w0rd",
    "mqtt_host": "edge-broker.example",
    "mqtt_port": 1883,
    "mqtt_acl_version": 1,
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


# Runs inside services/sensel-edge-agent. Exercises registration + reload using
# a fake SenseL client and a recording northbound client stand-in.
_APPLY_CODE = """
import json, os, tempfile

from src.config.settings import (
    AppConfig, LoggingConfig, NorthboundMqttConfig, PolicySyncConfig,
    SensorIdentity, SenselConfig, load_config,
)
from src.runtime.registration import RegistrationState, attempt_registration
from src.runtime.mqtt_credentials import load_persisted_credentials

reg = json.loads(os.environ["REG_RESPONSE"])
with_creds = os.environ.get("WITH_CREDS") == "1"

tmp = tempfile.mkdtemp()
cred_path = os.path.join(tmp, "mqtt-credentials.json")
os.environ["MQTT_CREDENTIALS_PATH"] = cred_path
os.environ["AGENT_RUNTIME_PATH"] = os.path.join(tmp, "agent-runtime.json")


class FakeClient:
    def register(self):
        return reg


class RecordingMqtt:
    enabled = True
    connected = False

    def __init__(self):
        self.creds = None
        self.endpoint = None

    def update_tenant_id(self, tid):
        pass

    def update_credentials(self, u, p):
        self.creds = (u, p)
        return True

    def update_endpoint_if_unset(self, host, port=None):
        self.endpoint = (host, port)
        return True

    def publish_state(self, state):
        return True


config = AppConfig(
    sensor=SensorIdentity(id="ndr-x", site_id="plant1", type="ot-edge-sensor", capabilities=["mqtt"]),
    sensel=SenselConfig(api_url="http://cp:8081", api_key="k", verify_tls=False),
    northbound_mqtt=NorthboundMqttConfig(enabled=True, host="broker", tenant_id="default"),
    policy_sync=PolicySyncConfig(),
    logging=LoggingConfig(),
)
mqtt = RecordingMqtt()
attempt_registration(
    client=FakeClient(), config=config, mqtt=mqtt, policy_mqtt=None,
    state=RegistrationState(), force=True,
)

persisted = load_persisted_credentials(__import__("pathlib").Path(cred_path))

reload_user = None
if with_creds:
    # Fresh boot: only the persisted secret is present (no env creds).
    yaml_path = os.path.join(tmp, "sensor.yaml")
    open(yaml_path, "w").write(
        "sensor:\\n  id: ndr-x\\n  site_id: plant1\\n"
        "sensel:\\n  api_url: http://cp:8081\\n  api_key: k\\n"
    )
    for var in ("CONTROL_PLANE_MQTT_USERNAME", "CONTROL_PLANE_MQTT_PASSWORD"):
        os.environ.pop(var, None)
    os.environ["SENSOR_CONFIG_PATH"] = yaml_path
    reloaded = load_config()
    reload_user = (reloaded.northbound_mqtt.username, reloaded.policy_sync.mqtt_username)

print("RESULT:" + json.dumps({
    "nb_username": config.northbound_mqtt.username,
    "nb_password": config.northbound_mqtt.password,
    "policy_username": config.policy_sync.mqtt_username,
    "mqtt_creds": list(mqtt.creds) if mqtt.creds else None,
    "mqtt_endpoint": list(mqtt.endpoint) if mqtt.endpoint else None,
    "persisted_username": (persisted or {}).get("username") if persisted else None,
    "reload_user": list(reload_user) if reload_user else None,
}))
"""


def _parse_result(out: str) -> dict | None:
    for line in out.splitlines():
        if line.startswith("RESULT:"):
            try:
                return json.loads(line[len("RESULT:") :])
            except json.JSONDecodeError:
                return None
    return None


def _run(with_creds: bool, reg: dict) -> tuple[dict | None, str]:
    proc = subprocess.run(
        [sys.executable, "-c", _APPLY_CODE],
        cwd=str(EDGE_AGENT_DIR),
        capture_output=True,
        text=True,
        timeout=60,
        env={**os.environ, "REG_RESPONSE": json.dumps(reg), "WITH_CREDS": "1" if with_creds else "0"},
    )
    out = (proc.stdout or "") + (proc.stderr or "")
    return _parse_result(out), out


def check_apply(report: Report) -> None:
    result, out = _run(with_creds=True, reg=_REG_RESPONSE)
    if not result:
        report.add("M-1-apply", False, f"no result: {out[:300]}")
        report.add("M-2-reload", False, "skipped (apply failed)")
        return

    user = "ndr-tenant-acme-ndr-x"
    apply_ok = (
        result.get("nb_username") == user
        and result.get("nb_password") == "p4ss-w0rd"
        and result.get("policy_username") == user
        and result.get("mqtt_creds") == [user, "p4ss-w0rd"]
        and result.get("mqtt_endpoint") == ["edge-broker.example", 1883]
        and result.get("persisted_username") == user
    )
    report.add(
        "M-1-apply",
        apply_ok,
        f"nb={result.get('nb_username')} policy={result.get('policy_username')} "
        f"client_creds={result.get('mqtt_creds')} persisted={result.get('persisted_username')}",
    )

    reload_ok = result.get("reload_user") == [user, user]
    report.add(
        "M-2-reload",
        reload_ok,
        f"load_config picked persisted creds -> {result.get('reload_user')}",
    )


def check_noop(report: Report) -> None:
    result, out = _run(with_creds=False, reg={"tenant_id": "tenant-acme"})
    if not result:
        report.add("M-3-noop", False, f"no result: {out[:300]}")
        return
    ok = (
        result.get("nb_username") == ""
        and result.get("mqtt_creds") is None
        and result.get("persisted_username") is None
    )
    report.add(
        "M-3-noop",
        ok,
        f"no-credential response left nb_username='{result.get('nb_username')}' "
        f"persisted={result.get('persisted_username')}",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="MQTT credential auto-land E2E verification")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    report = Report()
    check_apply(report)
    check_noop(report)

    result = report.to_dict()
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"MQTT provisioning E2E @ {result['timestamp']}")
        for check in report.checks:
            mark = "PASS" if check.ok else "FAIL"
            req = "required" if check.required else "optional"
            print(f"  [{mark}] {check.code} ({req}): {check.detail}")

    failed = report.failed_required()
    if failed:
        print(f"\nMQTT provisioning E2E FAILED — {len(failed)} required check(s)", file=sys.stderr)
        return 1
    print("\nMQTT provisioning E2E passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
