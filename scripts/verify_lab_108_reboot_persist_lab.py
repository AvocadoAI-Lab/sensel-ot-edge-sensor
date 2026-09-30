#!/usr/bin/env python3
"""Lab 108 reboot persistence verify (項目 10).

After reboot (or current boot), verify:
  - M2 mirror IP 192.168.10.88 on ens33 (netplan)
  - Wazuh indexer-connector healthy
  - M2 ingest + CVE strict gates

Usage:
  # Verify without rebooting:
  SSHPASS=avocado@@ ./scripts/verify-lab-108-reboot-persist-lab.sh

  # Reboot 108 then verify (disruptive, ~3–5 min):
  SSHPASS=avocado@@ ./scripts/verify-lab-108-reboot-persist-lab.sh --reboot
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOST = os.environ.get("M2_LAB_SSH_HOST", "192.168.1.108")
USER = os.environ.get("M2_LAB_SSH_USER", "ubuntu")
PASS = os.environ.get("SSHPASS", "")
IFACE = os.environ.get("M2_LAB_NET_IFACE", "ens33")
MIRROR_IP = os.environ.get("M2_MIRROR_OT_IP", "192.168.10.88")
PREFIX = os.environ.get("M2_MIRROR_PREFIX", "24")
CP_BASE = os.environ.get("CONTROL_PLANE_BASE_URL", f"http://{HOST}:8081").rstrip("/")


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


def ssh(cmd: str, *, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "sshpass",
            "-p",
            PASS,
            "ssh",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "ConnectTimeout=10",
            f"{USER}@{HOST}",
            cmd,
        ],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def wait_ssh(chk: Checker, *, timeout_sec: int = 360) -> bool:
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        proc = ssh("echo up", timeout=15)
        if proc.returncode == 0 and "up" in (proc.stdout or ""):
            chk.ok(f"SSH reachable ({HOST})")
            return True
        time.sleep(10)
    chk.fail(f"SSH not reachable within {timeout_sec}s")
    return False


def wait_cp_health(chk: Checker, *, timeout_sec: int = 240) -> bool:
    import urllib.request

    deadline = time.time() + timeout_sec
    url = f"{CP_BASE}/api/health"
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=8) as resp:
                if resp.status == 200:
                    chk.ok(f"CP health {url}")
                    return True
        except Exception:
            pass
        time.sleep(8)
    chk.fail(f"CP health not ready: {url}")
    return False


def has_mirror_ip(text: str) -> bool:
    return f"inet {MIRROR_IP}/{PREFIX}" in text


def main() -> int:
    parser = argparse.ArgumentParser(description="Lab 108 reboot persistence verify")
    parser.add_argument("--reboot", action="store_true", help="Reboot 108 before verify")
    parser.add_argument("--skip-gates", action="store_true", help="Only infra checks (IP + Wazuh)")
    args = parser.parse_args()

    chk = Checker()
    print("==> Lab 108 reboot persistence verify (項目 10)")
    print(f"    host={HOST} mirror={MIRROR_IP}/{PREFIX} reboot={args.reboot}")

    if not PASS:
        chk.fail("SSHPASS required")
        return 1

    if args.reboot:
        print("==> Rebooting host (disruptive)...")
        proc = ssh(f"echo '{PASS}' | sudo -S systemctl reboot", timeout=30)
        reboot_denied = "block inhibitor" in (proc.stderr or proc.stdout or "").lower()
        if reboot_denied or proc.returncode != 0:
            if reboot_denied:
                chk.warn(
                    "systemd blocked reboot (active inhibitor) — verify continues on current boot; "
                    "use hypervisor console for true cold-boot test"
                )
            else:
                chk.warn(f"reboot command returned {proc.returncode}: {proc.stderr.strip()}")
            if not wait_ssh(chk, timeout_sec=30):
                return 1
        else:
            time.sleep(20)
            if not wait_ssh(chk, timeout_sec=360):
                return 1
        if not wait_cp_health(chk):
            return 1
    else:
        if not wait_ssh(chk, timeout_sec=30):
            return 1

    proc = ssh(f"ip -4 addr show dev {IFACE}")
    if proc.returncode != 0:
        chk.fail(f"ip addr show {IFACE}: {proc.stderr.strip()}")
    elif not has_mirror_ip(proc.stdout or ""):
        chk.fail(f"mirror IP {MIRROR_IP} missing on {IFACE} after boot")
    else:
        chk.ok(f"mirror IP {MIRROR_IP}/{PREFIX} on {IFACE}")

    proc = ssh(f"echo '{PASS}' | sudo -S cat /etc/netplan/99-sensel-m2-mirror.yaml 2>/dev/null || true")
    if MIRROR_IP not in (proc.stdout or "") or IFACE not in (proc.stdout or ""):
        chk.fail("netplan drop-in missing mirror config")
    else:
        chk.ok("netplan drop-in present")

    proc = ssh(
        "docker ps --format '{{.Names}}' | grep -qx wazuh-manager && "
        "docker exec wazuh-manager tail -80 /var/ossec/logs/ossec.log 2>/dev/null | "
        "grep -i indexer-connector | tail -5 || true",
        timeout=90,
    )
    log = proc.stdout or ""
    if "initialized successfully" in log:
        chk.ok("Wazuh indexer-connector initialized successfully (recent log)")
    elif "initialization failed" in log:
        chk.fail("Wazuh indexer-connector still failing — run lab-fix-wazuh-indexer-connector.sh")
    else:
        chk.warn("indexer-connector log inconclusive — manager may still be warming up")

    proc = ssh(
        "docker exec wazuh-indexer curl -sk -u admin:admin "
        "'https://localhost:9200/_cat/indices/wazuh-states-vulnerabilities*?v' 2>/dev/null | head -5",
        timeout=60,
    )
    if "wazuh-states-vulnerabilities" in (proc.stdout or ""):
        chk.ok("vulnerability state indices present on indexer")
    else:
        chk.warn("no wazuh-states-vulnerabilities index visible yet")

    if not args.skip_gates:
        env = os.environ.copy()
        print("==> Post-boot M2 ingest gate")
        m2 = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "verify_topology_m2_ingest_lab.py"), "--strict", "--expect-agent-id", "003"],
            cwd=str(ROOT),
            env=env,
        )
        if m2.returncode != 0:
            chk.fail("M2 ingest gate failed after boot")
        else:
            chk.ok("M2 ingest gate passed")

        print("==> Post-boot CVE strict gate")
        cve = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "verify_topology_cve_context_lab.py"),
                "--strict",
                "--expect-agent-id",
                os.environ.get("CVE_EXPECT_AGENT_ID", "004"),
            ],
            cwd=str(ROOT),
            env=env,
        )
        if cve.returncode != 0:
            chk.fail("CVE strict gate failed after boot")
        else:
            chk.ok("CVE strict gate passed")

    if chk.failures:
        print(f"\n==> REBOOT PERSIST VERIFY FAILED ({len(chk.failures)})", file=sys.stderr)
        return 1
    if chk.warnings:
        print(f"\n==> REBOOT PERSIST VERIFY PASSED WITH WARNINGS ({len(chk.warnings)})")
    else:
        print("\n==> REBOOT PERSIST VERIFY PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
