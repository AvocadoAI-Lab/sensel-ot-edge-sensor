#!/usr/bin/env python3
"""Lab M2 netplan persistence verify (項目 9).

Checks:
  1. /etc/netplan/99-sensel-m2-mirror.yaml exists with mirror IP
  2. After `ip addr del` + `netplan apply`, mirror IP is restored
  3. M2 ingest gate still passes

Usage:
  SSHPASS=avocado@@ ./scripts/verify-m2-netplan-persist-lab.sh
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys

HOST = os.environ.get("M2_LAB_SSH_HOST", "192.168.1.108")
USER = os.environ.get("M2_LAB_SSH_USER", "ubuntu")
PASS = os.environ.get("SSHPASS", "")
IFACE = os.environ.get("M2_LAB_NET_IFACE", "ens33")
MIRROR_IP = os.environ.get("M2_MIRROR_OT_IP", "192.168.10.88")
PREFIX = os.environ.get("M2_MIRROR_PREFIX", "24")
DROPIN = "/etc/netplan/99-sensel-m2-mirror.yaml"


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


def ssh(cmd: str, *, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    if not PASS:
        raise RuntimeError("Set SSHPASS")
    return subprocess.run(
        [
            "sshpass",
            "-p",
            PASS,
            "ssh",
            "-o",
            "StrictHostKeyChecking=accept-new",
            f"{USER}@{HOST}",
            cmd,
        ],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def ssh_sudo(script: str, *, timeout: int = 180) -> subprocess.CompletedProcess[str]:
    escaped = script.replace("'", "'\"'\"'")
    return ssh(f"bash -lc '{escaped}'", timeout=timeout)


def has_mirror_ip(output: str) -> bool:
    needle = f"inet {MIRROR_IP}/{PREFIX}"
    return needle in output


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify M2 netplan mirror IP persistence")
    parser.add_argument("--skip-m2-ingest", action="store_true", help="Only verify netplan restore")
    args = parser.parse_args()

    chk = Checker()
    print("==> M2 netplan persistence verify")
    print(f"    host={HOST} iface={IFACE} mirror={MIRROR_IP}/{PREFIX}")

    proc = ssh_sudo(f"echo '{PASS}' | sudo -S cat {DROPIN}")
    if proc.returncode != 0:
        chk.fail(f"missing {DROPIN}: {proc.stderr.strip()}")
        return 1
    if MIRROR_IP not in proc.stdout or IFACE not in proc.stdout:
        chk.fail(f"{DROPIN} missing {MIRROR_IP} or {IFACE}")
    else:
        chk.ok(f"{DROPIN} contains {MIRROR_IP} on {IFACE}")

    proc = ssh_sudo(
        f"echo '{PASS}' | sudo -S stat -c '%a' {DROPIN} 2>/dev/null || echo perm_unknown"
    )
    mode = (proc.stdout or "").strip()
    if mode.isdigit() and int(mode) > 600:
        chk.warn(f"{DROPIN} permissions {mode} (recommend 600)")
    elif mode == "600":
        chk.ok(f"{DROPIN} permissions 600")

    proc = ssh(f"ip -4 addr show dev {IFACE}")
    if not has_mirror_ip(proc.stdout or ""):
        chk.fail(f"mirror IP {MIRROR_IP} not on {IFACE} before test")
        return 1
    chk.ok(f"mirror IP present before netplan restore test")

    restore_script = f"""
set -euo pipefail
IFACE='{IFACE}'
MIRROR_IP='{MIRROR_IP}'
PREFIX='{PREFIX}'
SUDO_PASS='{PASS}'
sudo_cmd() {{ echo "$SUDO_PASS" | sudo -S "$@"; }}
if ip -4 addr show dev "$IFACE" | grep -q "inet ${MIRROR_IP}/"; then
  sudo_cmd ip addr del "${MIRROR_IP}/${PREFIX}" dev "$IFACE" || true
fi
if ip -4 addr show dev "$IFACE" | grep -q "inet ${MIRROR_IP}/"; then
  echo STILL_PRESENT
  exit 2
fi
sudo_cmd chmod 600 /etc/netplan/99-sensel-m2-mirror.yaml 2>/dev/null || true
sudo_cmd netplan apply
sleep 2
ip -4 addr show dev "$IFACE"
"""
    proc = ssh_sudo(restore_script, timeout=180)
    if proc.returncode != 0:
        chk.fail(f"netplan restore script failed: {proc.stderr.strip() or proc.stdout.strip()}")
    elif not has_mirror_ip(proc.stdout or ""):
        chk.fail(f"netplan apply did not restore {MIRROR_IP} on {IFACE}")
        print(proc.stdout or proc.stderr, file=sys.stderr)
    else:
        chk.ok(f"netplan apply restored {MIRROR_IP}/{PREFIX} on {IFACE}")

    if not args.skip_m2_ingest:
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        m2_py = os.path.join(root, "scripts", "verify_topology_m2_ingest_lab.py")
        print("==> M2 ingest gate after netplan restore")
        proc2 = subprocess.run(
            [sys.executable, m2_py, "--strict", "--expect-agent-id", "003"],
            cwd=root,
            env=os.environ.copy(),
        )
        if proc2.returncode != 0:
            chk.fail("M2 ingest gate failed after netplan restore")
        else:
            chk.ok("M2 ingest gate passed after netplan restore")

    if chk.failures:
        print(f"\n==> M2 NETPLAN VERIFY FAILED ({len(chk.failures)})", file=sys.stderr)
        return 1
    if chk.warnings:
        print(f"\n==> M2 NETPLAN VERIFY PASSED WITH WARNINGS ({len(chk.warnings)})")
    else:
        print("\n==> M2 NETPLAN VERIFY PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
