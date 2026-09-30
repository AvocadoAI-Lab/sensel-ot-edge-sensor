#!/usr/bin/env bash
# Lab CVE indexer seed for OT topology CVE gate (項目 8).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec python3 "$ROOT/scripts/seed_topology_lab_vuln_indexer.py" "$@"
