#!/usr/bin/env bash
# Merge Pi lab/production seed into .env without overwriting existing keys.
#
# Usage:
#   ./scripts/seed-pi-env.sh
#   ./scripts/seed-pi-env.sh .env.pi-lab.example .env
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SEED="${1:-${ROOT}/.env.pi-lab.example}"
TARGET="${2:-${ROOT}/.env}"

if [[ ! -f "$SEED" ]]; then
  echo "Seed file not found: $SEED" >&2
  exit 1
fi

python3 - "$SEED" "$TARGET" <<'PY'
import sys
from pathlib import Path

seed_path = Path(sys.argv[1])
target_path = Path(sys.argv[2])

def parse_lines(text: str) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    for line in text.splitlines():
        raw = line.rstrip("\n")
        if not raw.strip() or raw.lstrip().startswith("#"):
            rows.append(("", raw))
            continue
        if "=" not in raw:
            rows.append(("", raw))
            continue
        key, _, value = raw.partition("=")
        rows.append((key.strip(), raw))
    return rows

def load_keys(text: str) -> set[str]:
    keys: set[str] = set()
    for key, _ in parse_lines(text):
        if key:
            keys.add(key)
    return keys

seed_text = seed_path.read_text(encoding="utf-8")
existing_text = target_path.read_text(encoding="utf-8") if target_path.is_file() else ""
existing_keys = load_keys(existing_text)

out_lines: list[str] = []
if existing_text:
    out_lines.append(existing_text.rstrip("\n"))

added = 0
for key, raw in parse_lines(seed_text):
    if not key:
        continue
    if key in existing_keys:
        continue
    if out_lines and out_lines[-1] != "":
        out_lines.append("")
    out_lines.append(raw)
    existing_keys.add(key)
    added += 1

if not target_path.is_file():
    header = [
        "# SenseL OT Edge Sensor — managed .env",
        "# Seeded from .env.pi-lab.example; customize per site.",
        "",
    ]
    body = "\n".join(header + out_lines).strip() + "\n"
    target_path.write_text(body, encoding="utf-8")
    print(f"Created {target_path} ({added} keys from seed)")
else:
    if added:
        merged = "\n".join(out_lines).strip() + "\n"
        target_path.write_text(merged, encoding="utf-8")
        print(f"Merged {added} new keys into {target_path}")
    else:
        print(f"No changes — {target_path} already has all seed keys")
PY
