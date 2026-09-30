#!/usr/bin/env python3
"""Read-only Pi resource and deployed-model snapshot for the existing lab."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from _pi_reboot_bringup import connect
from lab_paths import PI_EDGEMED_ROOT


REMOTE = rf"""
python3 - <<'PY'
import hashlib
import json
import os
import subprocess

paths = [
    "{PI_EDGEMED_ROOT}/artifacts/classifiers/xgboost_binary.joblib",
    "{PI_EDGEMED_ROOT}/artifacts/classifiers/xgboost_category.joblib",
    "/home/fju/edgemed-slm/models/SmolLM2-360M-Instruct-Q4_K_M.gguf",
]
models = []
for path in paths:
    if not os.path.isfile(path):
        continue
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    models.append({
        "path": path,
        "bytes": os.path.getsize(path),
        "sha256": digest.hexdigest(),
    })

processes = []
for line in subprocess.check_output(
    ["ps", "-eo", "pid,comm,%cpu,rss,args"], text=True
).splitlines():
    if any(name in line for name in ("llama-server", "uvicorn", "src.main")):
        processes.append(line.strip())

print(json.dumps({
    "package_versions": json.loads(subprocess.check_output([
        "{PI_EDGEMED_ROOT}/.venv/bin/python",
        "-c",
        "import importlib.metadata,json; print(json.dumps({n:importlib.metadata.version(n) for n in ('xgboost','scikit-learn','pandas','numpy')}))",
    ], text=True)),
    "load_average": os.getloadavg(),
    "memory": open("/proc/meminfo", encoding="utf-8").read().splitlines()[:5],
    "disk": subprocess.check_output(["df", "-B1", "/"], text=True).splitlines(),
    "processes": processes,
    "models": models,
}))
PY
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    client = connect()
    _, stdout, stderr = client.exec_command(REMOTE, timeout=180)
    raw = stdout.read().decode("utf-8", "replace").strip()
    error = stderr.read().decode("utf-8", "replace").strip()
    client.close()
    if error:
        print(error, file=sys.stderr)
    parsed = json.loads(raw)
    text = json.dumps(parsed, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
