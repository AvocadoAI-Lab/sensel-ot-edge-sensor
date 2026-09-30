#!/usr/bin/env python3
"""Sync LGBM Round-5 model to Pi, temporarily swap known-attack artifact, benchmark, restore XGB."""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import paramiko

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.benchmark_phase_c_booster_latency import (  # noqa: E402
    _collect_windows,
    _http_score_body,
    _latency_summary,
    _percentile,
)
from app.classifier import load_classifier

HOST, USER, PW = "192.168.50.90", "fju", "0000"
REMOTE = "/home/fju/avocdo-edgemed"
CLASSIFIERS = f"{REMOTE}/artifacts/classifiers"
XGB_REMOTE = f"{CLASSIFIERS}/xgboost_binary.joblib"
XGB_BACKUP = f"{CLASSIFIERS}/xgboost_binary.joblib.xgb-backup"
XGB_CATEGORY_REMOTE = f"{CLASSIFIERS}/xgboost_category.joblib"
XGB_CATEGORY_BACKUP = f"{CLASSIFIERS}/xgboost_category.joblib.xgb-backup"
LGBM_REMOTE = f"{CLASSIFIERS}/lightgbm_binary.joblib"


def _utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def connect() -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        HOST,
        username=USER,
        password=PW,
        timeout=25,
        look_for_keys=False,
        allow_agent=False,
        banner_timeout=60,
    )
    transport = client.get_transport()
    if transport:
        transport.set_keepalive(20)
    return client


def run(client: paramiko.SSHClient, cmd: str, timeout: int = 180) -> tuple[int, str]:
    print(">>>", cmd[:180], flush=True)
    _, stdout, stderr = client.exec_command(cmd, timeout=timeout, get_pty=True)
    out = stdout.read().decode("utf-8", "replace")
    err = stderr.read().decode("utf-8", "replace")
    code = stdout.channel.recv_exit_status()
    text = out + (("\n" + err) if err.strip() else "")
    safe = text[-1200:].encode("utf-8", errors="replace").decode("utf-8", errors="replace")
    print(safe, flush=True)
    return code, text


def ensure_lightgbm(client: paramiko.SSHClient) -> None:
    code, text = run(
        client,
        f"cd {REMOTE} && source .venv/bin/activate && "
        "python -c \"import lightgbm; print(lightgbm.__version__)\"",
        timeout=120,
    )
    if code == 0 and any(ch.isdigit() for ch in text):
        return
    run(
        client,
        f"cd {REMOTE} && source .venv/bin/activate && pip install 'lightgbm==4.6.0'",
        timeout=600,
    )


def upload_model(client: paramiko.SSHClient, local_path: Path) -> None:
    sftp = client.open_sftp()
    run(client, f"mkdir -p {CLASSIFIERS}", timeout=30)
    print(f"upload {local_path} -> {LGBM_REMOTE}", flush=True)
    sftp.put(str(local_path), LGBM_REMOTE)
    sftp.close()


def backup_xgb(client: paramiko.SSHClient) -> None:
    run(
        client,
        f"test -f {XGB_REMOTE} && cp -f {XGB_REMOTE} {XGB_BACKUP} || echo 'no existing xgb binary to backup'",
        timeout=60,
    )
    run(
        client,
        f"test -f {XGB_CATEGORY_REMOTE} && cp -f {XGB_CATEGORY_REMOTE} {XGB_CATEGORY_BACKUP} || echo 'no category to backup'",
        timeout=60,
    )


def activate_lgbm_swap(client: paramiko.SSHClient) -> None:
    run(
        client,
        f"cp -f {LGBM_REMOTE} {XGB_REMOTE} && "
        f"rm -f {XGB_CATEGORY_REMOTE}",
        timeout=60,
    )


def restore_xgb(client: paramiko.SSHClient) -> None:
    run(
        client,
        f"if [ -f {XGB_BACKUP} ]; then cp -f {XGB_BACKUP} {XGB_REMOTE}; echo RESTORED_BINARY; else echo NO_BINARY_BACKUP; fi",
        timeout=60,
    )
    run(
        client,
        f"if [ -f {XGB_CATEGORY_BACKUP} ]; then cp -f {XGB_CATEGORY_BACKUP} {XGB_CATEGORY_REMOTE}; echo RESTORED_CATEGORY; else echo NO_CATEGORY_BACKUP; fi",
        timeout=60,
    )


def restart_api(client: paramiko.SSHClient) -> None:
    run(
        client,
        "echo 0000 | sudo -S bash -lc "
        "\"PID=$(pgrep -f '/home/fju/avocdo-edgemed/.venv/bin/uvicorn app.main:app' | head -1); "
        "if [ -n \\\"$PID\\\" ]; then kill \\\"$PID\\\"; fi\"",
        timeout=30,
    )
    time.sleep(2)
    run(
        client,
        "echo 0000 | sudo -S bash -lc "
        f"\"cd {REMOTE} && source .venv/bin/activate && "
        "nohup env OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 "
        "uvicorn app.main:app --host 0.0.0.0 --port 8000 "
        ">/tmp/edgemed-uvicorn.log 2>&1 & echo \\$!\"",
        timeout=30,
    )


def wait_health(base_url: str, attempts: int = 40, sleep_s: float = 3.0) -> dict[str, Any]:
    last_error = ""
    for index in range(attempts):
        time.sleep(sleep_s)
        try:
            with httpx.Client(base_url=base_url, timeout=12.0) as client:
                health = client.get("/health")
                model = client.get("/api/model")
                if health.status_code == 200:
                    return {
                        "ok": True,
                        "health": health.json(),
                        "model_keys": sorted(model.json().keys()) if model.status_code == 200 else [],
                    }
                last_error = f"health status={health.status_code}"
        except Exception as exc:
            last_error = str(exc)
        print(f"wait health {index}: {last_error}", flush=True)
    return {"ok": False, "error": last_error}


def probe_score(base_url: str, body: dict[str, Any]) -> dict[str, Any]:
    started = time.perf_counter()
    with httpx.Client(base_url=base_url, timeout=30.0) as client:
        response = client.post("/api/score", json=body)
        payload = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    known = ((payload.get("detection") or {}).get("known_attack") or {})
    return {
        "status_code": response.status_code,
        "latency_ms": round(elapsed_ms, 3),
        "known_detector": known.get("detector"),
        "known_category": known.get("category"),
        "known_probability": known.get("probability"),
        "detection_status": (payload.get("detection") or {}).get("status"),
    }


def benchmark_pi_http(
    *,
    base_url: str,
    windows: list[dict[str, Any]],
    iterations: int,
    label: str,
) -> dict[str, Any]:
    cycle = [windows[i % len(windows)] for i in range(iterations)]
    latencies: list[float] = []
    probes: list[dict[str, Any]] = []
    errors: list[str] = []
    with httpx.Client(base_url=base_url, timeout=30.0) as client:
        health = client.get("/health")
        if health.status_code >= 400:
            return {"label": label, "status": "unavailable", "error": f"/health status={health.status_code}"}
        for window in cycle[:3]:
            client.post("/api/score", json=_http_score_body(window))
        for index, window in enumerate(cycle):
            started = time.perf_counter()
            response = client.post("/api/score", json=_http_score_body(window))
            elapsed = (time.perf_counter() - started) * 1000.0
            latencies.append(elapsed)
            if response.status_code >= 400:
                errors.append(f"idx={index} status={response.status_code}")
            if index == 0:
                try:
                    payload = response.json()
                    known = ((payload.get("detection") or {}).get("known_attack") or {})
                    probes.append(
                        {
                            "known_detector": known.get("detector"),
                            "known_category": known.get("category"),
                            "detection_status": (payload.get("detection") or {}).get("status"),
                        }
                    )
                except Exception as exc:
                    probes.append({"parse_error": str(exc)})
    model_info: dict[str, Any] = {}
    try:
        with httpx.Client(base_url=base_url, timeout=10.0) as client:
            model_info = client.get("/api/model").json()
    except Exception:
        model_info = {}
    return {
        "label": label,
        "base_url": base_url,
        "status": "ok" if not errors else "degraded",
        "latency_ms": _latency_summary(latencies),
        "sample_probe": probes[:1],
        "http_errors": errors[:5],
        "api_model_keys": sorted(model_info.keys()) if isinstance(model_info, dict) else [],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Sync LGBM to Pi and benchmark /api/score")
    parser.add_argument(
        "--lgbm-model",
        type=Path,
        default=ROOT / "artifacts" / "fl-experiment-lgbm-three" / "models" / "fl-round-005.joblib",
    )
    parser.add_argument("--pi-base", default=f"http://{HOST}:8000")
    parser.add_argument("--iterations", type=int, default=200)
    parser.add_argument("--skip-restore", action="store_true")
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "artifacts" / "xgb-lgbm-benchmark" / "phase-c-pi-lgbm-latency.json",
    )
    args = parser.parse_args()

    if not args.lgbm_model.is_file():
        raise FileNotFoundError(args.lgbm_model)

    local_bundle = load_classifier(args.lgbm_model)
    if local_bundle.model_name != "lightgbm":
        raise ValueError(f"Expected lightgbm bundle, got {local_bundle.model_name!r}")

    xgb_bundle = load_classifier(ROOT / "artifacts" / "classifiers" / "xgboost_binary.joblib")
    windows = _collect_windows(
        splits_dir=ROOT / "artifacts" / "fl-experiment-three" / "splits",
        dataset_root=Path(r"D:\實習\資料集"),
        seed=20260818,
        max_rows=300,
        feature_names=xgb_bundle.features,
    )
    sample_body = _http_score_body(windows[0])

    report: dict[str, Any] = {
        "phase": "C-pi-lgbm",
        "recorded_at": _utc(),
        "local_lgbm_model": str(args.lgbm_model),
        "remote_paths": {
            "lgbm_binary": LGBM_REMOTE,
            "xgboost_binary": XGB_REMOTE,
            "xgboost_backup": XGB_BACKUP,
        },
        "note": (
        "Lab-only swap: LGBM Round-5 bundle copied over xgboost_binary.joblib; xgboost_category.joblib "
        "temporarily removed so main.py loads the LGBM binary bundle. Original XGB artifacts restored after benchmark."
        ),
    }

    client = connect()
    try:
        ensure_lightgbm(client)
        upload_model(client, args.lgbm_model)
        backup_xgb(client)

        # Baseline XGB on Pi before swap
        report["pi_xgb_before_swap"] = benchmark_pi_http(
            base_url=args.pi_base,
            windows=windows,
            iterations=args.iterations,
            label="pi_xgb_before_swap",
        )

        activate_lgbm_swap(client)
        restart_api(client)
        client.close()
        client = None

        health = wait_health(args.pi_base)
        report["health_after_lgbm_swap"] = health
        if not health.get("ok"):
            raise RuntimeError(f"Pi API unhealthy after LGBM swap: {health}")

        smoke = probe_score(args.pi_base, sample_body)
        report["smoke_after_lgbm_swap"] = smoke
        if smoke.get("known_detector") != "lightgbm":
            raise RuntimeError(
                f"LGBM swap verification failed: known_detector={smoke.get('known_detector')!r}, "
                f"status={smoke.get('status_code')}"
            )

        report["pi_lgbm_swapped"] = benchmark_pi_http(
            base_url=args.pi_base,
            windows=windows,
            iterations=args.iterations,
            label="pi_lgbm_swapped",
        )

        xgb_p95 = (report.get("pi_xgb_before_swap") or {}).get("latency_ms", {}).get("p95_ms")
        lgbm_p95 = (report.get("pi_lgbm_swapped") or {}).get("latency_ms", {}).get("p95_ms")
        report["gates"] = {
            "lgbm_p95_le_500ms": bool(lgbm_p95 is not None and lgbm_p95 <= 500.0),
            "lgbm_p95_le_1_5x_xgb": bool(
                xgb_p95 and lgbm_p95 is not None and lgbm_p95 <= xgb_p95 * 1.5
            ),
        }
    finally:
        if client is not None:
            client.close()
        if not args.skip_restore:
            restore_client = connect()
            try:
                restore_xgb(restore_client)
                restart_api(restore_client)
                report["restored_xgb"] = wait_health(args.pi_base)
            finally:
                restore_client.close()

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(
        {
            "output": str(args.output),
            "xgb_p95_ms": (report.get("pi_xgb_before_swap") or {}).get("latency_ms", {}).get("p95_ms"),
            "lgbm_p95_ms": (report.get("pi_lgbm_swapped") or {}).get("latency_ms", {}).get("p95_ms"),
            "known_detector": (report.get("smoke_after_lgbm_swap") or {}).get("known_detector"),
            "gates": report.get("gates"),
            "restored": not args.skip_restore,
        },
        ensure_ascii=False,
        indent=2,
    ))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
