#!/usr/bin/env python3
"""Run identical API probes on PC and Pi; write a comparison markdown report."""

from __future__ import annotations

import json
import platform
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "PI4_VS_PC_COMPARE.md"
PC_BASE = "http://127.0.0.1:8000"
PI_BASE = "http://192.168.50.90:8000"

SCORE_BODY = {
    "device_id": "monitor-07",
    "device_type": "patient_monitor",
    "operating_state": "idle",
    "criticality": "high",
    "features": {
        "flow_duration": 1.2,
        "packet_rate": 84,
        "byte_rate": 25000,
        "syn_count": 2,
        "ack_count": 8,
        "connection_rate": 6,
        "mean_packet_size": 320,
        "iat_mean": 0.08,
    },
}


def timed_get(client: httpx.Client, path: str) -> dict[str, Any]:
    t0 = time.perf_counter()
    try:
        r = client.get(path)
        ms = (time.perf_counter() - t0) * 1000
        return {
            "ok": r.status_code < 400,
            "status_code": r.status_code,
            "latency_ms": round(ms, 1),
            "body": r.json() if r.headers.get("content-type", "").startswith("application/json") else r.text[:500],
            "error": None,
        }
    except Exception as exc:
        ms = (time.perf_counter() - t0) * 1000
        return {"ok": False, "status_code": None, "latency_ms": round(ms, 1), "body": None, "error": str(exc)}


def timed_post(client: httpx.Client, path: str, body: dict[str, Any]) -> dict[str, Any]:
    t0 = time.perf_counter()
    try:
        r = client.post(path, json=body)
        ms = (time.perf_counter() - t0) * 1000
        payload: Any
        try:
            payload = r.json()
        except Exception:
            payload = r.text[:800]
        return {
            "ok": r.status_code < 400,
            "status_code": r.status_code,
            "latency_ms": round(ms, 1),
            "body": payload,
            "error": None,
        }
    except Exception as exc:
        ms = (time.perf_counter() - t0) * 1000
        return {"ok": False, "status_code": None, "latency_ms": round(ms, 1), "body": None, "error": str(exc)}


def summarize_score(body: Any) -> dict[str, Any]:
    if not isinstance(body, dict):
        return {"raw": str(body)[:200]}
    detection = body.get("detection") or {}
    assessment = body.get("assessment") or {}
    anomaly = detection.get("anomaly") or {}
    known = detection.get("known_attack")
    lstm = (detection.get("anomalies") or {}).get("lstm_autoencoder")
    return {
        "event_id": body.get("event_id"),
        "detection_status": detection.get("status"),
        "if_score": anomaly.get("score"),
        "if_anomalous": anomaly.get("anomalous"),
        "lstm": None if lstm is None else {
            "status": lstm.get("status"),
            "score": lstm.get("score"),
            "ticks": lstm.get("ticks"),
        },
        "known_attack": None if not known else {
            "category": known.get("category") or known.get("label"),
            "probability": known.get("probability"),
        },
        "verdict": assessment.get("verdict"),
        "severity": assessment.get("severity"),
        "taxonomy": assessment.get("taxonomy"),
        "generation_status": assessment.get("generation_status"),
        "summary": (assessment.get("summary") or "")[:180],
        "enrichment_status": (body.get("enrichment") or {}).get("status"),
        "response_mode": (body.get("response") or {}).get("mode"),
    }


def probe(base: str, label: str) -> dict[str, Any]:
    result: dict[str, Any] = {"label": label, "base": base}
    with httpx.Client(base_url=base, timeout=60.0) as client:
        result["health"] = timed_get(client, "/health")
        result["model"] = timed_get(client, "/api/model")
        # warm + measured score
        timed_post(client, "/api/score", SCORE_BODY)
        result["score"] = timed_post(client, "/api/score", SCORE_BODY)
        score_body = result["score"].get("body")
        result["score_summary"] = summarize_score(score_body)
        event_id = None
        if isinstance(score_body, dict):
            event_id = score_body.get("event_id")
        inv_body = {"event_id": event_id} if event_id else dict(SCORE_BODY)
        result["investigate"] = timed_post(client, "/api/investigate", inv_body)
        inv = result["investigate"].get("body")
        if isinstance(inv, dict):
            result["investigate_summary"] = {
                "enrichment_status": (inv.get("enrichment") or {}).get("status"),
                "sources": len((inv.get("enrichment") or {}).get("sources") or []),
                "generation_status": (inv.get("assessment") or {}).get("generation_status"),
                "summary": ((inv.get("assessment") or {}).get("summary") or "")[:180],
                "recommended_actions": (inv.get("response") or {}).get("recommended_actions"),
            }
        else:
            result["investigate_summary"] = {"error": result["investigate"].get("error") or inv}
    return result


def run_unittests(cwd: Path) -> dict[str, Any]:
    t0 = time.perf_counter()
    proc = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    ms = (time.perf_counter() - t0) * 1000
    tail = (proc.stderr or "")[-2500:] + "\n" + (proc.stdout or "")[-1500:]
    # parse OK / FAILED line
    summary_line = ""
    for line in (proc.stderr or proc.stdout or "").splitlines()[::-1]:
        if line.startswith("OK") or line.startswith("FAILED"):
            summary_line = line
            break
    return {
        "returncode": proc.returncode,
        "latency_ms": round(ms, 1),
        "summary": summary_line or ("pass" if proc.returncode == 0 else "fail"),
        "tail": tail[-2000:],
    }


def run_pi_unittests() -> dict[str, Any]:
    try:
        import paramiko
    except Exception as exc:
        return {"returncode": -1, "latency_ms": None, "summary": f"paramiko missing: {exc}", "tail": ""}

    t0 = time.perf_counter()
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        "192.168.50.90",
        username="fju",
        password="0000",
        timeout=20,
        look_for_keys=False,
        allow_agent=False,
    )
    cmd = (
        "cd /home/fju/sensel-ot-edge-sensor/services/edgemed && source .venv/bin/activate && "
        "python -m unittest discover -s tests -v"
    )
    _stdin, stdout, stderr = client.exec_command(cmd, timeout=300, get_pty=True)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    code = stdout.channel.recv_exit_status()
    client.close()
    ms = (time.perf_counter() - t0) * 1000
    text = out + "\n" + err
    summary_line = ""
    for line in text.splitlines()[::-1]:
        if line.startswith("OK") or line.startswith("FAILED") or "Ran " in line:
            if line.startswith("OK") or line.startswith("FAILED"):
                summary_line = line
                break
    if not summary_line:
        for line in text.splitlines()[::-1]:
            if line.startswith("Ran "):
                summary_line = line
                break
    return {
        "returncode": code,
        "latency_ms": round(ms, 1),
        "summary": summary_line or ("pass" if code == 0 else "fail"),
        "tail": text[-2000:],
    }


def md_escape(s: str) -> str:
    return s.replace("|", "\\|")


def render(pc: dict[str, Any], pi: dict[str, Any], pc_tests: dict[str, Any], pi_tests: dict[str, Any]) -> str:
    now = datetime.now(timezone.utc).isoformat()
    pc_h = pc["health"].get("body") or {}
    pi_h = pi["health"].get("body") or {}
    pc_s = pc.get("score_summary") or {}
    pi_s = pi.get("score_summary") or {}
    pc_i = pc.get("investigate_summary") or {}
    pi_i = pi.get("investigate_summary") or {}

    def lat(node: dict[str, Any], key: str) -> str:
        return str((node.get(key) or {}).get("latency_ms"))

    lines = [
        "# PC vs Raspberry Pi 4 — 同測對比",
        "",
        f"- 產生時間（UTC）：`{now}`",
        f"- PC：`{PC_BASE}`（{platform.platform()}）",
        f"- Pi：`{PI_BASE}`（Raspberry Pi 4 Model B 4GB）",
        "- 相同請求 body：`monitor-07` demo features（README 範例）",
        "",
        "## 1. 總覽",
        "",
        "| 項目 | PC | Pi 4 |",
        "|---|---|---|",
        f"| `/health` | `{pc_h.get('status')}` / degraded={pc_h.get('degraded_components')} | `{pi_h.get('status')}` / degraded={pi_h.get('degraded_components')} |",
        f"| health latency (ms) | {lat(pc, 'health')} | {lat(pi, 'health')} |",
        f"| score latency (ms) | {lat(pc, 'score')} | {lat(pi, 'score')} |",
        f"| investigate latency (ms) | {lat(pc, 'investigate')} | {lat(pi, 'investigate')} |",
        f"| IF score | {pc_s.get('if_score')} (anomalous={pc_s.get('if_anomalous')}) | {pi_s.get('if_score')} (anomalous={pi_s.get('if_anomalous')}) |",
        f"| LSTM | {pc_s.get('lstm')} | {pi_s.get('lstm')} |",
        f"| known_attack | {pc_s.get('known_attack')} | {pi_s.get('known_attack')} |",
        f"| verdict / severity | {pc_s.get('verdict')} / {pc_s.get('severity')} | {pi_s.get('verdict')} / {pi_s.get('severity')} |",
        f"| SLM generation_status | {pc_s.get('generation_status')} | {pi_s.get('generation_status')} |",
        f"| investigate enrichment | {pc_i.get('enrichment_status')} (sources={pc_i.get('sources')}) | {pi_i.get('enrichment_status')} (sources={pi_i.get('sources')}) |",
        f"| unittest | {md_escape(str(pc_tests.get('summary')))} ({pc_tests.get('latency_ms')} ms, rc={pc_tests.get('returncode')}) | {md_escape(str(pi_tests.get('summary')))} ({pi_tests.get('latency_ms')} ms, rc={pi_tests.get('returncode')}) |",
        "",
        "## 2. 元件狀態（/health）",
        "",
        "### PC",
        "```json",
        json.dumps(pc_h, ensure_ascii=False, indent=2),
        "```",
        "",
        "### Pi",
        "```json",
        json.dumps(pi_h, ensure_ascii=False, indent=2),
        "```",
        "",
        "## 3. `/api/score` 摘要",
        "",
        "### PC",
        "```json",
        json.dumps(pc_s, ensure_ascii=False, indent=2),
        "```",
        "",
        "### Pi",
        "```json",
        json.dumps(pi_s, ensure_ascii=False, indent=2),
        "```",
        "",
        "## 4. `/api/investigate` 摘要",
        "",
        "### PC",
        "```json",
        json.dumps(pc_i, ensure_ascii=False, indent=2),
        "```",
        "",
        "### Pi",
        "```json",
        json.dumps(pi_i, ensure_ascii=False, indent=2),
        "```",
        "",
        "## 5. 單元測試",
        "",
        f"- PC：`{pc_tests.get('summary')}`，耗時 {pc_tests.get('latency_ms')} ms，returncode={pc_tests.get('returncode')}",
        f"- Pi：`{pi_tests.get('summary')}`，耗時 {pi_tests.get('latency_ms')} ms，returncode={pi_tests.get('returncode')}",
        "",
        "<details><summary>PC unittest tail</summary>",
        "",
        "```text",
        pc_tests.get("tail") or "",
        "```",
        "",
        "</details>",
        "",
        "<details><summary>Pi unittest tail</summary>",
        "",
        "```text",
        pi_tests.get("tail") or "",
        "```",
        "",
        "</details>",
        "",
        "## 6. 解讀（白話）",
        "",
        "- 若 IF score / verdict 一致：代表同一批已訓練模型在兩邊推論行為對齊。",
        "- 若 Pi 的 latency 明顯較高：屬硬體差異，不是邏輯不同。",
        "- 若 LSTM 在 Pi 為 null、PC 有值：多半是 Pi 尚未裝好 torch。",
        "- 若兩邊 SLM 都是 `template_fallback`：代表目前 runtime 都還沒載入神經網路 SLM（Pi 上 GGUF 尚未接到 API）。",
        "",
    ]
    return "\n".join(lines)


def ensure_pc_server() -> None:
    try:
        with httpx.Client(timeout=2.0) as c:
            r = c.get(f"{PC_BASE}/health")
            if r.status_code < 500:
                return
    except Exception:
        pass
    log = Path(os_temp()) / "edgemed-pc-uvicorn.log"
    subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8000"],
        cwd=str(ROOT),
        stdout=open(log, "w", encoding="utf-8"),
        stderr=subprocess.STDOUT,
    )
    for _ in range(30):
        time.sleep(1)
        try:
            with httpx.Client(timeout=2.0) as c:
                if c.get(f"{PC_BASE}/health").status_code < 500:
                    return
        except Exception:
            continue
    raise RuntimeError(f"PC server failed to start; see {log}")


def os_temp() -> str:
    import os
    return os.environ.get("TEMP") or os.environ.get("TMP") or str(ROOT)


def main() -> int:
    print("ensuring PC server...", flush=True)
    ensure_pc_server()
    print("probing PC...", flush=True)
    pc = probe(PC_BASE, "PC")
    print("probing Pi...", flush=True)
    pi = probe(PI_BASE, "Pi")
    print("unittest PC...", flush=True)
    pc_tests = run_unittests(ROOT)
    print("unittest Pi...", flush=True)
    pi_tests = run_pi_unittests()
    text = render(pc, pi, pc_tests, pi_tests)
    OUT.write_text(text, encoding="utf-8")
    print(f"wrote {OUT}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
