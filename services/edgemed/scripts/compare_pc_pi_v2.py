#!/usr/bin/env python3
"""PC vs Pi V2 comparison: ensure PC SLM on, probe APIs, run dataset+unit tests, write ZH MD."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import paramiko

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "PI4_VS_PC_COMPARE_V2.md"
PC = "http://127.0.0.1:8000"
PI = "http://192.168.50.90:8000"
HOST = "192.168.50.90"
USER = "fju"
PW = "0000"
REMOTE = "/home/fju/sensel-ot-edge-sensor/services/edgemed"

SCORE_BODY = {
    "device_id": "monitor-07",
    "device_type": "patient_monitor",
    "operating_state": "idle",
    "criticality": "high",
    "session_id": "sess-v2-compare",
    "features": {
        "flow_duration": 1.2,
        "packet_rate": 84.0,
        "byte_rate": 25000.0,
        "syn_count": 2.0,
        "ack_count": 8.0,
        "connection_rate": 6.0,
        "mean_packet_size": 320.0,
        "iat_mean": 0.08,
    },
}


def ensure_pc_server() -> None:
    try:
        with httpx.Client(timeout=3.0) as c:
            h = c.get(f"{PC}/health").json()
            if h.get("components", {}).get("slm", {}).get("runtime_loaded"):
                print("PC already up with SLM", flush=True)
                return
            # up but SLM not loaded -> restart
            print("PC up but SLM unloaded; restarting", flush=True)
    except Exception:
        print("PC down; starting", flush=True)

    # kill port 8000 best-effort (Windows)
    if os.name == "nt":
        subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-NetTCPConnection -LocalPort 8000 -EA SilentlyContinue | "
             "ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -EA SilentlyContinue }"],
            check=False,
        )
        time.sleep(2)

    out = Path(os.environ.get("TEMP", ".")) / "edgemed-v2-pc-out.log"
    err = Path(os.environ.get("TEMP", ".")) / "edgemed-v2-pc-err.log"
    subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8000"],
        cwd=str(ROOT),
        stdout=open(out, "w", encoding="utf-8"),
        stderr=open(err, "w", encoding="utf-8"),
    )
    for i in range(90):
        time.sleep(4)
        try:
            with httpx.Client(timeout=10.0) as c:
                h = c.get(f"{PC}/health").json()
                loaded = h.get("components", {}).get("slm", {}).get("runtime_loaded")
                print(f"PC wait {i}: status={h.get('status')} slm={loaded}", flush=True)
                if loaded:
                    return
                if i >= 20 and h.get("status"):
                    # server up but SLM failed
                    print("PC server up without SLM", flush=True)
                    return
        except Exception as exc:
            print(f"PC wait {i}: {exc}", flush=True)
    raise RuntimeError("PC server failed to become ready")


def timed_get(client: httpx.Client, path: str) -> dict[str, Any]:
    t0 = time.perf_counter()
    try:
        r = client.get(path)
        return {
            "ok": r.status_code < 400,
            "status_code": r.status_code,
            "latency_ms": round((time.perf_counter() - t0) * 1000, 1),
            "body": r.json(),
            "error": None,
        }
    except Exception as exc:
        return {
            "ok": False,
            "status_code": None,
            "latency_ms": round((time.perf_counter() - t0) * 1000, 1),
            "body": None,
            "error": str(exc),
        }


def timed_post(client: httpx.Client, path: str, body: dict[str, Any]) -> dict[str, Any]:
    t0 = time.perf_counter()
    try:
        r = client.post(path, json=body)
        try:
            payload = r.json()
        except Exception:
            payload = r.text[:1000]
        return {
            "ok": r.status_code < 400,
            "status_code": r.status_code,
            "latency_ms": round((time.perf_counter() - t0) * 1000, 1),
            "body": payload,
            "error": None,
        }
    except Exception as exc:
        return {
            "ok": False,
            "status_code": None,
            "latency_ms": round((time.perf_counter() - t0) * 1000, 1),
            "body": None,
            "error": str(exc),
        }


def summarize_score(body: Any) -> dict[str, Any]:
    if not isinstance(body, dict):
        return {"raw": str(body)[:200]}
    detection = body.get("detection") or {}
    assessment = body.get("assessment") or {}
    primary = detection.get("anomaly") or {}
    anomalies = detection.get("anomalies") or {}
    if_payload = anomalies.get("isolation_forest") or {}
    known = detection.get("known_attack")
    lstm = anomalies.get("lstm_autoencoder")
    return {
        "event_id": body.get("event_id"),
        "detection_status": detection.get("status"),
        "if_score": if_payload.get("score"),
        "if_anomalous": if_payload.get("anomalous"),
        "primary_anomaly": {
            "detector": primary.get("detector"),
            "score": primary.get("score"),
            "anomalous": primary.get("anomalous"),
        },
        "lstm": None
        if lstm is None
        else {
            "status": lstm.get("status"),
            "score": lstm.get("score"),
            "ticks": lstm.get("ticks"),
            "anomalous": lstm.get("anomalous"),
        },
        "known_attack": None
        if not known
        else {"category": known.get("category") or known.get("label"), "probability": known.get("probability")},
        "verdict": assessment.get("verdict"),
        "severity": assessment.get("severity"),
        "taxonomy": assessment.get("taxonomy"),
        "generation_status": assessment.get("generation_status"),
        "summary": (assessment.get("summary") or "")[:220],
        "enrichment_status": (body.get("enrichment") or {}).get("status"),
        "response_mode": (body.get("response") or {}).get("mode"),
    }


def probe(base: str, label: str) -> dict[str, Any]:
    result: dict[str, Any] = {"label": label, "base": base}
    with httpx.Client(base_url=base, timeout=300.0) as client:
        result["health"] = timed_get(client, "/health")
        result["model"] = timed_get(client, "/api/model")

        # Align LSTM features if model exposes them
        body = dict(SCORE_BODY)
        body["session_id"] = f"sess-v2-{label.lower()}-{int(time.time())}"
        model_body = (result["model"].get("body") or {}) if result["model"].get("ok") else {}
        lstm_meta = model_body.get("lstm_autoencoder") or {}
        feats = lstm_meta.get("features")
        seq_len = int(lstm_meta.get("seq_len") or 10)
        if feats:
            body["features"] = {name: float(10 + i) for i, name in enumerate(feats)}
            # keep demo-ish values for overlapping names
            for k, v in SCORE_BODY["features"].items():
                if k in body["features"]:
                    body["features"][k] = v

        # Cold IF-only snapshot (fresh session) before LSTM buffer warms
        cold = dict(body)
        cold["session_id"] = f"{body['session_id']}-cold-if"
        result["score_cold"] = timed_post(client, "/api/score", cold)
        result["score_cold_summary"] = summarize_score(result["score_cold"].get("body"))

        # warm + measured single score
        timed_post(client, "/api/score", body)
        result["score"] = timed_post(client, "/api/score", body)
        result["score_summary"] = summarize_score(result["score"].get("body"))

        # LSTM sequence: send seq_len scores and capture last
        lstm_trace = []
        last = None
        for i in range(seq_len):
            r = timed_post(client, "/api/score", body)
            last = r
            summ = summarize_score(r.get("body"))
            lstm_trace.append({"i": i + 1, "latency_ms": r.get("latency_ms"), "lstm": summ.get("lstm")})
        result["lstm_trace"] = lstm_trace
        result["lstm_final"] = summarize_score((last or {}).get("body")).get("lstm")
        result["lstm_final_score_summary"] = summarize_score((last or {}).get("body"))
        result["lstm_final_latency_ms"] = (last or {}).get("latency_ms")

        event_id = None
        sb = result["score"].get("body")
        if isinstance(sb, dict):
            event_id = sb.get("event_id")
        inv_body = {"event_id": event_id} if event_id else dict(body)
        # Pi llama.cpp may need several minutes for first investigate.
        with httpx.Client(base_url=base, timeout=900.0) as slow:
            result["investigate"] = timed_post(slow, "/api/investigate", inv_body)
        inv = result["investigate"].get("body")
        if isinstance(inv, dict):
            event = inv.get("event") if isinstance(inv.get("event"), dict) else inv
            assessment = (event or {}).get("assessment") or {}
            enrichment = (event or {}).get("enrichment") or {}
            slm_meta = inv.get("slm") if isinstance(inv.get("slm"), dict) else {}
            result["investigate_summary"] = {
                "enrichment_status": enrichment.get("status"),
                "sources": len(enrichment.get("sources") or []),
                "generation_status": assessment.get("generation_status")
                or slm_meta.get("generation_status"),
                "summary": (assessment.get("summary") or "")[:220],
                "recommended_actions": ((event or {}).get("response") or {}).get("recommended_actions"),
                "slm_meta": slm_meta,
            }
        else:
            result["investigate_summary"] = {"error": result["investigate"].get("error") or inv}
    return result


def run_pc_tests() -> dict[str, Any]:
    def one(args: list[str]) -> dict[str, Any]:
        t0 = time.perf_counter()
        p = subprocess.run(
            [sys.executable, "-m", "unittest", *args, "-v"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        text = (p.stderr or "") + "\n" + (p.stdout or "")
        summary = ""
        for line in text.splitlines()[::-1]:
            if line.startswith("OK") or line.startswith("FAILED") or line.startswith("Ran "):
                if line.startswith("OK") or line.startswith("FAILED"):
                    summary = line
                    break
        return {
            "returncode": p.returncode,
            "latency_ms": round((time.perf_counter() - t0) * 1000, 1),
            "summary": summary or ("pass" if p.returncode == 0 else "fail"),
            "tail": text[-1800:],
        }

    return {
        "dataset": one(["tests.test_dataset_m1", "tests.test_ciciomt_prepare"]),
        "full": one(["discover", "-s", "tests"]),
    }


def _ssh_connect() -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        HOST,
        username=USER,
        password=PW,
        timeout=20,
        look_for_keys=False,
        allow_agent=False,
        banner_timeout=30,
        auth_timeout=30,
    )
    transport = client.get_transport()
    if transport is not None:
        transport.set_keepalive(15)
    return client


def _ssh_cat(path: str) -> str | None:
    """Fresh SSH each time — Pi long tests often drop idle sessions."""
    client = None
    try:
        client = _ssh_connect()
        _, stdout, _ = client.exec_command(
            f"if [ -f {path} ]; then cat {path}; else echo '__MISSING__'; fi",
            timeout=30,
        )
        text = stdout.read().decode("utf-8", errors="replace")
        if text.strip() == "__MISSING__":
            return None
        return text
    except Exception as exc:
        print(f"  ssh_cat({path}) err: {exc}", flush=True)
        return None
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass


def _ssh_exec(cmd: str, timeout: int = 30) -> tuple[int, str]:
    client = None
    try:
        client = _ssh_connect()
        _, stdout, stderr = client.exec_command(cmd, timeout=timeout)
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        code = stdout.channel.recv_exit_status()
        return code, out + (("\n" + err) if err else "")
    except Exception as exc:
        return -1, f"ERR:{exc}"
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass


def _pi_stop_api() -> None:
    print("  stopping Pi API to free RAM for tests...", flush=True)
    _ssh_exec("pkill -f 'uvicorn app.main:app' || true")
    time.sleep(2)


def _pi_start_api() -> None:
    """Restart llama-server + uvicorn with EDGEMED_LLAMA_SERVER."""
    import base64

    print("  restarting Pi API + llama-server...", flush=True)
    body = f"""#!/bin/bash
pkill -f 'uvicorn app.main:app' || true
pkill -f 'llama-server' || true
sleep 2
export LD_LIBRARY_PATH=/home/fju/edgemed-slm/llama-b10276:${{LD_LIBRARY_PATH:-}}
cd /home/fju/edgemed-slm/llama-b10276
nohup ./llama-server -m /home/fju/edgemed-slm/models/SmolLM2-360M-Instruct-Q4_K_M.gguf \\
  --host 127.0.0.1 --port 8081 -c 2048 -n 160 -t 2 -ngl 0 \\
  >/tmp/llama-server.log 2>&1 &
echo $! > /tmp/llama-server.pid
for i in $(seq 1 40); do
  if curl -s http://127.0.0.1:8081/health >/dev/null 2>&1 || curl -s http://127.0.0.1:8081/ >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
cd {REMOTE}
source .venv/bin/activate
export OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1
export EDGEMED_LLAMA_SERVER=http://127.0.0.1:8081
nohup uvicorn app.main:app --host 0.0.0.0 --port 8000 >/tmp/edgemed-uvicorn.log 2>&1 &
echo $! > /tmp/edgemed-uvicorn.pid
"""
    b64 = base64.b64encode(body.encode()).decode()
    _ssh_exec(f"echo {b64} | base64 -d > /tmp/start_edgemed_api.sh && chmod +x /tmp/start_edgemed_api.sh")
    _ssh_exec("bash /tmp/start_edgemed_api.sh", timeout=120)
    for i in range(50):
        time.sleep(3)
        try:
            with httpx.Client(timeout=8.0) as c:
                r = c.get(f"{PI}/health")
                if r.status_code == 200:
                    print(f"  Pi API back ({i})", flush=True)
                    return
        except Exception:
            pass
    print("  WARN: Pi API did not return after restart", flush=True)


def run_pi_tests() -> dict[str, Any]:
    """Run Pi tests via nohup + reconnecting poll. Stops API first to avoid OOM reboot."""

    def one(label: str, py_args: str, max_wait_s: int = 2400) -> dict[str, Any]:
        log = f"/tmp/edgemed_v2_{label}.log"
        marker = f"/tmp/edgemed_v2_{label}.done"
        t0 = time.perf_counter()
        _ssh_exec(f"rm -f {log} {marker}")
        time.sleep(0.5)
        launch = (
            f"nohup bash -lc 'cd {REMOTE} && source .venv/bin/activate && "
            f"export OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 MKL_NUM_THREADS=1 && "
            f"python -m unittest {py_args} -v >{log} 2>&1; "
            f"echo EXIT:$? >{marker}' >/dev/null 2>&1 & echo LAUNCHED"
        )
        code, out = _ssh_exec(launch)
        print(f"  Pi {label}: launched rc={code} {out.strip()[:80]}", flush=True)
        text = ""
        exit_code = 1
        saw_alive = False
        while True:
            elapsed = time.perf_counter() - t0
            if elapsed > max_wait_s:
                text = _ssh_cat(log) or text
                return {
                    "returncode": -1,
                    "latency_ms": round(elapsed * 1000, 1),
                    "summary": "TIMEOUT",
                    "tail": text[-1800:],
                }
            time.sleep(10)
            # detect reboot (uptime very small while we waited a long time)
            _, up = _ssh_exec("cut -d. -f1 /proc/uptime || echo 0")
            try:
                up_s = int((up or "0").strip().split()[0])
            except Exception:
                up_s = -1
            if up_s >= 0 and up_s < 90 and elapsed > 120:
                text = (_ssh_cat(log) or "") + "\n[host rebooted during test — likely OOM]"
                return {
                    "returncode": -2,
                    "latency_ms": round(elapsed * 1000, 1),
                    "summary": "HOST_REBOOT_LIKELY_OOM",
                    "tail": text[-1800:],
                }
            done = _ssh_cat(marker)
            if done is None:
                if int(elapsed) % 60 < 12:
                    _, ps = _ssh_exec(
                        "pgrep -af 'python -m unittest' || true; "
                        f"wc -c {log} 2>/dev/null || true; free -m | head -n 2"
                    )
                    print(f"  Pi {label}: waiting {int(elapsed)}s | {ps.strip()[:160]}", flush=True)
                    if "python -m unittest" in (ps or ""):
                        saw_alive = True
                    elif saw_alive and elapsed > 60:
                        # process vanished without marker — possible OOM killer
                        text = (_ssh_cat(log) or "") + "\n[unittest process vanished without done marker]"
                        return {
                            "returncode": -3,
                            "latency_ms": round(elapsed * 1000, 1),
                            "summary": "PROCESS_VANISHED",
                            "tail": text[-1800:],
                        }
                continue
            text = _ssh_cat(log) or ""
            for line in done.splitlines():
                if line.startswith("EXIT:"):
                    try:
                        exit_code = int(line.split(":", 1)[1].strip())
                    except ValueError:
                        exit_code = 1
            break
        summary = ""
        for line in text.splitlines()[::-1]:
            if line.startswith("OK") or line.startswith("FAILED"):
                summary = line
                break
        return {
            "returncode": exit_code,
            "latency_ms": round((time.perf_counter() - t0) * 1000, 1),
            "summary": summary or ("pass" if exit_code == 0 else "fail"),
            "tail": text[-1800:],
        }

    _pi_stop_api()
    try:
        return {
            "dataset": one(
                "dataset",
                "tests.test_dataset_m1 tests.test_ciciomt_prepare",
                max_wait_s=900,
            ),
            "full": one("full", "discover -s tests", max_wait_s=2400),
        }
    finally:
        _pi_start_api()


def zh_bool(v: Any) -> str:
    return "是" if v else "否"


def render(pc: dict[str, Any], pi: dict[str, Any], pc_t: dict[str, Any], pi_t: dict[str, Any]) -> str:
    now = datetime.now(timezone.utc).isoformat()
    pc_h = pc["health"].get("body") or {}
    pi_h = pi["health"].get("body") or {}
    pc_s = pc.get("score_summary") or {}
    pi_s = pi.get("score_summary") or {}
    pc_cold = pc.get("score_cold_summary") or {}
    pi_cold = pi.get("score_cold_summary") or {}
    pc_l = pc.get("lstm_final") or {}
    pi_l = pi.get("lstm_final") or {}
    pc_i = pc.get("investigate_summary") or {}
    pi_i = pi.get("investigate_summary") or {}
    pc_slm = (pc_h.get("components") or {}).get("slm") or {}
    pi_slm = (pi_h.get("components") or {}).get("slm") or {}

    lines = [
        "# 電腦 vs 樹莓派 4 — 同測對比報告 V2",
        "",
        f"- 產生時間（UTC）：`{now}`",
        f"- 電腦：`{PC}`（SLM：transformers／`try_load()`）",
        f"- 樹莓派：`{PI}`（LSTM torch ＋ SLM GGUF／llama.cpp）",
        "- 相同示範請求：`monitor-07` + README 特徵；另做冷啟動 IF 快照，再跑滿 `seq_len` 給 LSTM",
        "",
        "## 1. 總覽",
        "",
        "| 項目 | 電腦（PC） | 樹莓派 4 |",
        "|---|---|---|",
        f"| 健康狀態 | `{pc_h.get('status')}` / degraded={pc_h.get('degraded_components')} | `{pi_h.get('status')}` / degraded={pi_h.get('degraded_components')} |",
        f"| SLM runtime 已載入 | {zh_bool(pc_slm.get('runtime_loaded'))}（backend=`{pc_slm.get('backend')}`） | {zh_bool(pi_slm.get('runtime_loaded'))}（backend=`{pi_slm.get('backend')}`） |",
        f"| SLM model_id | {pc_slm.get('model_id')} | {pi_slm.get('model_id')} |",
        f"| health 延遲 (ms) | {(pc.get('health') or {}).get('latency_ms')} | {(pi.get('health') or {}).get('latency_ms')} |",
        f"| 單次 score 延遲 (ms) | {(pc.get('score') or {}).get('latency_ms')} | {(pi.get('score') or {}).get('latency_ms')} |",
        f"| IF 分數（`anomalies.isolation_forest`） | {pc_s.get('if_score')}（anomalous={pc_s.get('if_anomalous')}） | {pi_s.get('if_score')}（anomalous={pi_s.get('if_anomalous')}） |",
        f"| 冷啟動 IF（獨立 session） | {pc_cold.get('if_score')} / primary={pc_cold.get('primary_anomaly')} | {pi_cold.get('if_score')} / primary={pi_cold.get('primary_anomaly')} |",
        f"| 主異常欄位 primary_anomaly | {pc_s.get('primary_anomaly')} | {pi_s.get('primary_anomaly')} |",
        f"| LSTM 最終狀態 | {pc_l} | {pi_l} |",
        f"| known_attack | {pc_s.get('known_attack')} | {pi_s.get('known_attack')} |",
        f"| verdict / severity | {pc_s.get('verdict')} / {pc_s.get('severity')} | {pi_s.get('verdict')} / {pi_s.get('severity')} |",
        f"| SLM generation_status（單次 score） | {pc_s.get('generation_status')} | {pi_s.get('generation_status')} |",
        f"| investigate generation_status | {pc_i.get('generation_status')} | {pi_i.get('generation_status')} |",
        f"| investigate enrichment | {pc_i.get('enrichment_status')}（sources={pc_i.get('sources')}） | {pi_i.get('enrichment_status')}（sources={pi_i.get('sources')}） |",
        f"| 資料集測試 | {pc_t['dataset'].get('summary')}（{pc_t['dataset'].get('latency_ms')} ms） | {pi_t['dataset'].get('summary')}（{pi_t['dataset'].get('latency_ms')} ms） |",
        f"| 完整單元測試 | {pc_t['full'].get('summary')}（{pc_t['full'].get('latency_ms')} ms, rc={pc_t['full'].get('returncode')}） | {pi_t['full'].get('summary')}（{pi_t['full'].get('latency_ms')} ms, rc={pi_t['full'].get('returncode')}） |",
        "",
        "## 2. 這次重測重點",
        "",
        "- 電腦：transformers 版 SmolLM2（`backend=transformers`）。",
        "- 樹莓派：接上 GGUF＋llama.cpp（`backend=llama_cpp`），仍走同一套 schema／證據護欄；不過關則 `template_fallback`。",
        "- 評分欄位已分開：`if_score`＝真正 Isolation Forest；`primary_anomaly`＝融合後主異常（取可用偵測器最高分）。",
        "- Pi 完整單元測試會先停掉 uvicorn，測完再以含 llama 環境變數方式重啟 API。",
        "",
        "## 2.1 兩邊評分為何看起來不一樣（必讀）",
        "",
        "### 真正的 IF",
        "",
        f"- 冷啟動同特徵：PC IF=`{pc_cold.get('if_score')}`，Pi IF=`{pi_cold.get('if_score')}`。",
        f"- 暖機後摘要：PC IF=`{pc_s.get('if_score')}`，Pi IF=`{pi_s.get('if_score')}`。",
        "- 若兩者接近或相同：代表 `detector.joblib` 在兩邊可重現，**不是兩套不同 IF 模型**。",
        "",
        "### 主異常欄位（容易誤讀）",
        "",
        f"- PC primary=`{pc_s.get('primary_anomaly')}`",
        f"- Pi primary=`{pi_s.get('primary_anomaly')}`",
        "- `detection.anomaly` 會在 IF／LSTM 之間選**分數較高者**當代表。",
        "- 因此若 PC LSTM 已暖機且分數很高，而 Pi LSTM 還在 warming，表格若只看 primary 會誤以為「IF 兩邊差很多」。",
        "",
        "### SLM 與評分無關",
        "",
        "- SLM（含 GGUF）只生說明文字，不改 IF／LSTM／XGBoost 分數。",
        "",
        "## 3. 健康檢查原始結果",
        "",
        "### 電腦",
        "```json",
        json.dumps(pc_h, ensure_ascii=False, indent=2),
        "```",
        "",
        "### 樹莓派",
        "```json",
        json.dumps(pi_h, ensure_ascii=False, indent=2),
        "```",
        "",
        "## 4. `/api/score` 摘要",
        "",
        "### 冷啟動（獨立 session）",
        "",
        "#### 電腦",
        "```json",
        json.dumps(pc_cold, ensure_ascii=False, indent=2),
        "```",
        "",
        "#### 樹莓派",
        "```json",
        json.dumps(pi_cold, ensure_ascii=False, indent=2),
        "```",
        "",
        "### 暖機後單次",
        "",
        "#### 電腦",
        "```json",
        json.dumps(pc_s, ensure_ascii=False, indent=2),
        "```",
        "",
        "#### 樹莓派",
        "```json",
        json.dumps(pi_s, ensure_ascii=False, indent=2),
        "```",
        "",
        "## 5. LSTM 序列追蹤（滿 seq_len）",
        "",
        "### 電腦最終",
        "```json",
        json.dumps(pc_l, ensure_ascii=False, indent=2),
        "```",
        "",
        "### 樹莓派最終",
        "```json",
        json.dumps(pi_l, ensure_ascii=False, indent=2),
        "```",
        "",
        "<details><summary>電腦 LSTM trace</summary>",
        "",
        "```json",
        json.dumps(pc.get("lstm_trace"), ensure_ascii=False, indent=2),
        "```",
        "",
        "</details>",
        "",
        "<details><summary>樹莓派 LSTM trace</summary>",
        "",
        "```json",
        json.dumps(pi.get("lstm_trace"), ensure_ascii=False, indent=2),
        "```",
        "",
        "</details>",
        "",
        "## 6. `/api/investigate` 摘要",
        "",
        "### 電腦",
        "```json",
        json.dumps(pc_i, ensure_ascii=False, indent=2),
        "```",
        "",
        "### 樹莓派",
        "```json",
        json.dumps(pi_i, ensure_ascii=False, indent=2),
        "```",
        "",
        "## 7. 資料集與單元測試",
        "",
        "| 套件 | 電腦 | 樹莓派 |",
        "|---|---|---|",
        f"| 資料集相關（10 項） | {pc_t['dataset'].get('summary')} / {pc_t['dataset'].get('latency_ms')} ms / rc={pc_t['dataset'].get('returncode')} | {pi_t['dataset'].get('summary')} / {pi_t['dataset'].get('latency_ms')} ms / rc={pi_t['dataset'].get('returncode')} |",
        f"| 完整 unittest | {pc_t['full'].get('summary')} / {pc_t['full'].get('latency_ms')} ms / rc={pc_t['full'].get('returncode')} | {pi_t['full'].get('summary')} / {pi_t['full'].get('latency_ms')} ms / rc={pi_t['full'].get('returncode')} |",
        "",
        "<details><summary>電腦資料集測試結尾</summary>",
        "",
        "```text",
        pc_t["dataset"].get("tail") or "",
        "```",
        "",
        "</details>",
        "",
        "<details><summary>樹莓派資料集測試結尾</summary>",
        "",
        "```text",
        pi_t["dataset"].get("tail") or "",
        "```",
        "",
        "</details>",
        "",
        "<details><summary>電腦完整測試結尾</summary>",
        "",
        "```text",
        pc_t["full"].get("tail") or "",
        "```",
        "",
        "</details>",
        "",
        "<details><summary>樹莓派完整測試結尾</summary>",
        "",
        "```text",
        pi_t["full"].get("tail") or "",
        "```",
        "",
        "</details>",
        "",
        "## 8. 白話結論（V2）",
        "",
        "1. **SLM**：PC 用 transformers；Pi 用 GGUF＋llama.cpp。兩邊都可能因護欄落到 `template_fallback`。",
        "2. **LSTM**：滿 seq_len 後兩邊應可 `status=ok`。",
        "3. **IF**：請看 `anomalies.isolation_forest`／冷啟動 IF；不要只看 `detection.anomaly`（那是主異常，可能是 LSTM）。",
        "4. **延遲**：Pi 通常明顯慢於 PC；若 Pi 已開 llama.cpp，investigate／帶生字路徑會更慢。",
        "5. **資料集測試**：兩邊應為 OK（10/10）。",
        "6. **單元測試**：共同 SLM fallback 失敗屬既有差異；Pi 若缺 fixture 可能多 ERROR。",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ckpt = ROOT / "docs" / "_v2_checkpoint.json"
    print("ensuring PC + SLM...", flush=True)
    ensure_pc_server()
    print("probing PC...", flush=True)
    pc = probe(PC, "PC")
    print("probing Pi...", flush=True)
    pi = probe(PI, "Pi")
    print("PC tests...", flush=True)
    pc_t = run_pc_tests()
    ckpt.write_text(
        json.dumps({"pc": pc, "pi": pi, "pc_t": pc_t}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"checkpoint {ckpt}", flush=True)
    print("Pi tests...", flush=True)
    pi_t = run_pi_tests()
    text = render(pc, pi, pc_t, pi_t)
    OUT.write_text(text, encoding="utf-8")
    print(f"wrote {OUT}", flush=True)
    print("V2_DONE", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
