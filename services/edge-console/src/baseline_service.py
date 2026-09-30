"""Baseline lifecycle (MVP-1): pcap → candidate → approve / rollback.

Architecture (no HTTP on the sensor; everything via shared volumes + docker):
- Console writes the uploaded pcap to ``<agent>/baseline/uploads`` (console rw,
  sensor ro can read it).
- Console runs the learner *inside* the packet-sensor container via
  ``docker exec`` (the sensor owns scapy + the parsers). The learner writes the
  candidate to ``<assets>/baseline/candidate.json`` (sensor rw, console ro).
- Approve merges the candidate's ``iec61850`` block into
  ``detection-policy.json`` and bumps the stamp, which the sensor hot-reloads.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_SENSOR_AGENT_DIR = "/app/data/agent"
_SENSOR_ASSETS_DIR = "/app/data/assets"
_SENSOR_CANDIDATE = f"{_SENSOR_ASSETS_DIR}/baseline/candidate.json"
_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _agent_dir() -> Path:
    return Path(os.environ.get("DETECTION_POLICY_PATH", "/data/agent/detection-policy.json")).parent


def _assets_dir() -> Path:
    return Path(os.environ.get("ASSETS_DIR", "/data/assets"))


def _policy_path() -> Path:
    return Path(os.environ.get("DETECTION_POLICY_PATH", "/data/agent/detection-policy.json"))


def _stamp_path() -> Path:
    return Path(os.environ.get("DETECTION_POLICY_STAMP_PATH", "/data/agent/detection-policy.stamp"))


def _uploads_dir() -> Path:
    return _agent_dir() / "baseline" / "uploads"


def _candidate_path() -> Path:
    return _assets_dir() / "baseline" / "candidate.json"


def _live_observed_path() -> Path:
    return _assets_dir() / "baseline" / "live-observed.json"


def _state_path() -> Path:
    return _agent_dir() / "baseline" / "baseline-state.json"


def _container() -> str:
    return os.environ.get("PACKET_SENSOR_CONTAINER", "sensel-packet-sensor")


def _read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
        os.replace(tmp, str(path))
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


# -- learning ----------------------------------------------------------------
def _env_int(name: str, default: int) -> int:
    try:
        return max(0, int(os.environ.get(name, str(default))))
    except (TypeError, ValueError):
        return default


def max_pcap_bytes() -> int:
    """Hard upload guard (default 100MB, env-configurable)."""
    return _env_int("BASELINE_MAX_PCAP_MB", 100) * 1024 * 1024


def _auto_limit_bytes() -> int:
    return _env_int("BASELINE_AUTO_LIMIT_MB", 50) * 1024 * 1024


def _auto_limit_packets() -> int:
    return _env_int("BASELINE_AUTO_LIMIT_PACKETS", 500_000)


def _learn_timeout() -> int:
    return _env_int("BASELINE_LEARN_TIMEOUT_SEC", 600) or 600


def upload_target(filename: str) -> tuple[Path, str]:
    """Compute the (host_pcap_path, fname) to stream an upload into."""
    safe = _SAFE_NAME.sub("_", filename or "capture.pcap").strip("_") or "capture.pcap"
    if not safe.lower().endswith((".pcap", ".pcapng", ".cap")):
        safe += ".pcap"
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    fname = f"{stamp}-{safe}"
    uploads = _uploads_dir()
    uploads.mkdir(parents=True, exist_ok=True)
    return uploads / fname, fname


def run_learn(fname: str, *, limit: int = 0) -> dict[str, Any]:
    """Run the learner inside packet-sensor against an already-saved pcap."""
    host_pcap = _uploads_dir() / fname
    if not host_pcap.is_file() or host_pcap.stat().st_size == 0:
        return {"ok": False, "error": "空的 pcap 內容", "status": 400}

    if not Path("/var/run/docker.sock").exists():
        return {"ok": False, "error": "Docker socket 未掛載，無法在 packet-sensor 內執行學習", "status": 503}

    # Auto-cap packets for large captures: OT identities appear early, so a
    # bounded learn protects against approaching the docker exec timeout.
    effective_limit = int(limit) if limit and limit > 0 else 0
    auto_limited = False
    if effective_limit <= 0 and host_pcap.stat().st_size > _auto_limit_bytes():
        effective_limit = _auto_limit_packets()
        auto_limited = True

    sensor_pcap = f"{_SENSOR_AGENT_DIR}/baseline/uploads/{fname}"
    cmd = [
        "docker", "exec", _container(),
        "python", "-m", "src.baseline.learn",
        "--pcap", sensor_pcap,
        "--out", _SENSOR_CANDIDATE,
        "--source-ref", fname,
    ]
    if effective_limit > 0:
        cmd += ["--limit", str(effective_limit)]

    timeout = _learn_timeout()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"學習逾時（>{timeout}s），pcap 可能過大；可改用較短擷取或設定封包上限", "status": 504}
    except FileNotFoundError:
        return {"ok": False, "error": "docker CLI 不可用", "status": 503}

    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()[-500:]
        return {"ok": False, "error": f"學習失敗: {detail}", "status": 500}

    candidate = _read_json(_candidate_path())
    if not candidate:
        return {"ok": False, "error": "學習完成但找不到候選結果", "status": 500}
    return {
        "ok": True,
        "candidate": candidate,
        "pcap": fname,
        "auto_limited": auto_limited,
        "packet_limit": effective_limit or None,
    }


def learn_from_pcap(content: bytes, filename: str, *, limit: int = 0) -> dict[str, Any]:
    """Non-streaming helper (kept for tests / programmatic callers)."""
    if not content:
        return {"ok": False, "error": "空的 pcap 內容", "status": 400}
    if len(content) > max_pcap_bytes():
        return {"ok": False, "error": f"pcap 超過 {max_pcap_bytes() // 1024 // 1024}MB 上限", "status": 413}
    host_pcap, fname = upload_target(filename)
    host_pcap.write_bytes(content)
    return run_learn(fname, limit=limit)


def get_candidate() -> dict[str, Any] | None:
    cand = _read_json(_candidate_path())
    return cand or None


# -- drift (live observed vs active baseline) --------------------------------
def _active_iec() -> dict[str, Any]:
    policy = _read_json(_policy_path())
    baseline = policy.get("baseline") if isinstance(policy.get("baseline"), dict) else {}
    iec = baseline.get("iec61850") if isinstance(baseline.get("iec61850"), dict) else {}
    return iec


def _live_iec() -> tuple[dict[str, Any], str]:
    live = _read_json(_live_observed_path())
    obs = live.get("observed") if isinstance(live.get("observed"), dict) else {}
    iec = obs.get("iec61850") if isinstance(obs.get("iec61850"), dict) else {}
    return iec, str(live.get("generated_at") or "")


def _goose_key(entry: dict[str, Any]) -> str:
    return f"{str(entry.get('publisher_mac', '')).lower()}|{entry.get('appid')}|{entry.get('gocb_ref', '')}"


def compute_drift() -> dict[str, Any]:
    active = _active_iec()
    live, gen = _live_iec()
    has_active = bool(active.get("goose_publishers") or active.get("mms_ieds"))
    has_live = bool(gen) or bool(live.get("goose_publishers") or live.get("mms_ieds"))

    a_g = {_goose_key(e): e for e in (active.get("goose_publishers") or [])}
    l_g = {_goose_key(e): e for e in (live.get("goose_publishers") or [])}
    g_added = [l_g[k] for k in l_g if k not in a_g]
    g_removed = [a_g[k] for k in a_g if k not in l_g]
    g_changed: list[dict[str, Any]] = []
    for k in a_g:
        if k not in l_g:
            continue
        a, b = a_g[k], l_g[k]
        diffs: dict[str, Any] = {}
        if bool(a.get("production")) != bool(b.get("production")):
            diffs["production"] = [a.get("production"), b.get("production")]
        if b.get("conf_rev") is not None and a.get("conf_rev") != b.get("conf_rev"):
            diffs["conf_rev"] = [a.get("conf_rev"), b.get("conf_rev")]
        if diffs:
            g_changed.append({"publisher_mac": b.get("publisher_mac"), "appid": b.get("appid"), "gocb_ref": b.get("gocb_ref"), "changes": diffs})

    a_m = {e.get("ied_ip"): e for e in (active.get("mms_ieds") or [])}
    l_m = {e.get("ied_ip"): e for e in (live.get("mms_ieds") or [])}
    m_added = [l_m[k] for k in l_m if k not in a_m]
    m_removed = [a_m[k] for k in a_m if k not in l_m]
    m_client_changes: list[dict[str, Any]] = []
    for ip in a_m:
        if ip not in l_m:
            continue
        a_clients = set(a_m[ip].get("allowed_mms_clients") or [])
        l_clients = set(l_m[ip].get("allowed_mms_clients") or [])
        added_c = sorted(l_clients - a_clients)
        removed_c = sorted(a_clients - l_clients)
        if added_c or removed_c:
            m_client_changes.append({"ied_ip": ip, "added_clients": added_c, "removed_clients": removed_c})

    summary = {
        "added": len(g_added) + len(m_added),
        "removed": len(g_removed) + len(m_removed),
        "changed": len(g_changed) + len(m_client_changes),
    }
    summary["total"] = summary["added"] + summary["removed"] + summary["changed"]
    return {
        "ok": True,
        "has_live": has_live,
        "has_active": has_active,
        "live_generated_at": gen,
        "goose": {"added": g_added, "removed": g_removed, "changed": g_changed},
        "mms": {"added": m_added, "removed": m_removed, "client_changes": m_client_changes},
        "summary": summary,
    }


# -- state for UI ------------------------------------------------------------
def _active_summary(policy: dict[str, Any]) -> dict[str, Any] | None:
    baseline = policy.get("baseline")
    if not isinstance(baseline, dict):
        return None
    iec = baseline.get("iec61850") if isinstance(baseline.get("iec61850"), dict) else {}
    goose = iec.get("goose_publishers") if isinstance(iec.get("goose_publishers"), list) else []
    mms = iec.get("mms_ieds") if isinstance(iec.get("mms_ieds"), list) else []
    if not goose and not mms:
        return None
    return {
        "version": str(policy.get("version") or ""),
        "applied_at": str(policy.get("updated_at") or ""),
        "source": str(policy.get("baseline_source") or policy.get("source") or "unknown"),
        "goose": len(goose),
        "mms": len(mms),
    }


def get_state() -> dict[str, Any]:
    policy = _read_json(_policy_path())
    state_doc = _read_json(_state_path())
    candidate = _read_json(_candidate_path())
    active = _active_summary(policy)
    history = state_doc.get("versions") if isinstance(state_doc.get("versions"), list) else []

    cand_out = None
    pending = False
    if candidate:
        gen = candidate.get("generated_at") or ""
        applied = (active or {}).get("applied_at") or ""
        # Pending if the candidate is newer than what is currently applied.
        pending = bool(gen) and (not applied or gen > applied)
        cand_out = {
            "generated_at": gen,
            "source": candidate.get("source") or "",
            "source_ref": candidate.get("source_ref") or "",
            "stats": candidate.get("stats") or {},
            "pending": pending,
        }

    drift = compute_drift()
    drift_total = drift["summary"]["total"] if drift.get("has_active") else 0

    if cand_out and pending:
        state = "learning"  # candidate learned, awaiting approval
    elif active and drift_total > 0:
        state = "drift"
    elif active:
        state = "active"
    else:
        state = "not_loaded"

    return {
        "state": state,
        "active": active,
        "candidate": cand_out,
        "history": history,
        "drift": {"summary": drift["summary"], "has_live": drift["has_live"], "live_generated_at": drift["live_generated_at"]},
        "assets": (active or {}).get("goose", 0) + (active or {}).get("mms", 0) if active else 0,
        "comm_pairs": (candidate.get("stats", {}) if candidate else {}).get("comm_pairs", 0),
    }


# -- approve / rollback ------------------------------------------------------
def _apply_iec61850(observed_iec: dict[str, Any], *, source_ref: str, source: str) -> dict[str, Any]:
    policy = _read_json(_policy_path())
    baseline = policy.get("baseline") if isinstance(policy.get("baseline"), dict) else {}
    iec = baseline.get("iec61850") if isinstance(baseline.get("iec61850"), dict) else {}

    iec["goose_publishers"] = observed_iec.get("goose_publishers") or []
    iec["mms_ieds"] = observed_iec.get("mms_ieds") or []
    baseline["iec61850"] = iec
    policy["baseline"] = baseline

    version = f"baseline-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
    policy["version"] = version
    policy["baseline_source"] = source
    policy["updated_at"] = _now_iso()
    _atomic_write_json(_policy_path(), policy)

    # Stamp: line0 = epoch (change marker), line1 = version (read by services).
    stamp = _stamp_path()
    stamp.parent.mkdir(parents=True, exist_ok=True)
    stamp.write_text(f"{int(time.time())}\n{version}\n", encoding="utf-8")
    return {"version": version, "goose": len(iec["goose_publishers"]), "mms": len(iec["mms_ieds"])}


def _record_history(version: str, source_ref: str, observed_iec: dict[str, Any]) -> None:
    doc = _read_json(_state_path())
    versions = doc.get("versions") if isinstance(doc.get("versions"), list) else []
    for v in versions:
        if isinstance(v, dict):
            v["active"] = False
    versions.insert(0, {
        "version": version,
        "applied_at": _now_iso(),
        "source_ref": source_ref,
        "active": True,
        "goose": len(observed_iec.get("goose_publishers") or []),
        "mms": len(observed_iec.get("mms_ieds") or []),
        "snapshot": observed_iec,  # full snapshot enables rollback
    })
    doc["versions"] = versions[:20]
    doc["active_version"] = version
    _atomic_write_json(_state_path(), doc)


def approve_candidate() -> dict[str, Any]:
    candidate = _read_json(_candidate_path())
    if not candidate:
        return {"ok": False, "error": "沒有可核准的候選 baseline", "status": 404}
    observed = candidate.get("observed") if isinstance(candidate.get("observed"), dict) else {}
    iec = observed.get("iec61850") if isinstance(observed.get("iec61850"), dict) else {}
    if not (iec.get("goose_publishers") or iec.get("mms_ieds")):
        return {"ok": False, "error": "候選 baseline 不含可套用的 IEC 61850 觀測", "status": 422}
    source_ref = str(candidate.get("source_ref") or "pcap")
    applied = _apply_iec61850(iec, source_ref=source_ref, source="edge-console-learning")
    _record_history(applied["version"], source_ref, iec)
    return {"ok": True, **applied}


def approve_drift() -> dict[str, Any]:
    """Accept the current live observations as the new active baseline."""
    live, gen = _live_iec()
    if not (live.get("goose_publishers") or live.get("mms_ieds")):
        return {"ok": False, "error": "尚無 live 觀測可套用為新基線", "status": 404}
    source_ref = f"drift:{gen or 'live'}"
    applied = _apply_iec61850(live, source_ref=source_ref, source="edge-console-drift")
    _record_history(applied["version"], source_ref, live)
    return {"ok": True, **applied}


def rollback(version: str) -> dict[str, Any]:
    doc = _read_json(_state_path())
    versions = doc.get("versions") if isinstance(doc.get("versions"), list) else []
    target = next((v for v in versions if isinstance(v, dict) and v.get("version") == version), None)
    if target is None:
        return {"ok": False, "error": f"找不到版本 {version}", "status": 404}
    snapshot = target.get("snapshot") if isinstance(target.get("snapshot"), dict) else {}
    if not snapshot:
        return {"ok": False, "error": "該版本沒有可回滾的快照", "status": 422}
    source_ref = f"rollback:{version}"
    applied = _apply_iec61850(snapshot, source_ref=source_ref, source="edge-console-rollback")
    _record_history(applied["version"], source_ref, snapshot)
    return {"ok": True, **applied, "rolled_back_from": version}
