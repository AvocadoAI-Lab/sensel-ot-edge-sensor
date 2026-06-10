"""Read-only view of the OT detection policy applied on this edge sensor."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

RULE_LABELS_ZH: dict[str, str] = {
    "OT-001": "新 MAC 出現",
    "OT-002": "新 IP 出現",
    "OT-003": "MAC-IP 綁定異常",
    "OT-004": "新通訊對",
    "OT-005": "新目的埠",
    "OT-006": "埠掃描行為",
    "OT-007": "非預期 Modbus 寫入",
    "OT-008": "異常流量速率",
    "OT-009": "Relay 離線",
    "OT-010": "未授權主機存取 Relay",
    "OT-011": "新 GOOSE publisher",
    "OT-012": "GOOSE test bit（正式環境）",
    "OT-013": "GOOSE stNum 異常",
    "OT-014": "新 MMS 客戶端連線 IED",
    "OT-015": "MMS 連線速率異常",
    "OT-016": "非預期 MMS 寫入",
    "OT-017": "GOOSE 靜默（IED 離線）",
    "OT-018": "未授權 MMS 存取 Relay IED",
    "OT-019": "CTI IoC 命中",
}


def _policy_path() -> Path:
    return Path(os.environ.get("DETECTION_POLICY_PATH", "/data/agent/detection-policy.json"))


def _stamp_path() -> Path:
    return Path(os.environ.get("DETECTION_POLICY_STAMP_PATH", "/data/agent/detection-policy.stamp"))


def _static_baseline_path() -> Path:
    policy_dir = Path(os.environ.get("POLICY_DIR", "/data/config/policy"))
    baseline = policy_dir / "baseline.json"
    if baseline.is_file():
        return baseline
    alt = Path("/app/config/policy/baseline.json")
    return alt if alt.is_file() else baseline


def _read_stamp(stamp_path: Path) -> dict[str, Any] | None:
    if not stamp_path.is_file():
        return None
    try:
        lines = stamp_path.read_text(encoding="utf-8").strip().splitlines()
    except OSError:
        return None
    if not lines:
        return None
    mtime_iso = datetime.fromtimestamp(
        stamp_path.stat().st_mtime,
        tz=timezone.utc,
    ).isoformat().replace("+00:00", "Z")
    version = lines[1].strip() if len(lines) > 1 else ""
    return {"mtime_iso": mtime_iso, "version": version}


def _extract_mms_summary(baseline: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not isinstance(baseline, dict):
        return []
    iec = baseline.get("iec61850")
    if not isinstance(iec, dict):
        return []
    mms_ieds = iec.get("mms_ieds")
    if not isinstance(mms_ieds, list):
        return []
    out: list[dict[str, Any]] = []
    for entry in mms_ieds:
        if not isinstance(entry, dict):
            continue
        clients = entry.get("allowed_mms_clients")
        if not isinstance(clients, list):
            clients = []
        out.append(
            {
                "ied_ip": str(entry.get("ied_ip") or "").strip(),
                "asset_id": str(entry.get("asset_id") or "").strip(),
                "allowed_mms_clients": [str(c).strip() for c in clients if str(c).strip()],
            }
        )
    return out


def _rule_entries(rules: list[str]) -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    for raw in sorted(rules, key=lambda r: r.upper()):
        rid = str(raw).strip().upper()
        if not rid:
            continue
        entries.append({"rule_id": rid, "label_zh": RULE_LABELS_ZH.get(rid, rid)})
    return entries


def _fallback_info() -> dict[str, Any] | None:
    static = _static_baseline_path()
    if static.is_file():
        return {
            "kind": "static_baseline",
            "path": str(static),
            "note": "尚未收到 Portal MQTT 政策；packet-sensor 可能使用 compose 內建 baseline / sensor.yaml",
        }
    return {
        "kind": "none",
        "path": "",
        "note": "無 detection-policy.json，亦無靜態 baseline.json",
    }


def build_applied_detection_policy() -> dict[str, Any]:
    """Return the detection policy currently on disk (read-only)."""
    policy_path = _policy_path()
    stamp_path = _stamp_path()

    if not policy_path.is_file():
        return {
            "loaded": False,
            "path": str(policy_path),
            "error": None,
            "fallback": _fallback_info(),
            "portal_compare": {
                "enabled": False,
                "status": "skipped",
                "detail": "本地政策檔不存在",
            },
        }

    try:
        data = json.loads(policy_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return {
            "loaded": False,
            "path": str(policy_path),
            "error": str(exc),
            "fallback": _fallback_info(),
            "portal_compare": {
                "enabled": False,
                "status": "skipped",
                "detail": "無法解析本地政策檔",
            },
        }

    if not isinstance(data, dict):
        return {
            "loaded": False,
            "path": str(policy_path),
            "error": "policy root must be an object",
            "fallback": _fallback_info(),
            "portal_compare": {
                "enabled": False,
                "status": "skipped",
                "detail": "無法解析本地政策檔",
            },
        }

    rules_raw = data.get("rules_enabled") or []
    rules = (
        sorted(
            [str(r).strip().upper() for r in rules_raw if str(r).strip()],
            key=lambda r: r.upper(),
        )
        if isinstance(rules_raw, list)
        else []
    )
    baseline = data.get("baseline") if isinstance(data.get("baseline"), dict) else None
    source = str(data.get("source") or "unknown").strip() or "unknown"

    return {
        "loaded": True,
        "path": str(policy_path),
        "schema_version": str(data.get("schema_version") or ""),
        "tenant_id": str(data.get("tenant_id") or ""),
        "site_id": str(data.get("site_id") or ""),
        "sensor_id": data.get("sensor_id"),
        "version": str(data.get("version") or ""),
        "updated_at": str(data.get("updated_at") or ""),
        "generated_at": str(data.get("generated_at") or ""),
        "source": source,
        "rules_enabled": rules,
        "rules_count": len(rules),
        "rule_entries": _rule_entries(rules),
        "mms_summary": _extract_mms_summary(baseline),
        "stamp": _read_stamp(stamp_path),
        "fallback": None,
        "portal_compare": {
            "enabled": False,
            "status": "skipped",
            "detail": "Portal 比對尚未實作；請至 Control Plane 工控安全防護 → 偵測政策 查看發布版本",
        },
    }
