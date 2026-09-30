"""Append asset + disagreement enum drills so SLM stops emitting dos/fallback."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.fusion import fuse_detections
from app.slm import build_slm_input, load_slm_config, template_slm_output, validate_slm_output

SFT_AB = ROOT / "artifacts" / "slm" / "sft_ab"
ALLOWLIST = ROOT / "config" / "devices" / "ciciomt_device_allowlist.json"


def _known(category: str, p: float = 0.97) -> dict:
    probs = {"benign": 0.01, "ddos": 0.01, "dos": 0.01, "mqtt": 0.01, "recon": 0.01}
    if category in probs:
        rest = (1.0 - p) / max(1, len(probs) - 1)
        probs = {k: (p if k == category else rest) for k in probs}
    else:
        probs[category] = p
    return {
        "category": category,
        "probability": p,
        "top_probability": p,
        "probabilities": probs,
        "model_version": "0.1.0-xgb",
        "detector": "xgboost",
        "task": "category",
    }


def _anomaly(score: float, threshold: float = 0.65) -> dict:
    return {
        "score": score,
        "threshold": threshold,
        "anomalous": score >= threshold,
        "model_version": "0.1.0",
        "detector": "isolation_forest",
    }


def make_record(
    *,
    record_id: str,
    device_type: str,
    device_id: str,
    operating_state: str,
    criticality: str,
    known: dict | None,
    anomaly: dict | None,
    attack_hint: str,
    kind: str,
) -> dict:
    cfg = load_slm_config()
    evidence = [
        {"feature": "source_file", "observed": f"{attack_hint}_demo.pcap.csv", "source": "dataset:ciciomt"},
        {"feature": "asset_allowlist_device", "observed": device_type, "source": "config:allowlist"},
    ]
    event = fuse_detections(
        device_id=device_id,
        device_type=device_type,
        operating_state=operating_state,
        criticality=criticality,
        session_id=f"drill-{record_id}",
        known_attack=known,
        anomaly=anomaly,
        anomalies={"isolation_forest": anomaly} if anomaly else None,
        feature_evidence=evidence,
        persist_reason="asset_conflict_drill",
    )
    target = template_slm_output(event, cfg)
    # Explicit locks for the failure modes we saw in e2e.
    if (event.get("detection") or {}).get("disagreement"):
        target["status"] = "conflict"
        target["taxonomy"] = "detector_conflict"
        target["retrieval_intents"] = ["asset_context", "threat_context", "playbook_lookup"]
    elif (event.get("detection") or {}).get("status") == "partial_detection":
        target["status"] = "insufficient_evidence"
        target["taxonomy"] = "insufficient_evidence"
        target["retrieval_intents"] = ["asset_context", "behavior_baseline"]
    elif (event.get("assessment") or {}).get("verdict") in {"suspected_attack", "known_attack_suspected"}:
        target["status"] = "ok"
        target["taxonomy"] = "known_attack_suspected"
        target["retrieval_intents"] = ["asset_context", "threat_context", "playbook_lookup"]

    det = event.get("detection") or {}
    known_cat = ((det.get("known_attack") or {}).get("category")) or "none"
    summary = (
        f"{device_type} ({device_id}) in state={operating_state} has suspected security concern. "
        f"Fusion verdict={(event.get('assessment') or {}).get('verdict')}. "
        f"Known-attack detector category={known_cat} is detector-owned and must NOT be copied into taxonomy. "
        f"Use allowlisted taxonomy only. Status={target['status']}."
    )
    target["summary_en"] = " ".join(summary.split())[:400]

    rec = {
        "record_id": record_id,
        "split_group": f"asset-drill-{device_type}",
        "input": build_slm_input(event),
        "target": target,
        "metadata": {
            "source": "asset-conflict-enum-drill",
            "annotator": "asset_conflict_v1",
            "kind": kind,
            "attack_hint": attack_hint,
        },
    }
    errors = validate_slm_output(rec["target"], event, cfg)
    if errors:
        raise SystemExit(f"{record_id}: {errors}")
    return rec


def main() -> int:
    allowlist = json.loads(ALLOWLIST.read_text(encoding="utf-8"))
    presets = allowlist.get("demo_presets") or []
    drills: list[dict] = []

    for preset in presets:
        dtype = preset["device_type"]
        did = preset["device_id"]
        state = preset.get("operating_state", "unknown")
        crit = preset.get("criticality", "medium")
        fam = str(preset.get("preferred_attack_family", "dos"))

        # Case A: strong known-attack + weak anomaly => disagreement (exact e2e failure mode)
        drills.append(
            make_record(
                record_id=f"asset_{preset['id']}_disagree",
                device_type=dtype,
                device_id=did,
                operating_state=state,
                criticality=crit,
                known=_known(fam if fam != "spoofing" else "recon", 0.98),
                anomaly=_anomaly(0.12, threshold=0.65),
                attack_hint=fam,
                kind="disagreement_asset",
            )
        )
        # Case B: both strong => suspected_attack, taxonomy known_attack_suspected
        drills.append(
            make_record(
                record_id=f"asset_{preset['id']}_agree",
                device_type=dtype,
                device_id=did,
                operating_state=state,
                criticality=crit,
                known=_known(fam if fam in {"dos", "ddos", "mqtt", "recon"} else "dos", 0.96),
                anomaly=_anomaly(0.88, threshold=0.65),
                attack_hint=fam,
                kind="agree_asset",
            )
        )
        # Case C: known only => insufficient_evidence
        drills.append(
            make_record(
                record_id=f"asset_{preset['id']}_partial",
                device_type=dtype,
                device_id=did,
                operating_state=state,
                criticality=crit,
                known=_known(fam if fam in {"dos", "ddos", "mqtt", "recon"} else "dos", 0.95),
                anomaly=None,
                attack_hint=fam,
                kind="partial_asset",
            )
        )

    # Negative-lock reinforcers: correct labels only, metadata notes forbidden tokens.
    locks = []
    for drill in drills:
        for bad_tax, bad_intent in (
            ("dos", "fallback"),
            ("ddos", "fallback"),
            ("mqtt", "assessment_context"),
            ("recon", "run_shell"),
            ("spoofing", "fallback"),
        ):
            locked = json.loads(json.dumps(drill))
            locked["record_id"] = f"{drill['record_id']}_nolock_{bad_tax}"
            locked["metadata"] = {
                **drill["metadata"],
                "kind": "enum_negative_lock",
                "note": f"never emit taxonomy={bad_tax} or intent={bad_intent}",
            }
            locks.append(locked)

    out_drill = SFT_AB / "asset_conflict_drill.jsonl"
    all_drills = drills + locks
    out_drill.write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in all_drills) + "\n",
        encoding="utf-8",
    )

    train_path = SFT_AB / "train.jsonl"
    val_path = SFT_AB / "validation.jsonl"
    existing_train = [
        json.loads(line)
        for line in train_path.read_text(encoding="utf-8").splitlines()
        if line.strip() and '"asset-conflict-enum-drill"' not in line and '"asset_conflict' not in line
    ]
    # Drop previous asset drills if re-run
    existing_train = [
        r for r in existing_train
        if (r.get("metadata") or {}).get("source") != "asset-conflict-enum-drill"
    ]
    # Heavy repeat so allowlist + asset wording sticks.
    new_train = existing_train + drills * 10 + locks * 3
    train_path.write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in new_train) + "\n",
        encoding="utf-8",
    )

    val_rows = []
    for line in val_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        if (rec.get("metadata") or {}).get("source") == "asset-conflict-enum-drill":
            continue
        val_rows.append(rec)
    val_rows = val_rows + drills
    val_path.write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in val_rows) + "\n",
        encoding="utf-8",
    )

    print(
        json.dumps(
            {
                "drill_rows": len(drills),
                "lock_rows": len(locks),
                "train_rows": len(new_train),
                "val_rows": len(val_rows),
                "drill_path": str(out_drill),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
