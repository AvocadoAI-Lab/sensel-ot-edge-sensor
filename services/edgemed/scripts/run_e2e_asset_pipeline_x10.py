"""Run 10 end-to-end asset pipeline cases and score pass/fail."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.classifier import load_classifier, score_known_attack
from app.fusion import fuse_detections
from app.guardrails import enforce_advisory_response, load_security_policy
from app.rag import build_default_orchestrator
from app.schema import assert_detector_fields_unchanged, detector_owned_snapshot
from app.slm import apply_slm_to_event, build_slm_input

from scripts.run_e2e_asset_pipeline import (
    generate_slm,
    load_allowlist,
    load_attack_row,
    score_anomaly_if,
)


def evaluate_case(report_like: dict, allowlist_types: set[str]) -> dict:
    checks = {}
    asset = report_like.get("asset") or {}
    xgb = report_like.get("xgboost") or {}
    fusion = report_like.get("fusion") or {}
    slm = report_like.get("slm") or {}
    rag = report_like.get("rag") or {}
    response = report_like.get("response") or {}

    checks["has_asset_type"] = bool(asset.get("device_type")) and asset.get("device_type") in allowlist_types
    checks["xgb_scored"] = bool(xgb.get("category")) and xgb.get("probability") is not None
    checks["fusion_verdict"] = bool(fusion.get("verdict"))
    checks["slm_applied"] = slm.get("generation_status") in {
        "generated",
        "template_fallback",
    }
    sources = rag.get("sources") or []
    checks["rag_available"] = rag.get("status") == "available"
    checks["rag_has_asset"] = any(
        (s.get("source_id") or "").startswith("asset-profile:") for s in sources
    )
    checks["advisory_only"] = (response.get("mode") == "advisory_only")
    checks["detector_unchanged"] = bool(report_like.get("detector_unchanged", False))

    failed = [name for name, ok in checks.items() if not ok]
    return {
        "passed": not failed,
        "failed_checks": failed,
        "checks": checks,
        "slm_generation_status": slm.get("generation_status"),
    }


def main() -> int:
    allowlist_path = ROOT / "config" / "devices" / "ciciomt_device_allowlist.json"
    allowlist = load_allowlist(allowlist_path)
    presets = allowlist.get("demo_presets") or []
    if len(presets) < 10:
        raise SystemExit(f"Need 10 presets, found {len(presets)}")
    presets = presets[:10]
    allowlist_types = set(allowlist.get("allowed_device_types") or [])

    xgb = load_classifier(ROOT / "artifacts" / "classifiers" / "xgboost_category.joblib")
    detector_path = ROOT / "artifacts" / "detector.joblib"
    model_id = "HuggingFaceTB/SmolLM2-360M-Instruct"
    adapter = str(ROOT / "artifacts" / "slm" / "smollm2-360m-lora-ab" / "adapter")
    security_policy = load_security_policy()
    rag = build_default_orchestrator(related_events_provider=lambda device_id, limit=5: [])

    # Warm SLM once
    print("Loading SLM (once)...", flush=True)
    warm_event = fuse_detections(
        device_id="warm",
        device_type="medical_aiot",
        operating_state="unknown",
        criticality="medium",
        known_attack={
            "category": "dos",
            "probability": 0.9,
            "top_probability": 0.9,
            "probabilities": {"dos": 0.9},
            "model_version": "warm",
            "detector": "xgboost",
            "task": "category",
        },
        anomaly={"score": 0.2, "threshold": 0.5, "anomalous": False, "detector": "isolation_forest"},
        feature_evidence=[{"feature": "warm", "observed": 1, "source": "test"}],
    )
    generate_slm(warm_event, model_id, adapter if Path(adapter).exists() else None, max_new_tokens=32)

    rows = []
    for index, preset in enumerate(presets, start=1):
        case_id = f"t{index:02d}"
        print(f"[{case_id}] {preset['id']} ...", flush=True)
        try:
            row = load_attack_row(
                dataset_root=Path(r"D:\實習\資料集"),
                manifest_path=ROOT / "artifacts" / "ciciomt" / "official_file_manifest.json",
                family=str(preset.get("preferred_attack_family", "dos")),
                seed=40 + index,
            )
            features = {name: float(row["features"].get(name, 0.0)) for name in xgb.features}
            known = score_known_attack(xgb, features)
            if known is None:
                raise RuntimeError("xgboost score failed")
            anomaly, if_evidence = score_anomaly_if(features, detector_path)
            feature_evidence = [
                {"feature": "source_file", "observed": row["source_file"], "source": "dataset:ciciomt"},
                {"feature": "attack_family_label", "observed": row["attack_family"], "source": "dataset:label"},
                {
                    "feature": "asset_allowlist_device",
                    "observed": preset["device_name"],
                    "source": "config:ciciomt_device_allowlist",
                },
            ] + if_evidence
            event = fuse_detections(
                device_id=preset["device_id"],
                device_type=preset["device_type"],
                operating_state=preset["operating_state"],
                criticality=preset.get("criticality", "high"),
                session_id=f"{preset['id']}:{row['source_file']}",
                known_attack=known,
                anomaly=anomaly,
                anomalies={"isolation_forest": anomaly} if anomaly else None,
                feature_evidence=feature_evidence,
                persist_reason="e2e_x10",
            )
            event["asset"]["device_name"] = preset.get("device_name")
            event["asset"]["interaction_mode"] = preset.get("interaction_mode")
            event["asset"]["allowlist_ref"] = "config/devices/ciciomt_device_allowlist.json"
            event = enforce_advisory_response(event, security_policy)

            before = detector_owned_snapshot(event)
            raw_slm, parsed_slm = generate_slm(
                event,
                model_id,
                adapter if Path(adapter).exists() else None,
                max_new_tokens=220,
            )
            event = apply_slm_to_event(event, parsed_slm)
            event = rag.apply(event)
            unchanged = True
            try:
                assert_detector_fields_unchanged(
                    {"detection": before["detection"], "evidence": before["evidence"]},
                    event,
                )
            except Exception:
                unchanged = False
            event = enforce_advisory_response(event, security_policy)

            report_like = {
                "asset": event.get("asset"),
                "xgboost": {
                    "category": known.get("category"),
                    "probability": known.get("probability"),
                },
                "fusion": {
                    "verdict": (event.get("assessment") or {}).get("verdict"),
                    "disagreement": (event.get("detection") or {}).get("disagreement"),
                },
                "slm": {
                    "generation_status": (event.get("assessment") or {}).get("generation_status"),
                    "summary": (event.get("assessment") or {}).get("summary"),
                    "taxonomy": (event.get("assessment") or {}).get("taxonomy"),
                    "raw": raw_slm,
                    "parsed": parsed_slm,
                    "asset_context": build_slm_input(event).get("asset_context"),
                },
                "rag": {
                    "status": (event.get("enrichment") or {}).get("status"),
                    "sources": (event.get("enrichment") or {}).get("sources"),
                    "claims": (event.get("enrichment") or {}).get("claims"),
                },
                "response": event.get("response"),
                "detector_unchanged": unchanged,
                "source_file": row["source_file"],
                "dataset_family": row["attack_family"],
            }
            verdict = evaluate_case(report_like, allowlist_types)
            rows.append(
                {
                    "case_id": case_id,
                    "preset_id": preset["id"],
                    "device_type": preset["device_type"],
                    "device_name": preset.get("device_name"),
                    "dataset_family": row["attack_family"],
                    "source_file": row["source_file"],
                    "xgb_category": known.get("category"),
                    "xgb_probability": known.get("probability"),
                    "fusion_verdict": (event.get("assessment") or {}).get("verdict"),
                    "disagreement": (event.get("detection") or {}).get("disagreement"),
                    "slm_status": (event.get("assessment") or {}).get("generation_status"),
                    "rag_status": (event.get("enrichment") or {}).get("status"),
                    "ok": verdict["passed"],
                    "failed_checks": verdict["failed_checks"],
                    "detail": report_like,
                }
            )
            print(
                f"  -> {'PASS' if verdict['passed'] else 'FAIL'} "
                f"slm={report_like['slm']['generation_status']} rag={report_like['rag']['status']}",
                flush=True,
            )
        except Exception as exc:
            rows.append(
                {
                    "case_id": case_id,
                    "preset_id": preset["id"],
                    "ok": False,
                    "failed_checks": ["exception"],
                    "error": str(exc),
                }
            )
            print(f"  -> FAIL exception: {exc}", flush=True)

    passed = sum(1 for r in rows if r.get("ok"))
    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "n": len(rows),
        "passed": passed,
        "failed": len(rows) - passed,
        "pass_rate": passed / len(rows) if rows else 0.0,
        "pass_definition": [
            "asset.device_type in allowlist",
            "xgboost scored",
            "fusion has verdict",
            "slm applied (generated or template_fallback)",
            "rag available",
            "rag has asset-profile source",
            "response.mode advisory_only",
            "detector fields unchanged",
        ],
        "note": "slm template_fallback still counts as pipeline pass; generation_status is reported separately",
        "cases": rows,
    }

    out_dir = ROOT / "artifacts" / "e2e"
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "asset_pipeline_x10.json"
    md_path = out_dir / "asset_pipeline_x10.md"
    json_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    lines = [
        "# E2E Asset Pipeline ×10",
        "",
        f"- Passed: **{passed}/10**",
        f"- Pass rate: {summary['pass_rate']:.0%}",
        "",
        "| Case | Preset | Device | Attack file | XGB | Fusion | SLM | RAG | Result |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        lines.append(
            "| {case_id} | {preset_id} | {device} | {src} | {xgb} | {verdict} | {slm} | {rag} | {ok} |".format(
                case_id=r.get("case_id"),
                preset_id=r.get("preset_id"),
                device=r.get("device_type", "-"),
                src=r.get("source_file", "-"),
                xgb=f"{r.get('xgb_category')}@{r.get('xgb_probability')}",
                verdict=r.get("fusion_verdict", "-"),
                slm=r.get("slm_status", "-"),
                rag=r.get("rag_status", "-"),
                ok="PASS" if r.get("ok") else "FAIL",
            )
        )
    lines.append("")
    lines.append(f"Full JSON: `{json_path.as_posix()}`")
    md_path.write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps({"passed": passed, "n": 10, "json": str(json_path), "md": str(md_path)}, indent=2))
    return 0 if passed == 10 else 1


if __name__ == "__main__":
    raise SystemExit(main())
