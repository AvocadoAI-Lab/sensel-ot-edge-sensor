"""Evaluate XGB accuracy for the three CIC device templates (camera / pager / bp).

Note: all three share the same deployed XGBoost models; device_type affects RAG only.
This script measures detector accuracy under each device's typical attack family + benign profiling.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.baseline_templates import load_template
from app.classifier import load_classifier, score_known_attack
from app.data.columns import apply_column_mapping, load_column_map
from app.data.ciciomt import discover_ciciomt_csv_dirs, resolve_manifest_files
from app.data.inventory import infer_attack_family, infer_label_from_filename
from app.rag import KnowledgeBase, ReadOnlyToolBelt


CASES = [
    {
        "profile_id": "cic-template-medical-camera-v1",
        "preset_id": "demo-blink-dos",
        "attack_family": "dos",
        "benign_csv_hint": "Blink_Camera_LAN_WATCH.pcap.csv",
    },
    {
        "profile_id": "cic-template-medical-pager-v1",
        "preset_id": "demo-pager-ddos",
        "attack_family": "ddos",
        "benign_csv_hint": "Multifunctional_Pager_LAN_PHYSICAL.pcap.csv",
    },
    {
        "profile_id": "cic-template-bp-monitor-v1",
        "preset_id": "demo-bpm-mqtt",
        "attack_family": "mqtt",
        "benign_csv_hint": "Benign_test.pcap.csv",
        "benign_from_attack_test": True,
    },
]


def _features_from_row(row: pd.Series, feature_names: list[str]) -> dict[str, float] | None:
    out: dict[str, float] = {}
    for name in feature_names:
        if name not in row.index:
            out[name] = 0.0
            continue
        val = row[name]
        if pd.isna(val):
            out[name] = 0.0
            continue
        try:
            out[name] = float(val)
        except (TypeError, ValueError):
            return None
    return out


def _load_csv_frame(path: Path, mapping: dict[str, str]) -> pd.DataFrame:
    frame = pd.read_csv(path)
    rename = apply_column_mapping(list(frame.columns), mapping)
    return frame.rename(columns=rename)


def _iter_attack_rows(
    *,
    dataset_root: Path,
    manifest_path: Path,
    attack_family: str,
    feature_names: list[str],
    max_rows_per_file: int | None,
) -> list[dict[str, Any]]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    dirs = discover_ciciomt_csv_dirs(dataset_root)
    test_files = resolve_manifest_files(manifest, dirs).get("test") or []
    mapping = load_column_map()
    rows: list[dict[str, Any]] = []
    for path in test_files:
        label = infer_label_from_filename(path)
        fam = infer_attack_family(label)
        if fam != attack_family:
            continue
        frame = _load_csv_frame(path, mapping)
        if max_rows_per_file is not None:
            frame = frame.head(max_rows_per_file)
        for idx, series in frame.iterrows():
            features = _features_from_row(series, feature_names)
            if features is None:
                continue
            rows.append(
                {
                    "source_file": path.name,
                    "attack_family": fam,
                    "row_index": int(idx),
                    "features": features,
                }
            )
    return rows


def _iter_benign_rows(
    *,
    dataset_root: Path,
    csv_hint: str,
    from_attack_test: bool,
    feature_names: list[str],
    max_rows: int | None,
) -> list[dict[str, Any]]:
    mapping = load_column_map()
    if from_attack_test:
        candidates = [
            dataset_root / "WiFI_and_MQTTattacksCSVtest" / csv_hint,
            dataset_root / "WiFI_and_MQTTattacksCSVtrain" / csv_hint.replace("_test", "_train"),
        ]
        path = next((p for p in candidates if p.is_file()), None)
    else:
        candidates = [
            dataset_root / "WiFI_and_MQTTprofilingCSV" / csv_hint,
            dataset_root / "WiFi_and_MQTT" / "profiling" / "CSV" / csv_hint,
        ]
        path = next((p for p in candidates if p.is_file()), None)
    if path is None:
        return []
    frame = _load_csv_frame(path, mapping)
    if max_rows is not None:
        frame = frame.head(max_rows)
    rows: list[dict[str, Any]] = []
    for idx, series in frame.iterrows():
        features = _features_from_row(series, feature_names)
        if features is None:
            continue
        rows.append({"source_file": path.name, "row_index": int(idx), "features": features})
    return rows


def _binary_metrics(scores: list[dict[str, Any]], *, expect_attack: bool) -> dict[str, Any]:
    if not scores:
        return {"rows": 0}
    correct = 0
    for item in scores:
        pred_attack = item["binary_predicted"] == "Attack"
        if pred_attack == expect_attack:
            correct += 1
    total = len(scores)
    return {
        "rows": total,
        "accuracy": round(correct / total, 6),
        "correct": correct,
        "expect": "Attack" if expect_attack else "Benign",
    }


def _category_metrics(scores: list[dict[str, Any]]) -> dict[str, Any]:
    if not scores:
        return {"rows": 0}
    correct = 0
    for item in scores:
        if item["category_predicted"].casefold() == item["attack_family"].casefold():
            correct += 1
        elif item["category_predicted"].casefold() == "attack" and item["attack_family"] != "benign":
            correct += 1
    total = len(scores)
    return {"rows": total, "accuracy": round(correct / total, 6), "correct": correct}


def evaluate_case(
    case: dict[str, Any],
    *,
    dataset_root: Path,
    manifest_path: Path,
    xgb_binary,
    xgb_category,
    max_attack_rows_per_file: int | None,
    max_benign_rows: int | None,
) -> dict[str, Any]:
    template = load_template(case["profile_id"])
    device_type = (template.get("device_template") or {}).get("device_type", "")
    kb = KnowledgeBase(kb_dir=ROOT / "config" / "kb")
    tools = ReadOnlyToolBelt(kb, related_events_provider=lambda **_: [])
    rag_asset = tools.get_asset_profile(str(device_type))
    rag_behavior = tools.get_behavior_baseline(str(device_type), "idle")

    attack_rows = _iter_attack_rows(
        dataset_root=dataset_root,
        manifest_path=manifest_path,
        attack_family=case["attack_family"],
        feature_names=xgb_category.features,
        max_rows_per_file=max_attack_rows_per_file,
    )
    attack_scored: list[dict[str, Any]] = []
    for row in attack_rows:
        cat = score_known_attack(xgb_category, row["features"])
        binary = score_known_attack(xgb_binary, row["features"])
        if cat is None or binary is None:
            continue
        attack_scored.append(
            {
                "attack_family": row["attack_family"],
                "category_predicted": str(cat.get("category") or ""),
                "binary_predicted": str(binary.get("category") or ""),
                "category_probability": cat.get("probability"),
            }
        )

    benign_rows = _iter_benign_rows(
        dataset_root=dataset_root,
        csv_hint=case["benign_csv_hint"],
        from_attack_test=bool(case.get("benign_from_attack_test")),
        feature_names=xgb_binary.features,
        max_rows=max_benign_rows,
    )
    benign_scored: list[dict[str, Any]] = []
    for row in benign_rows:
        binary = score_known_attack(xgb_binary, row["features"])
        if binary is None:
            continue
        benign_scored.append({"binary_predicted": str(binary.get("category") or "")})

    return {
        "profile_id": case["profile_id"],
        "preset_id": case["preset_id"],
        "device_type": device_type,
        "attack_family_evaluated": case["attack_family"],
        "benign_source": case["benign_csv_hint"],
        "stats_source": template.get("stats_source"),
        "rate_p95_hint": ((template.get("observed") or {}).get("thresholds") or {}).get("rate_p95_hint"),
        "rag_asset_ok": rag_asset.ok,
        "rag_behavior_ok": rag_behavior.ok,
        "attack_binary": _binary_metrics(attack_scored, expect_attack=True),
        "attack_category": _category_metrics(attack_scored),
        "benign_binary_fp": _binary_metrics(benign_scored, expect_attack=False),
        "benign_fp_rate": round(
            sum(1 for s in benign_scored if s["binary_predicted"] == "Attack") / max(len(benign_scored), 1),
            6,
        )
        if benign_scored
        else None,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset-root", type=Path, default=Path(r"D:\實習\資料集"))
    parser.add_argument(
        "--manifest",
        type=Path,
        default=ROOT / "artifacts" / "ciciomt" / "official_file_manifest.json",
    )
    parser.add_argument("--max-attack-rows-per-file", type=int, default=0, help="0 = all rows per attack file")
    parser.add_argument("--max-benign-rows", type=int, default=0, help="0 = all benign rows")
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "artifacts" / "eval" / "three_device_templates_eval.json",
    )
    args = parser.parse_args()

    max_attack = None if args.max_attack_rows_per_file <= 0 else args.max_attack_rows_per_file
    max_benign = None if args.max_benign_rows <= 0 else args.max_benign_rows

    xgb_binary = load_classifier(ROOT / "artifacts" / "classifiers" / "xgboost_binary.joblib")
    xgb_category = load_classifier(ROOT / "artifacts" / "classifiers" / "xgboost_category.joblib")

    results = []
    for case in CASES:
        print(f"Evaluating {case['profile_id']} ({case['attack_family']} + benign)...", flush=True)
        results.append(
            evaluate_case(
                case,
                dataset_root=args.dataset_root,
                manifest_path=args.manifest,
                xgb_binary=xgb_binary,
                xgb_category=xgb_category,
                max_attack_rows_per_file=max_attack,
                max_benign_rows=max_benign,
            )
        )

    report = {
        "note": "Shared XGBoost models; device_type templates differ in RAG/baseline stats only.",
        "dataset_root": str(args.dataset_root),
        "cases": results,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print(f"\nWrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
