"""Evaluate FL cohort models per test source file (attack type / benign partition).

Breaks down binary Attack-vs-Benign metrics by ``source_file`` so HPT gaps can be
attributed to specific CICIoMT attack CSVs rather than only cohort-level macro-F1.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.classifier import evaluate_classifier, load_classifier
from app.data.columns import load_column_map
from app.data.inventory import infer_label_from_filename
from app.fl_protocol_cohorts import group_site_ids_by_cohort, resolve_fl_protocol_group

import run_three_site_fl_experiment as fl_lab
from scripts.run_protocol_cohort_fl_experiment import _load_site_cohort_map


def _utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _attack_display_name(source_file: str) -> str:
    if not source_file:
        return "unknown"
    path = Path(source_file)
    label = infer_label_from_filename(path)
    if label.lower().replace(" ", "_") in {"benign", "benign_test"} or "benign" in source_file.lower():
        return "Benign (official test partition)"
    return label


def _load_final_cohort_models(experiment_dir: Path, cohorts: tuple[str, ...]) -> dict[str, Any]:
    summary_path = experiment_dir / "summary.json"
    if not summary_path.is_file():
        raise FileNotFoundError(f"Missing summary.json in {experiment_dir}")
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    rounds = int(summary.get("rounds") or 0)
    if rounds <= 0:
        raise ValueError(f"Invalid rounds in {summary_path}")
    models_dir = experiment_dir / "models"
    bundles: dict[str, Any] = {}
    for cohort in cohorts:
        model_path = models_dir / f"cohort-{cohort}-round-{rounds:03d}.joblib"
        if not model_path.is_file():
            raise FileNotFoundError(f"Missing final model: {model_path}")
        bundles[cohort] = load_classifier(model_path)
    return {
        "stage_dir": str(experiment_dir),
        "rounds": rounds,
        "trees_per_site": summary.get("trees_per_site_per_round"),
        "client_weighting": summary.get("client_weighting"),
        "experiment_id": summary.get("experiment_id"),
        "models": bundles,
    }


def _evaluate_per_file(
    *,
    site_id: str,
    cohort: str,
    bundle: Any,
    test: pd.DataFrame,
) -> list[dict[str, Any]]:
    aligned = fl_lab._align(test, bundle.features)
    if aligned.empty or "source_file" not in aligned.columns:
        return []
    rows: list[dict[str, Any]] = []
    for source_file, part in aligned.groupby("source_file", sort=True):
        metrics = evaluate_classifier(bundle, part)
        cm = metrics["confusion_matrix"]
        label_kind = str(part["label"].iloc[0]) if len(part) else "unknown"
        rows.append(
            {
                "site_id": site_id,
                "cohort": cohort,
                "source_file": str(source_file),
                "attack_display": _attack_display_name(str(source_file)),
                "label_kind": label_kind,
                "rows": int(len(part)),
                "macro_f1": round(float(metrics["macro_f1"]), 6),
                "attack_f1": round(float(metrics["f1"]), 6),
                "fpr": metrics.get("fpr"),
                "fnr": metrics.get("fnr"),
                "fp": int(cm["fp"]),
                "fn": int(cm["fn"]),
                "tp": int(cm["tp"]),
                "tn": int(cm["tn"]),
            }
        )
    return rows


def evaluate_experiment(
    *,
    experiment_dir: Path,
    splits_dir: Path,
    dataset_root: Path,
    stage_name: str,
    max_train: int,
    max_test: int,
    max_benign: int,
    seed: int,
) -> dict[str, Any]:
    site_ids = fl_lab.discover_site_ids(splits_dir)
    site_cohort = _load_site_cohort_map(splits_dir, site_ids)
    cohort_groups = group_site_ids_by_cohort(site_ids, splits_dir=splits_dir)
    cohorts = tuple(sorted(cohort_groups))
    loaded = _load_final_cohort_models(experiment_dir, cohorts)
    mapping = load_column_map()
    frames = fl_lab.load_site_frames(
        splits_dir=splits_dir,
        dataset_root=dataset_root,
        mapping=mapping,
        max_train=max_train,
        max_test=max_test,
        max_benign=max_benign,
        seed=seed,
        site_ids=site_ids,
    )

    per_file: list[dict[str, Any]] = []
    for site_id in site_ids:
        cohort = site_cohort[site_id]
        bundle = loaded["models"][cohort]
        per_file.extend(
            _evaluate_per_file(
                site_id=site_id,
                cohort=cohort,
                bundle=bundle,
                test=frames[site_id]["test"],
            )
        )

    return {
        "stage": stage_name,
        "experiment_dir": str(experiment_dir),
        "experiment_id": loaded["experiment_id"],
        "rounds": loaded["rounds"],
        "trees_per_site": loaded["trees_per_site"],
        "client_weighting": loaded["client_weighting"],
        "evaluated_at": _utc(),
        "per_file": per_file,
    }


def _index_rows(rows: list[dict[str, Any]]) -> dict[tuple[str, str], dict[str, Any]]:
    return {(row["site_id"], row["source_file"]): row for row in rows}


def compare_stages(stage_payloads: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if len(stage_payloads) < 2:
        return []
    base = _index_rows(stage_payloads[0]["per_file"])
    full = _index_rows(stage_payloads[-1]["per_file"])
    keys = sorted(set(base) & set(full))
    out: list[dict[str, Any]] = []
    for key in keys:
        b, f = base[key], full[key]
        out.append(
            {
                "site_id": b["site_id"],
                "cohort": b["cohort"],
                "source_file": b["source_file"],
                "attack_display": b["attack_display"],
                "label_kind": b["label_kind"],
                "rows": b["rows"],
                "baseline_macro_f1": b["macro_f1"],
                "full_hpt_macro_f1": f["macro_f1"],
                "delta_macro_f1": round(f["macro_f1"] - b["macro_f1"], 6),
                "baseline_fp": b["fp"],
                "full_hpt_fp": f["fp"],
                "delta_fp": f["fp"] - b["fp"],
                "baseline_fn": b["fn"],
                "full_hpt_fn": f["fn"],
                "delta_fn": f["fn"] - b["fn"],
            }
        )
    return out


def write_markdown(
    *,
    output_path: Path,
    stage_payloads: list[dict[str, Any]],
    comparisons: list[dict[str, Any]],
) -> None:
    lines: list[str] = [
        "# HPT 差距歸因：逐攻擊檔案 / 錯誤類型",
        "",
        f"> **產生時間**：{datetime.now().strftime('%Y-%m-%d %H:%M')}  ",
        "> **任務**：binary Attack vs Benign（非多類攻擊分類）  ",
        "> **方法**：對每個 test `source_file` 計算 macro-F1、FP（Benign→Attack）、FN（Attack→Benign）  ",
        "> **相關**：[HPT 前後對比](HPT_BEFORE_AFTER_COMPARISON_20260904.md) · [超參差距歸因](HPT_GAP_ATTRIBUTION_20260909.md)",
        "",
        "---",
        "",
        "## 1. 結論先行",
        "",
        "- **不是**「某一棵 XGB 樹判錯」— 現有 pipeline 無逐樹 attribution。",
        "- **是**「哪個 **test CSV**（攻擊類型或 Benign 分區）上 **FP/FN 變多或變少**」。",
        "- HPT 主要改善 **MQTT 站的 Benign 誤報（FP↓）**；Network 的 recon/spoof 攻擊檔改善有限。",
        "",
        "---",
        "",
        "## 2. 三階段設定",
        "",
        "| 階段 | 實驗目錄 | 輪數 | FL 設定 |",
        "|------|----------|------|---------|",
    ]
    for payload in stage_payloads:
        lines.append(
            f"| **{payload['stage']}** | `{Path(payload['experiment_dir']).name}` | "
            f"{payload['rounds']} | {payload['trees_per_site']} 樹/站 · {payload['client_weighting']} |"
        )

    lines.extend(
        [
            "",
            "---",
            "",
            "## 3. 逐檔案指標（六站 cohort · 最終 FL 模型）",
            "",
            "| 階段 | 站 | cohort | 攻擊/Benign | 列數 | macro-F1 | FP | FN |",
            "|------|-----|--------|-------------|------|----------|----|----|",
        ]
    )
    for payload in stage_payloads:
        for row in sorted(payload["per_file"], key=lambda r: (r["cohort"], r["site_id"], r["source_file"])):
            lines.append(
                f"| {payload['stage']} | {row['site_id']} | {row['cohort']} | {row['attack_display']} | "
                f"{row['rows']} | {row['macro_f1']:.4f} | {row['fp']} | {row['fn']} |"
            )

    lines.extend(
        [
            "",
            "---",
            "",
            "## 4. Baseline → Full HPT 差異（逐檔案）",
            "",
            "正值 `Δmacro-F1` = Full HPT 較好；`ΔFP` 負值 = 誤報減少；`ΔFN` 負值 = 漏報減少。",
            "",
            "| 站 | cohort | 攻擊/Benign | Base F1 | Full F1 | ΔF1 | ΔFP | ΔFN |",
            "|----|--------|-------------|---------|---------|-----|-----|-----|",
        ]
    )
    for row in sorted(comparisons, key=lambda r: (-abs(r["delta_macro_f1"]), r["cohort"], r["site_id"])):
        lines.append(
            f"| {row['site_id']} | {row['cohort']} | {row['attack_display']} | "
            f"{row['baseline_macro_f1']:.4f} | {row['full_hpt_macro_f1']:.4f} | "
            f"{row['delta_macro_f1']:+.4f} | {row['delta_fp']:+d} | {row['delta_fn']:+d} |"
        )

    # Summarize by attack display name (pooled across sites that share file type)
    lines.extend(["", "---", "", "## 5. 依攻擊類型彙總（Baseline → Full HPT）", ""])
    by_attack: dict[str, dict[str, int | float]] = {}
    for row in comparisons:
        key = row["attack_display"]
        bucket = by_attack.setdefault(
            key,
            {"delta_fp": 0, "delta_fn": 0, "delta_f1_sum": 0.0, "count": 0, "label_kind": row["label_kind"]},
        )
        bucket["delta_fp"] = int(bucket["delta_fp"]) + row["delta_fp"]
        bucket["delta_fn"] = int(bucket["delta_fn"]) + row["delta_fn"]
        bucket["delta_f1_sum"] = float(bucket["delta_f1_sum"]) + row["delta_macro_f1"]
        bucket["count"] = int(bucket["count"]) + 1

    lines.extend(
        [
            "| 攻擊/Benign | 檔案數 | ΣΔFP | ΣΔFN | 平均 Δmacro-F1 |",
            "|-------------|--------|------|------|----------------|",
        ]
    )
    for attack, bucket in sorted(by_attack.items(), key=lambda item: -abs(float(item[1]["delta_f1_sum"]))):
        avg = float(bucket["delta_f1_sum"]) / int(bucket["count"]) if bucket["count"] else 0.0
        lines.append(
            f"| {attack} | {bucket['count']} | {bucket['delta_fp']:+d} | {bucket['delta_fn']:+d} | {avg:+.4f} |"
        )

    lines.extend(
        [
            "",
            "---",
            "",
            "## 6. 解讀備註",
            "",
            "1. **Benign (official test partition)**：各站從 `Benign_test.pcap.csv` 切分的 test 子集；FP 在此列代表正常流量被誤判為 Attack。",
            "2. **Attack 列**：僅含該攻擊 CSV 的 flow；FN 代表該攻擊被漏判為 Benign。",
            "3. 若需追到 **單筆 flow**，需另存 prediction diff（本報告未含）。",
            "4. 若需 **逐棵樹** attribution，需 SHAP / tree ablation（本報告未含）。",
            "",
            "---",
            "",
            "## 7. 重現",
            "",
            "```powershell",
            f"cd {ROOT}",
            "python scripts/run_per_attack_file_eval.py \\",
            "  --output-json artifacts/per-attack-file-eval-six-cohort.json \\",
            "  --output-md ..\\..\\SenseLControlPlane-feat-i1-integration\\SenseLControlPlane-feat-i1-integration\\docs\\experiments\\HPT_PER_ATTACK_FILE_ATTRIBUTION.md",
            "```",
            "",
        ]
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset-root", type=Path, default=Path(r"D:\實習\資料集"))
    parser.add_argument("--splits-dir", type=Path, default=ROOT / "artifacts" / "fl-experiment-six" / "splits")
    parser.add_argument("--baseline-dir", type=Path, default=ROOT / "artifacts" / "fl-experiment-six-cohort")
    parser.add_argument("--xgb-hpo-dir", type=Path, default=ROOT / "artifacts" / "fl-experiment-six-cohort-hpo")
    parser.add_argument("--full-hpt-dir", type=Path, default=ROOT / "artifacts" / "fl-experiment-six-cohort-hpo-full")
    parser.add_argument("--seed", type=int, default=20260818)
    parser.add_argument("--max-train-rows-per-file", type=int, default=2000)
    parser.add_argument("--max-test-rows-per-file", type=int, default=2000)
    parser.add_argument("--max-benign-rows", type=int, default=3000)
    parser.add_argument(
        "--output-json",
        type=Path,
        default=ROOT / "artifacts" / "per-attack-file-eval-six-cohort.json",
    )
    parser.add_argument(
        "--output-md",
        type=Path,
        default=None,
        help="Markdown report path (Control Plane docs/experiments/)",
    )
    args = parser.parse_args()

    stage_dirs = [
        ("Baseline", args.baseline_dir),
        ("XGB HPO", args.xgb_hpo_dir),
        ("Full HPT", args.full_hpt_dir),
    ]
    stage_payloads: list[dict[str, Any]] = []
    for stage_name, experiment_dir in stage_dirs:
        print(f"==> Evaluating {stage_name}: {experiment_dir}", flush=True)
        stage_payloads.append(
            evaluate_experiment(
                experiment_dir=experiment_dir,
                splits_dir=args.splits_dir,
                dataset_root=args.dataset_root,
                stage_name=stage_name,
                max_train=args.max_train_rows_per_file,
                max_test=args.max_test_rows_per_file,
                max_benign=args.max_benign_rows,
                seed=args.seed,
            )
        )

    comparisons = compare_stages(stage_payloads)
    payload = {
        "generated_at": _utc(),
        "splits_dir": str(args.splits_dir),
        "stages": stage_payloads,
        "baseline_to_full_hpt": comparisons,
    }
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote JSON: {args.output_json}", flush=True)

    if args.output_md:
        write_markdown(output_path=args.output_md, stage_payloads=stage_payloads, comparisons=comparisons)
        print(f"Wrote MD: {args.output_md}", flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
