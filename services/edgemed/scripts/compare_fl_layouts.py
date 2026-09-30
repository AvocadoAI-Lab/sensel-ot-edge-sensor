#!/usr/bin/env python3
"""Compare two FL experiment summaries (e.g. three-site vs six-site)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _metric_row(label: str, three: Any, six: Any, *, higher_better: bool = True) -> dict[str, Any]:
    delta = None
    if isinstance(three, (int, float)) and isinstance(six, (int, float)):
        delta = round(float(six) - float(three), 6)
    winner = "tie"
    if delta is not None and delta != 0:
        if higher_better:
            winner = "six" if delta > 0 else "three"
        else:
            winner = "six" if delta < 0 else "three"
    return {"metric": label, "three_site": three, "six_site": six, "delta_six_minus_three": delta, "winner": winner}


def build_comparison(three: dict[str, Any], six: dict[str, Any]) -> dict[str, Any]:
    three_rounds = three.get("federated_rounds") or []
    six_rounds = six.get("federated_rounds") or []
    three_e1 = (three.get("local_only") or {}).get("per_local_model") or {}
    six_e1 = (six.get("local_only") or {}).get("per_local_model") or {}

    rows = [
        _metric_row("E0 federation base macro-F1", three.get("E0_round0_macro_f1"), six.get("E0_round0_macro_f1")),
        _metric_row("E1 local-only cross-site macro-F1 mean", three.get("E1_local_cross_site_macro_f1_mean"), six.get("E1_local_cross_site_macro_f1_mean")),
        _metric_row("E2 round-5 macro-F1", three.get("E2_round5_macro_f1"), six.get("E2_round5_macro_f1")),
        _metric_row("E3 centralized oracle macro-F1", three.get("E3_centralized_macro_f1"), six.get("E3_centralized_macro_f1")),
        _metric_row("total experiment seconds", three.get("total_experiment_seconds"), six.get("total_experiment_seconds"), higher_better=False),
    ]
    if three_rounds and six_rounds:
        rows.append(
            _metric_row(
                "round-5 update bytes",
                three_rounds[-1].get("update_bytes"),
                six_rounds[-1].get("update_bytes"),
                higher_better=False,
            )
        )
        rows.append(
            _metric_row(
                "round-5 wall seconds",
                three_rounds[-1].get("round_seconds"),
                six_rounds[-1].get("round_seconds"),
                higher_better=False,
            )
        )

    round_curve = []
    for left, right in zip(three_rounds, six_rounds):
        round_curve.append(
            {
                "round": left.get("round"),
                "three_macro_f1": left.get("macro_f1"),
                "six_macro_f1": right.get("macro_f1"),
                "delta": round(float(right.get("macro_f1", 0)) - float(left.get("macro_f1", 0)), 6),
            }
        )

    per_site_e1 = {
        "three_site": {site: payload.get("macro_f1") for site, payload in three_e1.items()},
        "six_site": {site: payload.get("macro_f1") for site, payload in six_e1.items()},
    }

    interpretation = []
    e2_three = three.get("E2_round5_macro_f1")
    e2_six = six.get("E2_round5_macro_f1")
    if isinstance(e2_three, (int, float)) and isinstance(e2_six, (int, float)):
        if e2_six > e2_three:
            interpretation.append("Six-site FL round-5 macro-F1 is higher than three-site on the same seed and hyperparameters.")
        elif e2_six < e2_three:
            interpretation.append("Six-site FL round-5 macro-F1 is lower than three-site; more clients did not improve the proxy aggregate in this run.")
        else:
            interpretation.append("Six-site and three-site round-5 macro-F1 are equal in this run.")

    e1_three = three.get("E1_local_cross_site_macro_f1_mean")
    e1_six = six.get("E1_local_cross_site_macro_f1_mean")
    if isinstance(e1_three, (int, float)) and isinstance(e1_six, (int, float)):
        if e1_six < e1_three:
            interpretation.append("Six-site layout increases non-IID pressure: local-only cross-site mean F1 dropped versus three-site.")

    return {
        "three_site_summary": str(three.get("experiment_id")),
        "six_site_summary": str(six.get("experiment_id")),
        "three_site_count": three.get("site_count"),
        "six_site_count": six.get("site_count"),
        "shared_seed": three.get("seed"),
        "shared_rounds": three.get("rounds"),
        "shared_trees_per_site": three.get("trees_per_site_per_round"),
        "comparison_rows": rows,
        "round_curve": round_curve,
        "per_site_e1_macro_f1": per_site_e1,
        "interpretation": interpretation,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# FL 三站 vs 六站對照",
        "",
        f"- 三站：`{report['three_site_summary']}`（{report['three_site_count']} sites）",
        f"- 六站：`{report['six_site_summary']}`（{report['six_site_count']} sites）",
        f"- 共用 seed：`{report.get('shared_seed')}`；rounds：`{report.get('shared_rounds')}`；每站每輪加樹：`{report.get('shared_trees_per_site')}`",
        "",
        "## 主要指標",
        "",
        "| 指標 | 三站 | 六站 | Δ(六-三) |",
        "|---|---:|---:|---:|",
    ]
    for row in report["comparison_rows"]:
        delta = row["delta_six_minus_three"]
        delta_text = "" if delta is None else f"{delta:+.6f}"
        lines.append(
            f"| {row['metric']} | {row['three_site']} | {row['six_site']} | {delta_text} |"
        )
    lines.extend(["", "## 每輪 macro-F1", "", "| Round | 三站 | 六站 | Δ |", "|---|---:|---:|---:|"])
    for row in report["round_curve"]:
        lines.append(
            f"| {row['round']} | {row['three_macro_f1']} | {row['six_macro_f1']} | {row['delta']:+.6f} |"
        )
    lines.extend(["", "## 解讀", ""])
    for item in report["interpretation"]:
        lines.append(f"- {item}")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--three-summary",
        type=Path,
        default=ROOT / "artifacts" / "fl-experiment-three" / "summary.json",
    )
    parser.add_argument(
        "--six-summary",
        type=Path,
        default=ROOT / "artifacts" / "fl-experiment-six" / "summary.json",
    )
    parser.add_argument(
        "--output-json",
        type=Path,
        default=ROOT / "artifacts" / "fl-experiment-comparison" / "three-vs-six.json",
    )
    parser.add_argument(
        "--output-md",
        type=Path,
        default=ROOT / "artifacts" / "fl-experiment-comparison" / "three-vs-six.md",
    )
    args = parser.parse_args()

    report = build_comparison(_load(args.three_summary), _load(args.six_summary))
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    args.output_md.write_text(render_markdown(report), encoding="utf-8")
    print(json.dumps(report["comparison_rows"], ensure_ascii=False, indent=2))
    print(f"Wrote {args.output_json}")
    print(f"Wrote {args.output_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
