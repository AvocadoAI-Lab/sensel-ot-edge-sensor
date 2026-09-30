#!/usr/bin/env python3
"""Generate HPT before/after comparison charts for FL experiments."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

plt.rcParams["font.sans-serif"] = ["Microsoft JhengHei", "SimHei", "DejaVu Sans"]
plt.rcParams["axes.unicode_minus"] = False

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_FIGURES = Path(
    r"D:\實習\SenseLControlPlane-feat-i1-integration\SenseLControlPlane-feat-i1-integration"
    r"\docs\experiments\figures"
)

STAGE_COLORS = {
    "baseline": "#94a3b8",
    "xgb_hpo": "#3b82f6",
    "full_hpt": "#16a34a",
    "max_accuracy": "#ea580c",
}
COHORT_LABELS = {"wifi": "WiFi", "mqtt": "MQTT", "network": "Network"}

EXPERIMENTS = {
    "six_cohort": {
        "baseline": ROOT / "artifacts" / "fl-experiment-six-cohort",
        "xgb_hpo": ROOT / "artifacts" / "fl-experiment-six-cohort-hpo",
        "full_hpt": ROOT / "artifacts" / "fl-experiment-six-cohort-hpo-full",
        "max_accuracy": ROOT / "artifacts" / "fl-experiment-six-cohort-max-accuracy",
        "mode": "cohort",
    },
    "three_global": {
        "baseline": ROOT / "artifacts" / "fl-experiment-three",
        "xgb_hpo": ROOT / "artifacts" / "fl-experiment-three-hpo",
        "full_hpt": ROOT / "artifacts" / "fl-experiment-three-hpo-full",
        "mode": "single",
    },
    "three_cohort": {
        "baseline": ROOT / "artifacts" / "fl-experiment-three-cohort",
        "xgb_hpo": ROOT / "artifacts" / "fl-experiment-three-cohort-hpo",
        "full_hpt": ROOT / "artifacts" / "fl-experiment-three-cohort-hpo-full",
        "mode": "cohort",
    },
}


def _load_summary(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _e2_macro_f1(summary: dict[str, Any], mode: str) -> float | None:
    if mode == "cohort":
        return summary.get("E2_cohort_aware_round5_macro_f1")
    return summary.get("E2_round5_macro_f1")


def _e3_cohort_macro_f1(summary: dict[str, Any]) -> float | None:
    return summary.get("E3_cohort_centralized_macro_f1")


def _stage_metrics(exp_key: str, stage: str) -> dict[str, Any]:
    cfg = EXPERIMENTS[exp_key]
    path = cfg[stage] / "summary.json"
    if not path.is_file():
        return {}
    summary = _load_summary(path)
    mode = cfg["mode"]
    out: dict[str, Any] = {"E2": _e2_macro_f1(summary, mode)}
    if mode == "cohort":
        out["E3_cohort"] = _e3_cohort_macro_f1(summary)
        out["cohort_final"] = summary.get("cohort_final_macro_f1") or {}
    else:
        out["E3"] = summary.get("E3_centralized_macro_f1")
    return out


def _cohort_round_curve(experiment_dir: Path, cohort_names: tuple[str, ...]) -> list[float]:
    cohorts_dir = experiment_dir / "cohorts"
    curves: list[list[float]] = []
    for name in cohort_names:
        summary_path = cohorts_dir / f"{name}-summary.json"
        if not summary_path.is_file():
            continue
        payload = _load_summary(summary_path)
        curves.append([float(r["metrics"]["macro_f1"]) for r in payload["rounds"]])
    if not curves:
        return []
    max_len = max(len(c) for c in curves)
    means: list[float] = []
    for idx in range(max_len):
        vals = [c[idx] for c in curves if idx < len(c)]
        means.append(float(np.mean(vals)))
    return means


def _cohort_round_curve_frozen_tail(experiment_dir: Path, cohort_names: tuple[str, ...]) -> list[float]:
    """Average per-cohort FL curves; shorter cohorts freeze at their final round (Max Accuracy)."""
    cohorts_dir = experiment_dir / "cohorts"
    curves: list[list[float]] = []
    for name in cohort_names:
        summary_path = cohorts_dir / f"{name}-summary.json"
        if not summary_path.is_file():
            continue
        payload = _load_summary(summary_path)
        curves.append([float(r["metrics"]["macro_f1"]) for r in payload["rounds"]])
    if not curves:
        return []
    max_len = max(len(c) for c in curves)
    means: list[float] = []
    for idx in range(max_len):
        vals = [c[min(idx, len(c) - 1)] for c in curves]
        means.append(float(np.mean(vals)))
    return means


def _single_global_round_curve(experiment_dir: Path) -> list[float]:
    rounds_dir = experiment_dir / "rounds"
    if not rounds_dir.is_dir():
        return []
    curves: list[float] = []
    for path in sorted(rounds_dir.glob("round-*/metrics.json")):
        payload = _load_summary(path)
        curves.append(float(payload.get("macro_f1") or 0.0))
    return curves


def _plot_six_cohort_stages(out_dir: Path) -> Path:
    base = _stage_metrics("six_cohort", "baseline")
    xgb = _stage_metrics("six_cohort", "xgb_hpo")
    full = _stage_metrics("six_cohort", "full_hpt")
    max_acc = _stage_metrics("six_cohort", "max_accuracy")

    stages = [
        ("Baseline\n(預設 XGB+FL)", "baseline", base["E2"], base.get("E3_cohort")),
        ("Stage-1\n(XGB HPO)", "xgb_hpo", xgb["E2"], xgb.get("E3_cohort")),
        ("Full HPT\n(XGB+FL HPO)", "full_hpt", full["E2"], full.get("E3_cohort")),
        ("Max Accuracy\n(per-cohort HPO)", "max_accuracy", max_acc.get("E2"), max_acc.get("E3_cohort")),
    ]
    x = np.arange(len(stages))
    width = 0.35
    e2 = [float(s[2]) for s in stages]
    e3 = [float(s[3]) for s in stages]
    colors = [STAGE_COLORS[s[1]] for s in stages]

    fig, ax = plt.subplots(figsize=(11, 5.5))
    bars1 = ax.bar(x - width / 2, e2, width, label="E2 cohort FL (macro-F1)", color=colors, edgecolor="white")
    bars2 = ax.bar(x + width / 2, e3, width, label="E3 cohort centralized", color=colors, alpha=0.45, edgecolor="white", hatch="//")

    ax.set_ylabel("macro-F1")
    ax.set_title("六站協定分組 · HPT 前後 macro-F1 對比")
    ax.set_xticks(x)
    ax.set_xticklabels([s[0] for s in stages])
    ax.set_ylim(0.88, 1.0)
    ax.legend(loc="lower right")
    ax.grid(axis="y", alpha=0.3)

    for bar in list(bars1) + list(bars2):
        h = bar.get_height()
        ax.annotate(f"{h:.3f}", xy=(bar.get_x() + bar.get_width() / 2, h),
                    xytext=(0, 4), textcoords="offset points", ha="center", fontsize=9)

    fig.tight_layout()
    out = out_dir / "hpt-six-cohort-macro-f1-stages.png"
    fig.savefig(out, dpi=150)
    plt.close(fig)
    return out


def _plot_cohort_breakdown(out_dir: Path) -> Path:
    cohorts = ("wifi", "mqtt", "network")
    baseline = _stage_metrics("six_cohort", "baseline").get("cohort_final", {})
    xgb_hpo = _stage_metrics("six_cohort", "xgb_hpo").get("cohort_final", {})
    full_hpt = _stage_metrics("six_cohort", "full_hpt").get("cohort_final", {})
    max_acc = _stage_metrics("six_cohort", "max_accuracy").get("cohort_final", {})

    x = np.arange(len(cohorts))
    width = 0.2
    fig, ax = plt.subplots(figsize=(10, 5.5))

    stage_rows = [
        ("Baseline", baseline, "baseline"),
        ("XGB HPO", xgb_hpo, "xgb_hpo"),
        ("Full HPT", full_hpt, "full_hpt"),
        ("Max Acc", max_acc, "max_accuracy"),
    ]
    for offset, (label, data, key) in enumerate(stage_rows):
        vals = [float(data.get(c, 0)) for c in cohorts]
        pos = x + (offset - 1.5) * width
        bars = ax.bar(pos, vals, width, label=label, color=STAGE_COLORS[key], edgecolor="white")
        for bar in bars:
            h = bar.get_height()
            ax.annotate(f"{h:.3f}", xy=(bar.get_x() + bar.get_width() / 2, h),
                        xytext=(0, 3), textcoords="offset points", ha="center", fontsize=8)

    ax.set_ylabel("E2 最終 macro-F1")
    ax.set_title("六站 · 各協定 cohort HPT 前後對比")
    ax.set_xticks(x)
    ax.set_xticklabels([COHORT_LABELS[c] for c in cohorts])
    ax.set_ylim(0.82, 1.02)
    ax.legend()
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    out = out_dir / "hpt-six-cohort-by-protocol.png"
    fig.savefig(out, dpi=150)
    plt.close(fig)
    return out


def _plot_fl_round_curves(out_dir: Path) -> Path:
    hpo_fl = _load_summary(ROOT / "artifacts" / "hpo-fl-params-results.json")
    baseline_curve = _cohort_round_curve(EXPERIMENTS["six_cohort"]["baseline"], ("mqtt", "network", "wifi"))
    xgb_fl_curve = next(
        t["round_macro_f1_means"] for t in hpo_fl["trials"] if t["fl_params"] == hpo_fl["baseline_fl_params"]
    )
    full_curve = hpo_fl["best_metrics"]["round_macro_f1_means"]
    max_acc_curve = _cohort_round_curve_frozen_tail(
        EXPERIMENTS["six_cohort"]["max_accuracy"], ("mqtt", "network", "wifi")
    )

    fig, ax = plt.subplots(figsize=(9, 5.5))
    ax.plot(range(1, len(baseline_curve) + 1), baseline_curve, "o-", color=STAGE_COLORS["baseline"],
            lw=2, label=f"Baseline FL (5×8 equal) → {baseline_curve[-1]:.3f}")
    ax.plot(range(1, len(xgb_fl_curve) + 1), xgb_fl_curve, "s-", color=STAGE_COLORS["xgb_hpo"],
            lw=2, label=f"XGB HPO + 預設 FL → {xgb_fl_curve[-1]:.3f}")
    ax.plot(range(1, len(full_curve) + 1), full_curve, "^-", color=STAGE_COLORS["full_hpt"],
            lw=2, label=f"Full HPT (7×12 sample) → {full_curve[-1]:.3f}")
    ax.plot(range(1, len(max_acc_curve) + 1), max_acc_curve, "D-", color=STAGE_COLORS["max_accuracy"],
            lw=2, label=f"Max Accuracy (per-cohort) → {max_acc_curve[-1]:.3f}")

    ax.set_xlabel("FL Round")
    ax.set_ylabel("跨 cohort 平均 macro-F1")
    ax.set_title("六站 cohort FL · 逐輪收斂曲線（HPT 前後）")
    max_rounds = max(len(full_curve), len(baseline_curve), len(max_acc_curve))
    ax.set_xticks(range(1, max_rounds + 1))
    ax.set_ylim(0.88, 0.96)
    ax.legend(loc="lower right", fontsize=8)
    ax.grid(alpha=0.3)
    fig.tight_layout()
    out = out_dir / "hpt-six-cohort-fl-rounds.png"
    fig.savefig(out, dpi=150)
    plt.close(fig)
    return out


def _plot_all_experiments(out_dir: Path) -> Path:
    rows = [
        ("六站 cohort E2", "six_cohort", "E2"),
        ("六站 E3 cohort", "six_cohort", "E3_cohort"),
        ("三站 global E2", "three_global", "E2"),
        ("三站 cohort E2", "three_cohort", "E2"),
    ]
    labels = [r[0] for r in rows]
    x = np.arange(len(labels))
    width = 0.2

    fig, ax = plt.subplots(figsize=(11, 5.5))
    stage_keys = [
        ("Baseline", "baseline"),
        ("XGB HPO", "xgb_hpo"),
        ("Full HPT", "full_hpt"),
        ("Max Acc", "max_accuracy"),
    ]
    for offset, (name, key) in enumerate(stage_keys):
        plot_x, plot_h = [], []
        for xi, (label, exp_key, metric_key) in enumerate(rows):
            if key == "max_accuracy" and exp_key != "six_cohort":
                continue
            metrics = _stage_metrics(exp_key, key)
            value = metrics.get(metric_key)
            if value is not None:
                plot_x.append(xi + (offset - 1.5) * width)
                plot_h.append(float(value))
        bars = ax.bar(plot_x, plot_h, width, label=name, color=STAGE_COLORS[key], edgecolor="white")
        for bar in bars:
            h = bar.get_height()
            ax.annotate(f"{h:.3f}", xy=(bar.get_x() + bar.get_width() / 2, h),
                        xytext=(0, 3), textcoords="offset points", ha="center", fontsize=8)

    ax.set_ylabel("macro-F1")
    ax.set_title("全部實驗 · HPT 前後 macro-F1 總覽")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=9)
    ax.set_ylim(0.92, 1.0)
    ax.legend()
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    out = out_dir / "hpt-all-experiments-overview.png"
    fig.savefig(out, dpi=150)
    plt.close(fig)
    return out


def _plot_three_site_stages(out_dir: Path) -> Path:
    fig, axes = plt.subplots(1, 2, figsize=(12, 5.5))
    panels = [
        ("三站 · 單一 global E2", "three_global", "E2"),
        ("三站 · 協定分組 E2", "three_cohort", "E2"),
    ]
    width = 0.25
    for ax, (title, exp_key, metric_key) in zip(axes, panels):
        stages = ["Baseline", "XGB HPO", "Full HPT"]
        keys = ["baseline", "xgb_hpo", "full_hpt"]
        vals = [float(_stage_metrics(exp_key, k).get(metric_key) or 0) for k in keys]
        colors = [STAGE_COLORS[k] for k in keys]
        bars = ax.bar(stages, vals, color=colors, edgecolor="white", width=0.55)
        ax.set_title(title)
        ax.set_ylabel("macro-F1")
        ax.set_ylim(0.96, 1.0)
        ax.grid(axis="y", alpha=0.3)
        for bar in bars:
            h = bar.get_height()
            ax.annotate(f"{h:.3f}", xy=(bar.get_x() + bar.get_width() / 2, h),
                        xytext=(0, 4), textcoords="offset points", ha="center", fontsize=10)
    fig.suptitle("三站 · Full HPT 前後對比（18 組 FL grid × Stage-1 XGB）", fontsize=12)
    fig.tight_layout()
    out = out_dir / "hpt-three-site-stages.png"
    fig.savefig(out, dpi=150)
    plt.close(fig)
    return out


def _plot_xgb_validation(out_dir: Path) -> Path:
    hpo = _load_summary(ROOT / "artifacts" / "hpo-macro-f1-results.json")
    baseline = float(hpo["baseline_default_validation"]["macro_f1"])
    best = float(hpo["best_validation"]["macro_f1"])

    fig, ax = plt.subplots(figsize=(6, 4.5))
    bars = ax.bar(["Baseline XGB\n(validation)", "Stage-1 XGB HPO\n(validation)"],
                  [baseline, best], color=[STAGE_COLORS["baseline"], STAGE_COLORS["xgb_hpo"]],
                  edgecolor="white", width=0.5)
    ax.set_ylim(0.99, 1.001)
    ax.set_ylabel("macro-F1")
    ax.set_title("Stage-1 · XGB validation macro-F1")
    for bar in bars:
        h = bar.get_height()
        ax.annotate(f"{h:.4f}", xy=(bar.get_x() + bar.get_width() / 2, h),
                    xytext=(0, 4), textcoords="offset points", ha="center")
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    out = out_dir / "hpt-xgb-validation.png"
    fig.savefig(out, dpi=150)
    plt.close(fig)
    return out


def main() -> None:
    out_dir = DEFAULT_FIGURES
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = [
        _plot_six_cohort_stages(out_dir),
        _plot_cohort_breakdown(out_dir),
        _plot_fl_round_curves(out_dir),
        _plot_all_experiments(out_dir),
        _plot_three_site_stages(out_dir),
        _plot_xgb_validation(out_dir),
    ]
    manifest = out_dir / "hpt-comparison-manifest.json"
    manifest.write_text(
        json.dumps({"figures": [str(p) for p in paths]}, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"figures": [str(p.name) for p in paths]}, indent=2))


if __name__ == "__main__":
    main()
