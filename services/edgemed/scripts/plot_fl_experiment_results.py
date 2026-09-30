"""Generate reproducible charts from FL and system-validation JSON artifacts."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

ROOT = Path(__file__).resolve().parents[1]


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def save(fig: Any, output: Path) -> None:
    fig.tight_layout()
    fig.savefig(output, dpi=180, bbox_inches="tight")
    plt.close(fig)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--experiment-dir",
        type=Path,
        default=ROOT / "artifacts" / "fl-experiment",
    )
    parser.add_argument("--system-validation", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)

    summary = read_json(args.experiment_dir / "summary.json")
    repeated = read_json(args.experiment_dir / "repetition-summary.json")
    rounds = [
        read_json(args.experiment_dir / "rounds" / f"round-{number:03d}" / "metrics.json")
        for number in range(1, 6)
    ]
    system = read_json(args.system_validation)

    fig, ax = plt.subplots(figsize=(7.2, 4.2))
    x = np.arange(1, 6)
    means = [repeated["rounds"][str(number)]["mean"] for number in x]
    deviations = [
        repeated["rounds"][str(number)]["sample_standard_deviation"]
        for number in x
    ]
    ax.errorbar(x, means, yerr=deviations, marker="o", capsize=4, label="E2 mean ± sample SD")
    ax.axhline(
        repeated["metrics"]["E0_round0_macro_f1"]["mean"],
        linestyle="--",
        label="E0 federation-compatible",
    )
    ax.axhline(
        repeated["metrics"]["E3_centralized_macro_f1"]["mean"],
        linestyle=":",
        label="E3 centralized oracle",
    )
    ax.set(title="Federated proxy performance by communication round", xlabel="Round", ylabel="Mean per-site Attack F1")
    ax.set_xticks(x)
    ax.set_ylim(0.90, 0.99)
    ax.grid(alpha=0.25)
    ax.legend()
    save(fig, args.output_dir / "round-performance.png")

    names = ["E0", "E1 local", "E2 R5", "E3"]
    keys = [
        "E0_round0_macro_f1",
        "E1_local_cross_site_macro_f1_mean",
        "E2_round5_macro_f1",
        "E3_centralized_macro_f1",
    ]
    values = [repeated["metrics"][key]["mean"] for key in keys]
    errors = [repeated["metrics"][key]["sample_standard_deviation"] for key in keys]
    fig, ax = plt.subplots(figsize=(7.2, 4.2))
    bars = ax.bar(names, values, yerr=errors, capsize=4)
    ax.bar_label(bars, fmt="%.3f", padding=3)
    ax.set(title="E0–E3 three-run comparison", xlabel="Experiment condition", ylabel="Mean per-site Attack F1")
    ax.set_ylim(0.78, 1.0)
    ax.grid(axis="y", alpha=0.25)
    save(fig, args.output_dir / "baseline-comparison.png")

    curve_models = {
        "E0": summary["round0"]["global_holdout"],
        "E2 Round 5": rounds[-1]["metrics"]["global_holdout"],
        "E3": summary["centralized"]["global_holdout"],
    }
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.4))
    for name, metrics in curve_models.items():
        axes[0].plot(
            metrics["roc_curve"]["fpr"],
            metrics["roc_curve"]["tpr"],
            label=f"{name} (AUC={metrics['roc_auc']:.3f})",
        )
        axes[1].plot(
            metrics["pr_curve"]["recall"],
            metrics["pr_curve"]["precision"],
            label=f"{name} (AP={metrics['pr_auc']:.3f})",
        )
    axes[0].plot([0, 1], [0, 1], linestyle="--", color="gray")
    axes[0].set(title="Global holdout ROC curves", xlabel="False positive rate", ylabel="True positive rate")
    axes[1].set(title="Global holdout precision–recall curves", xlabel="Recall", ylabel="Precision")
    for ax in axes:
        ax.grid(alpha=0.25)
        ax.legend()
    save(fig, args.output_dir / "global-roc-pr.png")

    update_bytes = [
        sum(item["update_bytes"] for item in payload["local_updates"].values())
        for payload in rounds
    ]
    model_bytes = [payload["artifact_bytes"] for payload in rounds]
    fig, ax = plt.subplots(figsize=(7.2, 4.2))
    ax.plot(x, np.asarray(update_bytes) / 1024, marker="o", label="Uploaded tree updates")
    ax.plot(x, np.asarray(model_bytes) / 1024, marker="s", label="Aggregate model artifact")
    ax.set(title="Communication payload and model growth", xlabel="Round", ylabel="Size (KiB)")
    ax.set_xticks(x)
    ax.grid(alpha=0.25)
    ax.legend()
    save(fig, args.output_dir / "communication-cost.png")

    site_names = ["Camera", "Pager", "BPM"]
    matrices = [
        rounds[-1]["metrics"]["per_site"][site]["confusion_matrix"]
        for site in ("site-camera", "site-pager", "site-bpm")
    ]
    fig, axes = plt.subplots(1, 3, figsize=(10.5, 3.5))
    for ax, site_name, matrix in zip(axes, site_names, matrices):
        values = np.asarray(
            [[matrix["tn"], matrix["fp"]], [matrix["fn"], matrix["tp"]]]
        )
        image = ax.imshow(values, cmap="Blues")
        for row in range(2):
            for column in range(2):
                ax.text(column, row, f"{values[row, column]:,}", ha="center", va="center")
        ax.set(
            title=f"{site_name} Round 5",
            xlabel="Predicted class",
            ylabel="True class",
            xticks=[0, 1],
            yticks=[0, 1],
            xticklabels=["Benign", "Attack"],
            yticklabels=["Benign", "Attack"],
        )
        fig.colorbar(image, ax=ax, fraction=0.046, pad=0.04)
    save(fig, args.output_dir / "round5-confusion-matrices.png")

    probes = [
        ("Control Plane", system["control_plane_ready"]),
        ("Console", system["console_health"]),
        ("Pi health", system["pi_edgemed_health"]),
        ("Pi inference", system["pi_inference"]),
    ]
    labels = [name for name, _ in probes]
    means = [probe["latency_ms"]["mean"] for _, probe in probes]
    p95 = [probe["latency_ms"]["p95"] for _, probe in probes]
    positions = np.arange(len(labels))
    width = 0.36
    fig, ax = plt.subplots(figsize=(8, 4.2))
    ax.bar(positions - width / 2, means, width, label="Mean")
    ax.bar(positions + width / 2, p95, width, label="p95")
    ax.set(
        title="Short lab service latency benchmark",
        xlabel="Probe",
        ylabel="Latency (ms, log scale)",
        xticks=positions,
        xticklabels=labels,
    )
    ax.set_yscale("log")
    ax.grid(axis="y", alpha=0.25)
    ax.legend()
    save(fig, args.output_dir / "system-latency.png")

    manifest = {
        "source": {
            "experiment_summary": str(args.experiment_dir / "summary.json"),
            "repetition_summary": str(args.experiment_dir / "repetition-summary.json"),
            "system_validation": str(args.system_validation),
        },
        "charts": sorted(path.name for path in args.output_dir.glob("*.png")),
    }
    (args.output_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(manifest, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
