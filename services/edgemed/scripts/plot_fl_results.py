#!/usr/bin/env python3
"""Render ROC/PR, round curves and communication-cost charts from experiment JSON."""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt


ROOT = Path(__file__).resolve().parents[1]
SUMMARY = ROOT / "artifacts" / "fl-experiment" / "summary.json"
REPEATS = ROOT / "artifacts" / "fl-experiment" / "repetition-summary.json"
OUT = ROOT / "artifacts" / "fl-experiment" / "figures"
DOCS = Path(
    r"D:\實習\SenseLControlPlane-feat-i1-integration\SenseLControlPlane-feat-i1-integration"
    r"\docs\experiments\figures"
)


def _save(fig: plt.Figure, name: str) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    DOCS.mkdir(parents=True, exist_ok=True)
    for directory in (OUT, DOCS):
        fig.savefig(directory / name, dpi=140, bbox_inches="tight")
    plt.close(fig)


def main() -> int:
    summary = json.loads(SUMMARY.read_text(encoding="utf-8"))
    holdout = summary["round0"]["global_holdout"]
    if "roc_curve" in holdout:
        fig, ax = plt.subplots(figsize=(5.2, 4.2))
        ax.plot(holdout["roc_curve"]["fpr"], holdout["roc_curve"]["tpr"], label=f"E0 AUC={holdout.get('roc_auc'):.3f}")
        e2 = json.loads((ROOT / "artifacts/fl-experiment/rounds/round-005/metrics.json").read_text(encoding="utf-8"))
        curve = e2["metrics"]["global_holdout"].get("roc_curve")
        if curve:
            ax.plot(curve["fpr"], curve["tpr"], label=f"E2 R5 AUC={e2['metrics']['global_holdout'].get('roc_auc'):.3f}")
        ax.plot([0, 1], [0, 1], "--", color="gray")
        ax.set_xlabel("False positive rate")
        ax.set_ylabel("True positive rate")
        ax.set_title("Global holdout ROC")
        ax.legend()
        _save(fig, "roc-holdout.png")
    if "pr_curve" in holdout:
        fig, ax = plt.subplots(figsize=(5.2, 4.2))
        ax.plot(holdout["pr_curve"]["recall"], holdout["pr_curve"]["precision"], label=f"E0 PR-AUC={holdout.get('pr_auc'):.3f}")
        e2 = json.loads((ROOT / "artifacts/fl-experiment/rounds/round-005/metrics.json").read_text(encoding="utf-8"))
        curve = e2["metrics"]["global_holdout"].get("pr_curve")
        if curve:
            ax.plot(curve["recall"], curve["precision"], label=f"E2 R5 PR-AUC={e2['metrics']['global_holdout'].get('pr_auc'):.3f}")
        ax.set_xlabel("Recall")
        ax.set_ylabel("Precision")
        ax.set_title("Global holdout PR")
        ax.legend()
        _save(fig, "pr-holdout.png")

    fig, ax = plt.subplots(figsize=(6.2, 4.0))
    rounds = [item["round"] for item in summary["federated_rounds"]]
    f1s = [item["macro_f1"] for item in summary["federated_rounds"]]
    ax.plot(rounds, f1s, marker="o", label="official seed")
    if REPEATS.is_file():
        repeats = json.loads(REPEATS.read_text(encoding="utf-8"))
        means = [repeats["rounds"][str(n)]["mean"] for n in rounds]
        ax.plot(rounds, means, marker="s", label="3-seed mean")
    ax.set_xlabel("Federation round")
    ax.set_ylabel("Cross-site Attack F1")
    ax.set_title("Round versus performance")
    ax.legend()
    _save(fig, "round-versus-f1.png")

    fig, ax = plt.subplots(figsize=(6.2, 4.0))
    bytes_ = [item.get("update_bytes") or 0 for item in summary["federated_rounds"]]
    ax.bar(rounds, bytes_)
    ax.set_xlabel("Federation round")
    ax.set_ylabel("Uploaded tree-update bytes")
    ax.set_title("Communication cost")
    _save(fig, "communication-cost.png")
    print(f"Wrote figures under {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
