"""Plot six-site XGBoost FL accuracy by federation round (one line per site)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

plt.rcParams["font.sans-serif"] = ["Microsoft JhengHei", "SimHei", "DejaVu Sans"]
plt.rcParams["axes.unicode_minus"] = False

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_EXPERIMENT = ROOT / "artifacts" / "fl-experiment-six"
DEFAULT_DOCS = Path(
    r"D:\實習\SenseLControlPlane-feat-i1-integration\SenseLControlPlane-feat-i1-integration"
    r"\docs\experiments\figures"
)

SITE_ORDER = (
    "site-camera",
    "site-pager",
    "site-bpm",
    "site-recon",
    "site-spoof",
    "site-baby-sensor",
)

SITE_LABELS: dict[str, str] = {
    "site-camera": "Camera (DoS)",
    "site-pager": "Pager (DDoS)",
    "site-bpm": "BPM (MQTT-DOS)",
    "site-recon": "Recon",
    "site-spoof": "Spoof (ARP)",
    "site-baby-sensor": "Baby Sensor (MQTT)",
}

SITE_COLORS: dict[str, str] = {
    "site-camera": "#1f77b4",
    "site-pager": "#ff7f0e",
    "site-bpm": "#2ca02c",
    "site-recon": "#d62728",
    "site-spoof": "#9467bd",
    "site-baby-sensor": "#8c564b",
}


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def collect_per_site_accuracy(experiment_dir: Path) -> tuple[list[int], dict[str, list[float]]]:
    summary = read_json(experiment_dir / "summary.json")
    discovered = set(summary.get("site_ids") or [])
    if not discovered:
        discovered = set((summary.get("round0") or {}).get("per_site") or {})
    site_ids = [site_id for site_id in SITE_ORDER if site_id in discovered]
    if not site_ids:
        site_ids = sorted(discovered)

    rounds = [0]
    series: dict[str, list[float]] = {site_id: [] for site_id in site_ids}

    round0 = summary["round0"]["per_site"]
    for site_id in site_ids:
        series[site_id].append(float(round0[site_id]["accuracy"]) * 100.0)

    for round_number in range(1, 6):
        metrics_path = experiment_dir / "rounds" / f"round-{round_number:03d}" / "metrics.json"
        payload = read_json(metrics_path)
        per_site = payload["metrics"]["per_site"]
        rounds.append(round_number)
        for site_id in site_ids:
            series[site_id].append(float(per_site[site_id]["accuracy"]) * 100.0)

    return rounds, series


def plot_accuracy(rounds: list[int], series: dict[str, list[float]], output_path: Path) -> None:
    fig, ax = plt.subplots(figsize=(9.0, 5.2))
    for site_id, values in series.items():
        label = SITE_LABELS.get(site_id, site_id)
        color = SITE_COLORS.get(site_id)
        ax.plot(
            rounds,
            values,
            marker="o",
            linewidth=2.0,
            markersize=6,
            label=label,
            color=color,
        )

    ax.set_title("六站 XGBoost 聯邦學習：各設備準確度 vs 聚合輪次", fontsize=13)
    ax.set_xlabel("聚合輪次 (Round)", fontsize=11)
    ax.set_ylabel("準確度 Accuracy (%)", fontsize=11)
    ax.set_xticks(rounds)
    ax.set_xticklabels(["R0 (起點)"] + [f"R{n}" for n in rounds[1:]])
    ax.set_ylim(0, 105)
    ax.grid(alpha=0.3, linestyle="--")
    ax.legend(loc="lower left", fontsize=9, framealpha=0.92)
    fig.tight_layout()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output_path, dpi=160, bbox_inches="tight")
    plt.close(fig)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--experiment-dir",
        type=Path,
        default=DEFAULT_EXPERIMENT,
        help="Six-site FL artifact directory",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="PNG output path (default: experiment-dir/figures/six-site-accuracy-by-round.png)",
    )
    parser.add_argument(
        "--docs-output",
        type=Path,
        default=DEFAULT_DOCS / "six-site-xgb-accuracy-by-round.png",
        help="Optional copy for controlplane docs/figures",
    )
    args = parser.parse_args()

    output = args.output or (args.experiment_dir / "figures" / "six-site-accuracy-by-round.png")
    rounds, series = collect_per_site_accuracy(args.experiment_dir)
    plot_accuracy(rounds, series, output)

    if args.docs_output:
        plot_accuracy(rounds, series, args.docs_output)

    manifest = {
        "experiment_dir": str(args.experiment_dir),
        "rounds": rounds,
        "accuracy_percent_by_site": {
            SITE_LABELS.get(site_id, site_id): values for site_id, values in series.items()
        },
        "charts": [str(output), str(args.docs_output) if args.docs_output else None],
    }
    manifest_path = output.parent / "six-site-accuracy-manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
