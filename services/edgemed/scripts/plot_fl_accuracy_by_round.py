"""Plot per-site accuracy: E1 · E2 R0–R5 · E3 (+ E3 cohort when available)."""

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
DEFAULT_DOCS = Path(
    r"D:\實習\SenseLControlPlane-feat-i1-integration\SenseLControlPlane-feat-i1-integration"
    r"\docs\experiments\figures"
)

THREE_SITE_ORDER = ("site-camera", "site-pager", "site-bpm")
SIX_SITE_ORDER = (
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
    "site-bpm": "BPM (MQTT)",
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

COHORT_LINESTYLE: dict[str, str] = {
    "wifi": "-",
    "mqtt": "--",
    "network": "-.",
}

PRESETS: dict[str, dict[str, Any]] = {
    "three-single": {
        "experiment_dir": ROOT / "artifacts" / "fl-experiment-three",
        "mode": "single",
        "site_order": THREE_SITE_ORDER,
        "title": "三站 · 單一 global：各設備 Accuracy（E1 → E2 R0–R5 → E3）",
        "output_name": "three-site-xgb-accuracy-by-round.png",
    },
    "six-single": {
        "experiment_dir": ROOT / "artifacts" / "fl-experiment-six",
        "mode": "single",
        "site_order": SIX_SITE_ORDER,
        "title": "六站 · 單一 global：各設備 Accuracy（E1 → E2 R0–R5 → E3）",
        "output_name": "six-site-xgb-accuracy-by-round.png",
    },
    "three-cohort": {
        "experiment_dir": ROOT / "artifacts" / "fl-experiment-three-cohort",
        "mode": "cohort",
        "site_order": THREE_SITE_ORDER,
        "title": "三站 · 協定分組：各設備 Accuracy（E1 → E2 R0–R5 → E3 → E3協定）",
        "output_name": "three-site-cohort-xgb-accuracy-by-round.png",
    },
    "six-cohort": {
        "experiment_dir": ROOT / "artifacts" / "fl-experiment-six-cohort",
        "mode": "cohort",
        "site_order": SIX_SITE_ORDER,
        "title": "六站 · 協定分組：各設備 Accuracy（E1 → E2 R0–R5 → E3 → E3協定）",
        "output_name": "six-site-cohort-xgb-accuracy-by-round.png",
    },
}


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _resolve_site_ids(summary: dict[str, Any], site_order: tuple[str, ...]) -> list[str]:
    discovered = set(summary.get("site_ids") or [])
    if not discovered:
        discovered = set((summary.get("round0") or {}).get("per_site") or {})
    site_ids = [site_id for site_id in site_order if site_id in discovered]
    return site_ids or sorted(discovered)


def _e2_single_series(
    experiment_dir: Path,
    site_ids: list[str],
) -> dict[str, list[float]]:
    summary = read_json(experiment_dir / "summary.json")
    series: dict[str, list[float]] = {site_id: [] for site_id in site_ids}
    round0 = summary["round0"]["per_site"]
    for site_id in site_ids:
        series[site_id].append(float(round0[site_id]["accuracy"]) * 100.0)
    round_count = int(summary.get("rounds") or 5)
    for round_number in range(1, round_count + 1):
        payload = read_json(experiment_dir / "rounds" / f"round-{round_number:03d}" / "metrics.json")
        per_site = payload["metrics"]["per_site"]
        for site_id in site_ids:
            series[site_id].append(float(per_site[site_id]["accuracy"]) * 100.0)
    return series


def _e2_cohort_series(
    experiment_dir: Path,
    site_ids: list[str],
    site_cohort_map: dict[str, str],
) -> dict[str, list[float]]:
    cohort_summaries: dict[str, dict[str, Any]] = {}
    for path in sorted((experiment_dir / "cohorts").glob("*-summary.json")):
        if path.name == "final-cohort-metrics.json":
            continue
        cohort_summaries[path.stem.replace("-summary", "")] = read_json(path)
    round0 = read_json(experiment_dir / "baselines" / "round-0-trained-eval.json")["per_site"]
    series: dict[str, list[float]] = {site_id: [] for site_id in site_ids}
    for site_id in site_ids:
        series[site_id].append(float(round0[site_id]["accuracy"]) * 100.0)
    round_count = int(read_json(experiment_dir / "summary.json").get("rounds") or 5)
    for round_number in range(1, round_count + 1):
        for site_id in site_ids:
            cohort = site_cohort_map[site_id]
            per_site = cohort_summaries[cohort]["rounds"][round_number - 1]["metrics"]["per_site"]
            series[site_id].append(float(per_site[site_id]["accuracy"]) * 100.0)
    return series


def collect_full_series(
    experiment_dir: Path,
    site_order: tuple[str, ...],
    mode: str,
) -> tuple[list[str], dict[str, list[float]], dict[str, str], list[str]]:
    summary = read_json(experiment_dir / "summary.json")
    site_ids = _resolve_site_ids(summary, site_order)
    site_cohort_map = summary.get("site_cohort_map") or {site_id: "single" for site_id in site_ids}

    e1_data = read_json(experiment_dir / "baselines" / "local-only-metrics.json")
    e3_data = read_json(experiment_dir / "baselines" / "centralized-oracle-metrics.json")
    e3c_path = experiment_dir / "baselines" / "centralized-cohort-oracle-metrics.json"
    e3c_data = read_json(e3c_path) if e3c_path.is_file() else None

    if mode == "single":
        e2 = _e2_single_series(experiment_dir, site_ids)
    elif mode == "cohort":
        e2 = _e2_cohort_series(experiment_dir, site_ids, site_cohort_map)
    else:
        raise ValueError(f"unknown mode: {mode}")

    x_labels = ["E1", "R0", "R1", "R2", "R3", "R4", "R5", "E3"]
    phase_labels = ["E1 local-only", "E2 聯邦學習 R0–R5", "E3 centralized"]
    if e3c_data is not None:
        x_labels.append("E3協定")
        phase_labels.append("E3 協定分組 centralized")

    series: dict[str, list[float]] = {}
    for site_id in site_ids:
        values = [
            float(e1_data["per_local_model"][site_id]["per_site"][site_id]["accuracy"]) * 100.0,
            *e2[site_id],
            float(e3_data["per_site"][site_id]["accuracy"]) * 100.0,
        ]
        if e3c_data is not None:
            values.append(float(e3c_data["per_site"][site_id]["accuracy"]) * 100.0)
        series[site_id] = values

    cohort_map = {
        site_id: site_cohort_map.get(site_id, "single") for site_id in site_ids
    }
    return x_labels, series, cohort_map, phase_labels


def plot_full_accuracy(
    *,
    x_labels: list[str],
    series: dict[str, list[float]],
    cohort_map: dict[str, str],
    title: str,
    output_path: Path,
    mode: str,
    phase_labels: list[str],
) -> None:
    x_pos = list(range(len(x_labels)))
    fig, ax = plt.subplots(figsize=(12.0, 5.6))

    for site_id, values in series.items():
        label = SITE_LABELS.get(site_id, site_id)
        color = SITE_COLORS.get(site_id)
        linestyle = COHORT_LINESTYLE.get(cohort_map.get(site_id, ""), "-") if mode == "cohort" else "-"
        ax.plot(
            x_pos,
            values,
            marker="o",
            linewidth=2.0,
            markersize=5,
            label=label,
            color=color,
            linestyle=linestyle,
            zorder=2,
        )
        if len(values) >= 1:
            ax.scatter(x_pos[0], values[0], marker="s", s=52, color=color, zorder=3, edgecolors="white", linewidths=0.6)
        if len(values) >= 8:
            ax.scatter(x_pos[7], values[7], marker="D", s=52, color=color, zorder=3, edgecolors="white", linewidths=0.6)
        if len(values) >= 9:
            ax.scatter(x_pos[8], values[8], marker="^", s=58, color=color, zorder=3, edgecolors="white", linewidths=0.6)

    ax.axvline(0.5, color="#bbbbbb", linestyle=":", linewidth=1.2, zorder=1)
    ax.axvline(6.5, color="#bbbbbb", linestyle=":", linewidth=1.2, zorder=1)
    if len(x_labels) >= 9:
        ax.axvline(7.5, color="#bbbbbb", linestyle=":", linewidth=1.2, zorder=1)

    ax.set_title(title, fontsize=13)
    ax.set_xlabel("實驗階段（與 MD 表格欄位一致）", fontsize=11)
    ax.set_ylabel("準確度 Accuracy (%)", fontsize=11)
    ax.set_xticks(x_pos)
    ax.set_xticklabels(x_labels, fontsize=9)
    ax.set_ylim(0, 105)
    ax.grid(alpha=0.28, linestyle="--", zorder=0)
    ax.legend(loc="lower left", fontsize=8, framealpha=0.92, ncol=2 if len(series) > 4 else 1)

    note = "標記：■ E1 local  ◆ E3 單一"
    if len(x_labels) >= 9:
        note += "  ▲ E3 協定"
    if mode == "cohort":
        note += "  |  線型：WiFi 實線 / MQTT 虛線 / Network 點劃線"
    ax.text(
        0.99,
        0.02,
        note,
        transform=ax.transAxes,
        ha="right",
        va="bottom",
        fontsize=7.5,
        color="#444444",
    )
    fig.tight_layout()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output_path, dpi=160, bbox_inches="tight")
    plt.close(fig)


def generate_chart(
    *,
    experiment_dir: Path,
    mode: str,
    site_order: tuple[str, ...],
    title: str,
    output_path: Path,
) -> dict[str, Any]:
    x_labels, series, cohort_map, phase_labels = collect_full_series(
        experiment_dir, site_order, mode
    )
    plot_full_accuracy(
        x_labels=x_labels,
        series=series,
        cohort_map=cohort_map,
        title=title,
        output_path=output_path,
        mode=mode,
        phase_labels=phase_labels,
    )
    return {
        "experiment_dir": str(experiment_dir),
        "mode": mode,
        "output": str(output_path),
        "x_labels": x_labels,
        "accuracy_percent_by_site": {
            SITE_LABELS.get(site_id, site_id): dict(zip(x_labels, values))
            for site_id, values in series.items()
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--preset", choices=sorted(PRESETS))
    parser.add_argument("--all-presets", action="store_true")
    parser.add_argument("--experiment-dir", type=Path)
    parser.add_argument("--mode", choices=("single", "cohort"))
    parser.add_argument("--title", type=str, default="")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--docs-output", type=Path, default=None)
    args = parser.parse_args()

    manifests: list[dict[str, Any]] = []

    if args.all_presets:
        for preset_name, preset in PRESETS.items():
            docs_output = DEFAULT_DOCS / preset["output_name"]
            artifact_output = preset["experiment_dir"] / "figures" / preset["output_name"]
            manifest = generate_chart(
                experiment_dir=preset["experiment_dir"],
                mode=preset["mode"],
                site_order=tuple(preset["site_order"]),
                title=preset["title"],
                output_path=artifact_output,
            )
            generate_chart(
                experiment_dir=preset["experiment_dir"],
                mode=preset["mode"],
                site_order=tuple(preset["site_order"]),
                title=preset["title"],
                output_path=docs_output,
            )
            manifest["preset"] = preset_name
            manifest["docs_output"] = str(docs_output)
            manifests.append(manifest)
            print(f"[{preset_name}] wrote {docs_output}", flush=True)

        manifest_path = DEFAULT_DOCS / "fl-accuracy-charts-manifest.json"
        manifest_path.write_text(
            json.dumps({"charts": manifests}, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        print(f"Wrote {manifest_path}", flush=True)
        return 0

    if args.preset:
        preset = PRESETS[args.preset]
        output = args.output or (DEFAULT_DOCS / preset["output_name"])
        manifest = generate_chart(
            experiment_dir=preset["experiment_dir"],
            mode=preset["mode"],
            site_order=tuple(preset["site_order"]),
            title=preset["title"],
            output_path=output,
        )
        print(json.dumps(manifest, ensure_ascii=False, indent=2))
        return 0

    if not args.experiment_dir or not args.mode or not args.output:
        parser.error("Provide --preset, --all-presets, or (--experiment-dir, --mode, --output)")

    site_order = THREE_SITE_ORDER if "three" in args.experiment_dir.name else SIX_SITE_ORDER
    manifest = generate_chart(
        experiment_dir=args.experiment_dir,
        mode=args.mode,
        site_order=site_order,
        title=args.title or "FL accuracy timeline",
        output_path=args.output,
    )
    if args.docs_output:
        generate_chart(
            experiment_dir=args.experiment_dir,
            mode=args.mode,
            site_order=site_order,
            title=args.title or "FL accuracy timeline",
            output_path=args.docs_output,
        )
    print(json.dumps(manifest, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
