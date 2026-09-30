"""Build frozen CIC site manifests for the federated XGBoost experiment."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.fl_protocol_cohorts import cohort_index, resolve_fl_protocol_group

THREE_SITES = (
    {
        "site_id": "site-camera",
        "device_type": "medical_camera",
        "fl_protocol_group": "wifi",
        "attack_family": "dos",
        "baseline_template": "cic-template-medical-camera-v1",
        "benign": {"kind": "profiling", "file": "Blink_Camera_LAN_WATCH.pcap.csv"},
        "exclude_prefixes": ["MQTT"],
        "include_mqtt_prefix": False,
    },
    {
        "site_id": "site-pager",
        "device_type": "medical_pager",
        "fl_protocol_group": "wifi",
        "attack_family": "ddos",
        "baseline_template": "cic-template-medical-pager-v1",
        "benign": {"kind": "profiling", "file": "Multifunctional_Pager_LAN_PHYSICAL.pcap.csv"},
        "exclude_prefixes": ["MQTT"],
        "include_mqtt_prefix": False,
    },
    {
        "site_id": "site-bpm",
        "device_type": "bp_monitor",
        "fl_protocol_group": "mqtt",
        "attack_family": "mqtt",
        "baseline_template": "cic-template-bp-monitor-v1",
        "benign": {"kind": "attack_test", "file": "Benign_test.pcap.csv"},
        "include_mqtt_prefix": True,
    },
)

SIX_SITES = (
    {
        "site_id": "site-camera",
        "device_type": "medical_camera",
        "fl_protocol_group": "wifi",
        "attack_family": "dos",
        "baseline_template": "cic-template-medical-camera-v1",
        "benign": {"kind": "profiling", "file": "Blink_Camera_LAN_WATCH.pcap.csv"},
        "exclude_prefixes": ["MQTT"],
        "include_mqtt_prefix": False,
    },
    {
        "site_id": "site-pager",
        "device_type": "medical_pager",
        "fl_protocol_group": "wifi",
        "attack_family": "ddos",
        "baseline_template": "cic-template-medical-pager-v1",
        "benign": {"kind": "profiling", "file": "Multifunctional_Pager_LAN_PHYSICAL.pcap.csv"},
        "exclude_prefixes": ["MQTT"],
        "include_mqtt_prefix": False,
    },
    {
        "site_id": "site-recon",
        "device_type": "network_scanner",
        "fl_protocol_group": "network",
        "attack_family": "recon",
        "baseline_template": "generic-observe-only-v1",
        "benign": {"kind": "attack_test", "file": "Benign_test.pcap.csv"},
        "include_mqtt_prefix": False,
    },
    {
        "site_id": "site-spoof",
        "device_type": "network_gateway",
        "fl_protocol_group": "network",
        "attack_family": "spoofing",
        "baseline_template": "generic-observe-only-v1",
        "benign": {"kind": "attack_test", "file": "Benign_test.pcap.csv"},
        "file_prefixes": ["ARP_SPOOFING"],
        "include_validation_in_train": True,
    },
    {
        "site_id": "site-bpm",
        "device_type": "bp_monitor",
        "fl_protocol_group": "mqtt",
        "attack_family": "mqtt_dos",
        "baseline_template": "cic-template-bp-monitor-v1",
        "benign": {"kind": "attack_test", "file": "Benign_test.pcap.csv"},
        "file_prefixes": ["MQTT-DOS"],
    },
    {
        "site_id": "site-baby-sensor",
        "device_type": "baby_sensor",
        "fl_protocol_group": "mqtt",
        "attack_family": "mqtt_flood_malformed",
        "baseline_template": "cic-template-baby-sensor-v1",
        "benign": {"kind": "profiling", "file": "SenseU_LAN_EMERGENCY.pcap.csv"},
        "file_prefixes": ["MQTT-DDOS", "MQTT-MALFORMED"],
        "include_validation_in_train": True,
    },
)

LAYOUTS = {
    "three": THREE_SITES,
    "six": SIX_SITES,
}


def _matches(name: str, site: dict[str, Any]) -> bool:
    from app.data.inventory import infer_attack_family, infer_label_from_filename

    upper = name.upper()
    for prefix in site.get("exclude_prefixes") or []:
        if upper.startswith(str(prefix).upper()):
            return False

    file_prefixes = site.get("file_prefixes")
    if file_prefixes:
        return any(upper.startswith(str(prefix).upper()) for prefix in file_prefixes)

    family = str(site.get("attack_family") or "")
    inferred = infer_attack_family(infer_label_from_filename(Path(name)))
    if inferred == family:
        return True
    return bool(site.get("include_mqtt_prefix")) and upper.startswith("MQTT")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--layout",
        choices=sorted(LAYOUTS),
        default="three",
        help="Site layout: three (legacy) or six (expanded non-IID)",
    )
    parser.add_argument(
        "--official-manifest",
        type=Path,
        default=ROOT / "artifacts" / "ciciomt" / "official_file_manifest.json",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Defaults to artifacts/fl-experiment-{layout}/splits",
    )
    parser.add_argument("--seed", type=int, default=20260818)
    args = parser.parse_args()

    sites = LAYOUTS[args.layout]
    output_dir = args.output_dir or (ROOT / "artifacts" / f"fl-experiment-{args.layout}" / "splits")
    official = json.loads(args.official_manifest.read_text(encoding="utf-8"))
    groups = official.get("group_splits") or {}
    output_dir.mkdir(parents=True, exist_ok=True)

    experiment_id = f"fl-{args.layout}-site-{args.seed}"
    index: dict[str, Any] = {
        "experiment_id": experiment_id,
        "layout": args.layout,
        "site_count": len(sites),
        "seed": args.seed,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "source_manifest": str(args.official_manifest),
        "sites": [],
    }

    for site in sites:
        fl_protocol_group = resolve_fl_protocol_group(site)
        train = [name for name in groups.get("train") or [] if _matches(name, site)]
        if site.get("include_validation_in_train"):
            for name in groups.get("validation") or []:
                if _matches(name, site) and name not in train:
                    train.append(name)
        validation = [
            name
            for name in groups.get("validation") or []
            if _matches(name, site) and name not in train
        ]
        test = [name for name in groups.get("test") or [] if _matches(name, site)]
        payload = {
            "experiment_id": experiment_id,
            "layout": args.layout,
            "seed": args.seed,
            "site_id": site["site_id"],
            "device_type": site["device_type"],
            "fl_protocol_group": fl_protocol_group,
            "attack_family": site["attack_family"],
            "baseline_template": site.get("baseline_template"),
            "benign": site.get("benign"),
            "file_prefixes": site.get("file_prefixes"),
            "exclude_prefixes": site.get("exclude_prefixes"),
            "include_mqtt_prefix": site.get("include_mqtt_prefix", False),
            "include_validation_in_train": site.get("include_validation_in_train", False),
            "max_train_rows_per_file": 5000,
            "max_test_rows_per_file": 3000,
            "max_benign_test_rows": 5000,
            "splits": {"train": train, "validation": validation, "test": test},
        }
        out_path = output_dir / f"{site['site_id']}.json"
        out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        index["sites"].append(
            {
                "site_id": site["site_id"],
                "file": out_path.name,
                "fl_protocol_group": fl_protocol_group,
                "attack_family": site["attack_family"],
                "train_files": len(train),
                "validation_files": len(validation),
                "test_files": len(test),
            }
        )
        print(
            f"{site['site_id']}: train={len(train)} val={len(validation)} test={len(test)} -> {out_path}"
        )

    site_ids = tuple(site["site_id"] for site in sites)
    index["protocol_cohorts"] = cohort_index(site_ids, splits_dir=output_dir)
    index_path = output_dir.parent / "experiment-manifest.json"
    index_path.write_text(json.dumps(index, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {index_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
