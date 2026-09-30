"""Run five FL proxy rounds with BPM training physically executed on a Pi."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
import time
from copy import deepcopy
from pathlib import Path
from typing import Any

from xgboost import XGBClassifier

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.classifier import ClassifierBundle, load_classifier, save_classifier
from app.data.columns import load_column_map
from scripts.fl_control_plane import default_cp_artifacts_dir, publish_global_model, record_round
from scripts.run_three_site_fl_experiment import (
    SITES,
    _align,
    _metrics_for,
    _sha256_file,
    _tree_update_bytes,
    _uncalibrated_federation_base,
    aggregate_independent_tree_updates,
    continue_binary,
    load_site_frames,
)


def load_connect(edge_repo: Path) -> Any:
    helper_path = edge_repo / "scripts" / "_pi_reboot_bringup.py"
    spec = importlib.util.spec_from_file_location("sensel_pi_connection", helper_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load Pi connection helper: {helper_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.connect


def transfer_put(client: Any, local: Path, remote: str) -> dict[str, Any]:
    started = time.perf_counter()
    sftp = client.open_sftp()
    sftp.put(str(local), remote)
    stat = sftp.stat(remote)
    sftp.close()
    return {
        "direction": "pc_to_pi",
        "bytes": int(stat.st_size),
        "seconds": round(time.perf_counter() - started, 6),
    }


def transfer_get(client: Any, remote: str, local: Path) -> dict[str, Any]:
    started = time.perf_counter()
    local.parent.mkdir(parents=True, exist_ok=True)
    sftp = client.open_sftp()
    remote_stat = sftp.stat(remote)
    sftp.get(remote, str(local))
    sftp.close()
    return {
        "direction": "pi_to_pc",
        "bytes": int(remote_stat.st_size),
        "seconds": round(time.perf_counter() - started, 6),
    }


def remote_run(client: Any, command: str, timeout: int = 600) -> tuple[str, str]:
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    output = stdout.read().decode("utf-8", "replace")
    error = stderr.read().decode("utf-8", "replace")
    status = stdout.channel.recv_exit_status()
    if status != 0:
        raise RuntimeError(f"Pi command failed ({status}): {error or output}")
    return output, error


def load_local_model(path: Path, base: ClassifierBundle) -> ClassifierBundle:
    model = XGBClassifier()
    model.load_model(path)
    return ClassifierBundle(
        model_name=base.model_name,
        task="binary",
        pipeline=model,
        features=base.features,
        classes=base.classes,
        preprocess=base.preprocess,
        metadata={"execution_host": "raspberry-pi", "site_id": "site-bpm"},
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset-root", type=Path, default=Path(r"D:\實習\資料集"))
    parser.add_argument(
        "--edge-repo",
        type=Path,
        default=Path(
            r"D:\實習\sensel-ot-edge-sensor-feat-sensel-fl-protobuf-foundation"
            r"\sensel-ot-edge-sensor-feat-sensel-fl-protobuf-foundation"
        ),
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=ROOT / "artifacts" / "hybrid-pi-fl",
    )
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--trees-per-site", type=int, default=8)
    parser.add_argument("--seed", type=int, default=20260818)
    parser.add_argument("--skip-control-plane", action="store_true")
    parser.add_argument(
        "--cp-artifacts-dir",
        type=Path,
        default=None,
        help="Control Plane federation-models directory",
    )
    args = parser.parse_args()
    cp_artifacts_dir = args.cp_artifacts_dir
    if cp_artifacts_dir is None and not args.skip_control_plane:
        cp_artifacts_dir = default_cp_artifacts_dir()

    frames = load_site_frames(
        splits_dir=ROOT / "artifacts" / "fl-experiment" / "splits",
        dataset_root=args.dataset_root,
        mapping=load_column_map(),
        max_train=2000,
        max_test=2000,
        max_benign=3000,
        seed=args.seed,
    )
    round0 = _uncalibrated_federation_base(
        load_classifier(ROOT / "artifacts" / "classifiers" / "xgboost_binary.joblib")
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    models_dir = args.output_dir / "models"
    models_dir.mkdir(parents=True, exist_ok=True)
    exchange_dir = args.output_dir / "exchange"
    exchange_dir.mkdir(parents=True, exist_ok=True)
    bpm_csv = exchange_dir / "site-bpm-local-train.csv"
    _align(frames["site-bpm"]["train"], round0.features).to_csv(
        bpm_csv, index=False
    )

    connect = load_connect(args.edge_repo)
    client = connect()
    remote_root = "/home/fju/sensel-ot-edge-sensor/services/edgemed"
    remote_exchange = f"{remote_root}/data/hybrid-pi-fl"
    remote_run(client, f"mkdir -p {remote_exchange}")
    setup_transfers = {
        "worker": transfer_put(
            client,
            args.edge_repo / "scripts" / "pi_xgb_local_update.py",
            f"{remote_root}/scripts/pi_xgb_local_update.py",
        ),
        "local_dataset": transfer_put(
            client, bpm_csv, f"{remote_exchange}/site-bpm-local-train.csv"
        ),
    }
    current = deepcopy(round0)
    rounds: list[dict[str, Any]] = []
    experiment_started = time.perf_counter()
    for round_no in range(1, args.rounds + 1):
        round_started = time.perf_counter()
        global_json = exchange_dir / f"global-round-{round_no - 1:03d}.json"
        current.pipeline.save_model(global_json)
        global_sha256 = _sha256_file(global_json)
        upload = transfer_put(
            client, global_json, f"{remote_exchange}/global.json"
        )
        command = (
            f"cd {remote_root} && .venv/bin/python scripts/pi_xgb_local_update.py "
            f"--global-model {remote_exchange}/global.json "
            f"--local-csv {remote_exchange}/site-bpm-local-train.csv "
            f"--classifier-bundle artifacts/classifiers/xgboost_binary.joblib "
            f"--output-model {remote_exchange}/site-bpm-local.json "
            f"--report {remote_exchange}/site-bpm-report.json "
            f"--expected-global-sha256 {global_sha256} "
            f"--extra-trees {args.trees_per_site} "
            f"--seed {args.seed + round_no}"
        )
        remote_stdout, remote_stderr = remote_run(client, command)
        local_pi_model = exchange_dir / f"site-bpm-round-{round_no:03d}.json"
        download = transfer_get(
            client,
            f"{remote_exchange}/site-bpm-local.json",
            local_pi_model,
        )
        local_report_path = exchange_dir / f"site-bpm-round-{round_no:03d}-report.json"
        report_download = transfer_get(
            client,
            f"{remote_exchange}/site-bpm-report.json",
            local_report_path,
        )
        pi_report = json.loads(local_report_path.read_text(encoding="utf-8"))
        if _sha256_file(local_pi_model) != pi_report["output_sha256"]:
            raise ValueError("Pi update SHA-256 mismatch after transfer")

        local_updates: dict[str, ClassifierBundle] = {}
        local_metadata: dict[str, dict[str, Any]] = {}
        for site_id in ("site-camera", "site-pager"):
            started = time.perf_counter()
            local = continue_binary(
                deepcopy(current),
                _align(frames[site_id]["train"], current.features),
                extra_trees=args.trees_per_site,
                seed=args.seed + round_no * 10 + SITES.index(site_id),
            )
            local_updates[site_id] = local
            local_metadata[site_id] = {
                "execution_host": "pc",
                "training_seconds": round(time.perf_counter() - started, 6),
                "update_bytes": _tree_update_bytes(current, local),
            }
        pi_local = load_local_model(local_pi_model, current)
        local_updates["site-bpm"] = pi_local
        local_metadata["site-bpm"] = {
            "execution_host": "raspberry-pi",
            "training_seconds": pi_report["wall_seconds"],
            "peak_rss_mb": pi_report["peak_rss_mb"],
            "update_bytes": _tree_update_bytes(current, pi_local),
            "model_upload": upload,
            "update_download": download,
            "report_download": report_download,
            "remote_output": remote_stdout.strip(),
            "remote_stderr": remote_stderr.strip(),
        }

        current, trees_added = aggregate_independent_tree_updates(
            current, local_updates
        )
        model_path = models_dir / f"hybrid-round-{round_no:03d}.joblib"
        save_classifier(current, model_path)
        metrics = _metrics_for(current, frames)
        sample_counts = {
            site_id: int(len(payload["train"]))
            for site_id, payload in frames.items()
        }
        artifact_sha = _sha256_file(model_path)
        round_id = f"hybrid-pi-round-{round_no:03d}"
        artifact_uri, artifact_size = publish_global_model(
            model_path,
            round_id=round_id,
            cp_artifacts_dir=cp_artifacts_dir,
        )
        if not args.skip_control_plane:
            record_round(
                round_id=round_id,
                base_version=f"pi-0.{round_no}.0",
                sample_counts=sample_counts,
                result_sha256=artifact_sha,
                epsilon=0.0,
                site_ids=tuple(frames),
                artifact_uri=artifact_uri,
                artifact_size_bytes=artifact_size,
                created_by="lab-hybrid-pi",
                update_metadata={
                    site_id: {
                        "execution_host": metadata["execution_host"],
                        "trees_added": trees_added[site_id],
                    }
                    for site_id, metadata in local_metadata.items()
                },
            )
        payload = {
            "round": round_no,
            "round_id": f"hybrid-pi-round-{round_no:03d}",
            "trees_added_by_site": trees_added,
            "sample_counts": sample_counts,
            "local_updates": local_metadata,
            "artifact": str(model_path),
            "artifact_bytes": model_path.stat().st_size,
            "artifact_sha256": artifact_sha,
            "metrics": metrics,
            "round_seconds": round(time.perf_counter() - round_started, 6),
        }
        round_path = args.output_dir / "rounds" / f"round-{round_no:03d}.json"
        round_path.parent.mkdir(parents=True, exist_ok=True)
        round_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        rounds.append(payload)
        print(
            f"round={round_no} pi_seconds={pi_report['wall_seconds']} "
            f"macro_f1={metrics['macro_f1']}",
            flush=True,
        )
    client.close()

    summary = {
        "experiment": "hybrid-pi-three-site-xgboost",
        "architecture": {
            "site-camera": "PC local process",
            "site-pager": "PC local process",
            "site-bpm": "Raspberry Pi 4 over SSH; local data and XGBoost training on Pi",
            "aggregator": "PC independent equal-tree append",
        },
        "setup_transfers": setup_transfers,
        "rounds": [
            {
                "round": item["round"],
                "macro_f1": item["metrics"]["macro_f1"],
                "round_seconds": item["round_seconds"],
                "pi_training_seconds": item["local_updates"]["site-bpm"][
                    "training_seconds"
                ],
                "pi_peak_rss_mb": item["local_updates"]["site-bpm"][
                    "peak_rss_mb"
                ],
                "pc_to_pi_bytes": item["local_updates"]["site-bpm"][
                    "model_upload"
                ]["bytes"],
                "pi_to_pc_bytes": item["local_updates"]["site-bpm"][
                    "update_download"
                ]["bytes"],
            }
            for item in rounds
        ],
        "total_seconds": round(time.perf_counter() - experiment_started, 6),
        "final_metrics": rounds[-1]["metrics"] if rounds else {},
        "limitations": [
            "One physical Pi client plus two PC virtual clients; not three physical edges.",
            "SSH transports the lab artifacts; Flower SuperLink is evaluated separately.",
            "Pi local CSV is a frozen exported site partition, not live packet capture.",
        ],
    }
    (args.output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote {args.output_dir / 'summary.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
