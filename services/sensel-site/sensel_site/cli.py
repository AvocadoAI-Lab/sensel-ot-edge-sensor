"""Operator CLI for lineage, signing, and trainer handoff."""

from __future__ import annotations

import argparse
import json
from typing import Any

from sensel_site.config import SiteConfig
from sensel_site.feature_contracts import FeatureContractRegistry
from sensel_site.lineage import DatasetLineageService, load_private_key
from sensel_site.store import SiteStore
from sensel_site.trainer import TrainerBoundary
from sensel_site.training_policy import load_xgboost_policy


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sensel-site")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status")

    label = commands.add_parser("label")
    label.add_argument("episode_id")
    label.add_argument("label")
    label.add_argument("--actor", required=True)
    label.add_argument("--reason", required=True)
    label.add_argument("--sensor-id")

    dataset = commands.add_parser("dataset-create")
    dataset.add_argument("--feature-contract", required=True)
    dataset.add_argument(
        "--label-source",
        choices=("fusion_decision", "manual", "unlabeled"),
        required=True,
    )
    dataset.add_argument(
        "--retention",
        choices=("training-short", "research", "regulated"),
        default="training-short",
    )
    dataset.add_argument("--started-at")
    dataset.add_argument("--ended-at")
    dataset.add_argument("--limit", type=int, default=100_000)

    export = commands.add_parser("dataset-export")
    export.add_argument("dataset_id")

    trainer = commands.add_parser("trainer-prepare")
    trainer.add_argument("dataset_id")
    trainer.add_argument("--algorithm", required=True)
    trainer.add_argument("--model-id", required=True)
    trainer.add_argument("--base-model-version", required=True)
    trainer.add_argument("--feature-contract", required=True)
    return parser


def _lineage(config: SiteConfig, store: SiteStore) -> DatasetLineageService:
    return DatasetLineageService(
        store,
        tenant_id=config.tenant_id,
        site_id=config.site_id,
        node_id=config.node_id,
        export_root=config.export_dir,
        signing_key_path=config.signing_key_path,
        signing_key_id=config.signing_key_id,
        feature_contract_registry=FeatureContractRegistry(
            config.feature_contract_dir
        ),
    )


def execute(args: argparse.Namespace, config: SiteConfig, store: SiteStore) -> Any:
    if args.command == "status":
        return {"tenant_id": config.tenant_id, "site_id": config.site_id, **store.counts()}
    if args.command == "label":
        return {
            "label_id": store.add_manual_label(
                tenant_id=config.tenant_id,
                site_id=config.site_id,
                episode_id=args.episode_id,
                label=args.label,
                actor=args.actor,
                reason=args.reason,
                sensor_id=args.sensor_id,
            )
        }
    if args.command == "dataset-create":
        result = _lineage(config, store).create_dataset(
            feature_contract_id=args.feature_contract,
            label_source=args.label_source,
            retention_class=args.retention,
            started_at=args.started_at,
            ended_at=args.ended_at,
            limit=args.limit,
        )
        return {
            "dataset_id": result.dataset_id,
            "created": result.created,
            "sample_count": result.manifest["sample_count"],
        }
    if args.command == "dataset-export":
        return {"path": str(_lineage(config, store).export_signed(args.dataset_id))}
    if args.command == "trainer-prepare":
        private_key = load_private_key(config.signing_key_path)
        boundary = TrainerBoundary(
            store,
            tenant_id=config.tenant_id,
            site_id=config.site_id,
            inbox_root=config.trainer_inbox_dir,
            public_key=private_key.public_key(),
            signing_key=private_key,
            signing_key_id=config.signing_key_id,
            training_policy=load_xgboost_policy(config.trainer_policy_path),
        )
        request, created = boundary.prepare_job(
            dataset_id=args.dataset_id,
            algorithm=args.algorithm,
            model_id=args.model_id,
            base_model_version=args.base_model_version,
            expected_feature_contract_id=args.feature_contract,
        )
        return {"job_id": request["job_id"], "created": created}
    raise ValueError(f"unsupported command: {args.command}")


def main() -> None:
    config = SiteConfig.from_env()
    config.data_dir.mkdir(parents=True, exist_ok=True)
    store = SiteStore(config.db_path)
    try:
        print(
            json.dumps(
                execute(_parser().parse_args(), config, store),
                ensure_ascii=False,
                sort_keys=True,
            )
        )
    finally:
        store.close()


if __name__ == "__main__":
    main()
