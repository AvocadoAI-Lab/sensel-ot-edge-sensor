"""Runtime registry for protocol-cohort XGBoost binary classifiers on EdgeMed."""

from __future__ import annotations

import json
from copy import deepcopy
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any

from .classifier import ClassifierBundle, load_classifier, score_known_attack
from .fl_protocol_cohorts import DEVICE_TYPE_TO_FL_COHORT, cohort_for_device_type

ROOT = Path(__file__).resolve().parents[1]
CLASSIFIERS_DIR = ROOT / "artifacts" / "classifiers"
MANIFEST_PATH = CLASSIFIERS_DIR / "cohort_model_manifest.json"
THRESHOLDS_PATH = CLASSIFIERS_DIR / "cohort_thresholds.json"
DEFAULT_DECISION_THRESHOLD = 0.5


def _utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def cohort_artifact_name(cohort: str) -> str:
    return f"xgboost_binary_{cohort}.joblib"


def cohort_artifact_path(cohort: str) -> Path:
    return CLASSIFIERS_DIR / cohort_artifact_name(cohort)


@lru_cache(maxsize=1)
def load_manifest() -> dict[str, Any] | None:
    if not MANIFEST_PATH.is_file():
        return None
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def load_cohort_thresholds() -> dict[str, float]:
    """Per-cohort Attack probability thresholds (default 0.5)."""
    thresholds: dict[str, float] = {}
    manifest = load_manifest()
    if manifest and isinstance(manifest.get("decision_thresholds"), dict):
        for cohort, value in manifest["decision_thresholds"].items():
            thresholds[str(cohort)] = float(value)
    if THRESHOLDS_PATH.is_file():
        payload = json.loads(THRESHOLDS_PATH.read_text(encoding="utf-8"))
        for cohort, value in (payload.get("thresholds") or {}).items():
            thresholds[str(cohort)] = float(value)
    return thresholds


def decision_threshold_for_cohort(cohort: str) -> float:
    return float(load_cohort_thresholds().get(cohort, DEFAULT_DECISION_THRESHOLD))


def manifest_cohort_entry(cohort: str) -> dict[str, Any] | None:
    manifest = load_manifest()
    if not manifest:
        return None
    entry = (manifest.get("cohorts") or {}).get(cohort)
    return entry if isinstance(entry, dict) else None


@lru_cache(maxsize=8)
def _load_bundle(path_str: str) -> ClassifierBundle:
    return load_classifier(Path(path_str))


def get_cohort_classifier(device_type: str) -> tuple[ClassifierBundle | None, dict[str, Any]]:
    """Return the cohort XGB bundle and deployment metadata for a device_type."""
    cohort = cohort_for_device_type(device_type)
    meta: dict[str, Any] = {
        "fl_protocol_group": cohort,
        "device_type": device_type,
    }
    entry = manifest_cohort_entry(cohort)
    if entry:
        meta.update(
            {
                "selected_source": entry.get("selected_source"),
                "macro_f1": entry.get("macro_f1"),
                "artifact": entry.get("artifact"),
            }
        )
        artifact = CLASSIFIERS_DIR / str(entry.get("artifact") or cohort_artifact_name(cohort))
    else:
        artifact = cohort_artifact_path(cohort)

    if not artifact.is_file():
        return None, meta

    try:
        return _load_bundle(str(artifact.resolve())), meta
    except Exception:
        return None, meta


def score_known_attack_for_device(
    features: dict[str, float],
    device_type: str,
) -> dict[str, Any] | None:
    bundle, meta = get_cohort_classifier(device_type)
    if bundle is None:
        return None
    cohort = str(meta.get("fl_protocol_group") or cohort_for_device_type(device_type))
    threshold = decision_threshold_for_cohort(cohort)
    scored = score_known_attack(bundle, features, decision_threshold=threshold)
    if scored is None:
        return None
    payload = deepcopy(scored)
    payload["fl_protocol_group"] = meta.get("fl_protocol_group")
    payload["cohort_model_source"] = meta.get("selected_source")
    payload["cohort_model_artifact"] = meta.get("artifact")
    payload["decision_threshold"] = round(threshold, 6)
    return payload


def deployment_status() -> dict[str, Any]:
    manifest = load_manifest()
    cohorts: dict[str, Any] = {}
    for cohort in sorted(DEVICE_TYPE_TO_FL_COHORT.values()):
        path = cohort_artifact_path(cohort)
        entry = manifest_cohort_entry(cohort) if manifest else None
        cohorts[cohort] = {
            "artifact": cohort_artifact_name(cohort),
            "ready": path.is_file(),
            "bytes": path.stat().st_size if path.is_file() else None,
            "selected_source": (entry or {}).get("selected_source"),
            "macro_f1": (entry or {}).get("macro_f1"),
            "decision_threshold": decision_threshold_for_cohort(cohort),
        }
    return {
        "schema": "sensel.cohort_xgb.deployment_status.v1",
        "manifest_ready": manifest is not None,
        "manifest_path": str(MANIFEST_PATH),
        "thresholds_path": str(THRESHOLDS_PATH),
        "decision_thresholds": load_cohort_thresholds(),
        "published_at": (manifest or {}).get("published_at"),
        "source_experiment": (manifest or {}).get("source_experiment"),
        "cohorts": cohorts,
        "device_type_map": dict(DEVICE_TYPE_TO_FL_COHORT),
    }
