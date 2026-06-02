"""Baseline policy validation — clean example, warnings on malformed input."""

from __future__ import annotations

from pathlib import Path

from service_loader import import_from_service

ROOT = Path(__file__).resolve().parents[2]


def _import():
    schema = import_from_service("packet-sensor", "src.policy.schema")
    return schema.validate_policy


def test_example_baseline_is_clean() -> None:
    import json

    validate_policy = _import()
    policy = json.loads((ROOT / "config/policy/baseline.example.json").read_text())
    assert validate_policy(policy) == []


def test_unknown_top_level_key_warns() -> None:
    validate_policy = _import()
    warnings = validate_policy({"assets": [], "typoo_key": 1})
    assert any("typoo_key" in w for w in warnings)


def test_asset_missing_id_warns() -> None:
    validate_policy = _import()
    warnings = validate_policy({"assets": [{"addresses": ["10.0.0.1"]}]})
    assert any("asset_id" in w for w in warnings)


def test_unknown_asset_field_warns() -> None:
    validate_policy = _import()
    warnings = validate_policy({"assets": [{"asset_id": "a", "allowed_pers": []}]})
    assert any("allowed_pers" in w for w in warnings)


def test_wrong_type_warns() -> None:
    validate_policy = _import()
    warnings = validate_policy({"assets": [{"asset_id": "a", "allowed_ports": "nope"}]})
    assert any("allowed_ports" in w for w in warnings)


def test_non_object_policy() -> None:
    validate_policy = _import()
    assert validate_policy([1, 2, 3]) == ["policy is not a JSON object"]
