"""Baseline policy validation — surfaces typos / wrong types instead of letting
them fail silently. Built on pydantic (already a dependency); warnings are
non-fatal so a partially-malformed policy degrades loudly rather than breaking
the sensor."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, ValidationError


class _Lax(BaseModel):
    model_config = ConfigDict(extra="allow")


class AssetModel(_Lax):
    asset_id: str
    addresses: list[str] = []
    allowed_peers: list[str] = []
    allowed_protocols: list[str] = []
    allowed_ports: list[int] = []
    allowed_modbus_function_codes: list[int] = []
    normal_packet_rate_per_min: dict = {}
    normal_write_count_per_hour: int = 0


class GoosePublisherModel(_Lax):
    asset_id: str | None = None
    publisher_mac: str = ""
    appid: int | None = None
    gocb_ref: str = ""
    production: bool = True
    max_silence_sec: float = 0.0


class MmsIedModel(_Lax):
    asset_id: str | None = None
    ied_ip: str
    allowed_mms_clients: list[str] = []


class Iec61850Model(_Lax):
    goose_publishers: list[GoosePublisherModel] = []
    mms_ieds: list[MmsIedModel] = []
    thresholds: dict = {}


class PolicyModel(_Lax):
    policy_version: str | None = None
    site_id: str | None = None
    assets: list[AssetModel] = []
    global_allowlists: dict = {}
    thresholds: dict = {}
    iec61850: Iec61850Model = Iec61850Model()
    ioc: list = []


_ENTRY_MODELS = {
    "assets": AssetModel,
    ("iec61850", "goose_publishers"): GoosePublisherModel,
    ("iec61850", "mms_ieds"): MmsIedModel,
}


def _unknown_keys(obj: dict, model: type[BaseModel], prefix: str) -> list[str]:
    known = set(model.model_fields)
    return [f"{prefix}: unknown field {key!r}" for key in obj if key not in known]


def validate_policy(raw: object) -> list[str]:
    """Return a list of human-readable warnings (empty == clean)."""
    if not isinstance(raw, dict):
        return ["policy is not a JSON object"]

    warnings: list[str] = []
    warnings += _unknown_keys(raw, PolicyModel, "policy")

    try:
        PolicyModel.model_validate(raw)
    except ValidationError as exc:
        for err in exc.errors():
            loc = ".".join(str(p) for p in err["loc"])
            warnings.append(f"policy.{loc}: {err['msg']}")

    for index, asset in enumerate(raw.get("assets", []) or []):
        if isinstance(asset, dict):
            warnings += _unknown_keys(asset, AssetModel, f"assets[{index}]")

    iec = raw.get("iec61850", {})
    if isinstance(iec, dict):
        for index, pub in enumerate(iec.get("goose_publishers", []) or []):
            if isinstance(pub, dict):
                warnings += _unknown_keys(pub, GoosePublisherModel, f"iec61850.goose_publishers[{index}]")
        for index, ied in enumerate(iec.get("mms_ieds", []) or []):
            if isinstance(ied, dict):
                warnings += _unknown_keys(ied, MmsIedModel, f"iec61850.mms_ieds[{index}]")

    return warnings
