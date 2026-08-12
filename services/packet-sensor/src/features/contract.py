"""Versioned feature ordering, preprocessing, and sequence assembly."""

from __future__ import annotations

import hashlib
import json
import math
from collections import OrderedDict, deque
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


_DATA_TYPES = {"float64", "int64", "boolean"}
_MISSING_POLICIES = {"reject", "zero", "default"}
_NORMALIZATIONS = {"none", "log1p", "z_score", "min_max"}


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _as_utc(value: datetime | str) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    else:
        raw = str(value).strip()
        if raw.endswith("Z"):
            raw = f"{raw[:-1]}+00:00"
        try:
            parsed = datetime.fromisoformat(raw)
        except ValueError as exc:
            raise ValueError(f"invalid feature frame timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _timestamp_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class FeatureDefinitionSpec:
    name: str
    index: int
    data_type: str
    missing_value_policy: str
    normalization: str
    default_value: float | None = None
    mean: float | None = None
    standard_deviation: float | None = None
    minimum: float | None = None
    maximum: float | None = None

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "FeatureDefinitionSpec":
        spec = cls(
            name=str(raw.get("name") or "").strip(),
            index=int(raw.get("index", -1)),
            data_type=str(raw.get("data_type") or "").strip().lower(),
            missing_value_policy=str(
                raw.get("missing_value_policy") or ""
            ).strip().lower(),
            normalization=str(raw.get("normalization") or "none").strip().lower(),
            default_value=(
                float(raw["default_value"]) if "default_value" in raw else None
            ),
            mean=float(raw["mean"]) if "mean" in raw else None,
            standard_deviation=(
                float(raw["standard_deviation"])
                if "standard_deviation" in raw
                else None
            ),
            minimum=float(raw["minimum"]) if "minimum" in raw else None,
            maximum=float(raw["maximum"]) if "maximum" in raw else None,
        )
        spec.validate()
        return spec

    def validate(self) -> None:
        if not self.name:
            raise ValueError("feature name is required")
        if self.index < 0:
            raise ValueError(f"feature {self.name} index must be non-negative")
        if self.data_type not in _DATA_TYPES:
            raise ValueError(f"feature {self.name} has unsupported data_type")
        if self.missing_value_policy not in _MISSING_POLICIES:
            raise ValueError(f"feature {self.name} has unsupported missing value policy")
        if self.missing_value_policy == "default" and self.default_value is None:
            raise ValueError(f"feature {self.name} requires default_value")
        if self.normalization not in _NORMALIZATIONS:
            raise ValueError(f"feature {self.name} has unsupported normalization")
        if self.normalization == "z_score" and (
            self.mean is None
            or self.standard_deviation is None
            or self.standard_deviation <= 0
        ):
            raise ValueError(f"feature {self.name} requires positive z-score parameters")
        if self.normalization == "min_max" and (
            self.minimum is None
            or self.maximum is None
            or self.maximum <= self.minimum
        ):
            raise ValueError(f"feature {self.name} requires valid min-max parameters")

    def value_from(self, values: Mapping[str, Any]) -> float:
        if self.name not in values or values[self.name] is None:
            if self.missing_value_policy == "reject":
                raise ValueError(f"missing required feature: {self.name}")
            raw_value: Any = (
                self.default_value if self.missing_value_policy == "default" else 0
            )
        else:
            raw_value = values[self.name]

        if isinstance(raw_value, bool):
            if self.data_type != "boolean":
                raise ValueError(f"feature {self.name} must be {self.data_type}")
            numeric = float(raw_value)
        elif self.data_type == "boolean":
            raise ValueError(f"feature {self.name} must be boolean")
        elif self.data_type == "int64":
            if not isinstance(raw_value, int):
                raise ValueError(f"feature {self.name} must be int64")
            numeric = float(raw_value)
        else:
            if not isinstance(raw_value, (int, float)):
                raise ValueError(f"feature {self.name} must be numeric")
            numeric = float(raw_value)

        if not math.isfinite(numeric):
            raise ValueError(f"feature {self.name} must be finite")
        if self.normalization == "none":
            return numeric
        if self.normalization == "log1p":
            if numeric <= -1:
                raise ValueError(f"feature {self.name} must be greater than -1 for log1p")
            return math.log1p(numeric)
        if self.normalization == "z_score":
            assert self.mean is not None and self.standard_deviation is not None
            return (numeric - self.mean) / self.standard_deviation
        assert self.minimum is not None and self.maximum is not None
        return (numeric - self.minimum) / (self.maximum - self.minimum)


@dataclass(frozen=True)
class FeatureContractSpec:
    contract_id: str
    version: str
    entity_scope: str
    sequence_length: int
    frame_interval_seconds: int
    features: tuple[FeatureDefinitionSpec, ...]
    definition_sha256: str

    @classmethod
    def load(cls, path: str | Path) -> "FeatureContractSpec":
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("feature contract must be a JSON object")
        expected_digest = str(raw.get("definition_sha256") or "")
        canonical = dict(raw)
        canonical.pop("definition_sha256", None)
        actual_digest = hashlib.sha256(_canonical_json(canonical)).hexdigest()
        if expected_digest != actual_digest:
            raise ValueError("feature contract definition_sha256 mismatch")

        raw_features = raw.get("features")
        if not isinstance(raw_features, list) or not raw_features:
            raise ValueError("feature contract requires at least one feature")
        features = tuple(FeatureDefinitionSpec.from_mapping(item) for item in raw_features)
        contract = cls(
            contract_id=str(raw.get("contract_id") or "").strip(),
            version=str(raw.get("version") or "").strip(),
            entity_scope=str(raw.get("entity_scope") or "").strip(),
            sequence_length=int(raw.get("sequence_length") or 0),
            frame_interval_seconds=int(raw.get("frame_interval_seconds") or 0),
            features=features,
            definition_sha256=expected_digest,
        )
        contract.validate()
        return contract

    def validate(self) -> None:
        if not self.contract_id or not self.version:
            raise ValueError("feature contract_id and version are required")
        if self.entity_scope not in {"sensor", "asset", "flow"}:
            raise ValueError("feature contract entity_scope is unsupported")
        if self.sequence_length <= 0 or self.frame_interval_seconds <= 0:
            raise ValueError("feature sequence length and interval must be positive")
        indices = [feature.index for feature in self.features]
        if indices != list(range(len(self.features))):
            raise ValueError("feature indices must be ordered and contiguous from zero")
        names = [feature.name for feature in self.features]
        if len(names) != len(set(names)):
            raise ValueError("feature names must be unique")

    def normalize(self, values: Mapping[str, Any]) -> tuple[float, ...]:
        return tuple(feature.value_from(values) for feature in self.features)


@dataclass(frozen=True)
class FeatureFrame:
    observed_at: datetime
    sequence_number: int
    values: tuple[float, ...]


@dataclass(frozen=True)
class FeatureSequence:
    contract_id: str
    entity_id: str
    started_at: datetime
    ended_at: datetime
    frames: tuple[FeatureFrame, ...]
    sequence_sha256: str

    @property
    def latest_values(self) -> tuple[float, ...]:
        return self.frames[-1].values


class FeatureSequenceBuilder:
    """Build fixed-length, per-entity sequences with bounded memory."""

    def __init__(
        self,
        contract: FeatureContractSpec,
        *,
        max_entities: int = 1024,
        interval_tolerance_seconds: float = 5.0,
    ):
        if max_entities <= 0:
            raise ValueError("max_entities must be positive")
        if interval_tolerance_seconds < 0:
            raise ValueError("interval_tolerance_seconds must be non-negative")
        self.contract = contract
        self.max_entities = max_entities
        self.interval_tolerance_seconds = interval_tolerance_seconds
        self._frames: OrderedDict[str, deque[FeatureFrame]] = OrderedDict()

    def add_frame(
        self,
        *,
        entity_id: str,
        observed_at: datetime | str,
        sequence_number: int,
        values: Mapping[str, Any],
    ) -> FeatureSequence | None:
        identity = entity_id.strip()
        if not identity:
            raise ValueError("feature sequence entity_id is required")
        timestamp = _as_utc(observed_at)
        if sequence_number < 0:
            raise ValueError("feature frame sequence_number must be non-negative")
        normalized = self.contract.normalize(values)

        frames = self._frames.get(identity)
        if frames:
            last = frames[-1]
            if timestamp <= last.observed_at:
                raise ValueError("feature frame timestamps must be strictly increasing")
            if sequence_number <= last.sequence_number:
                raise ValueError("feature frame sequence numbers must be strictly increasing")
            elapsed = (timestamp - last.observed_at).total_seconds()
            minimum_interval = max(
                0,
                self.contract.frame_interval_seconds
                - self.interval_tolerance_seconds,
            )
            maximum_interval = (
                self.contract.frame_interval_seconds
                + self.interval_tolerance_seconds
            )
            if elapsed < minimum_interval:
                raise ValueError("feature frame interval is shorter than the contract")
            if elapsed > maximum_interval:
                frames.clear()
        else:
            if len(self._frames) >= self.max_entities:
                self._frames.popitem(last=False)
            frames = deque(maxlen=self.contract.sequence_length)
            self._frames[identity] = frames

        frames.append(
            FeatureFrame(
                observed_at=timestamp,
                sequence_number=sequence_number,
                values=normalized,
            )
        )
        self._frames.move_to_end(identity)
        if len(frames) < self.contract.sequence_length:
            return None

        immutable_frames = tuple(frames)
        digest_payload = {
            "contract_id": self.contract.contract_id,
            "entity_id": identity,
            "frames": [
                {
                    "observed_at": _timestamp_text(frame.observed_at),
                    "sequence_number": frame.sequence_number,
                    "values": list(frame.values),
                }
                for frame in immutable_frames
            ],
        }
        return FeatureSequence(
            contract_id=self.contract.contract_id,
            entity_id=identity,
            started_at=immutable_frames[0].observed_at,
            ended_at=immutable_frames[-1].observed_at,
            frames=immutable_frames,
            sequence_sha256=hashlib.sha256(_canonical_json(digest_payload)).hexdigest(),
        )

    def clear(self, entity_id: str) -> None:
        self._frames.pop(entity_id, None)
