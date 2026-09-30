"""Versioned score calibration shared by local inference adapters."""

from __future__ import annotations

import json
import math
from bisect import bisect_right
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ScoreCalibrator:
    version: str
    kind: str = "identity"
    slope: float = 1.0
    intercept: float = 0.0
    points: tuple[tuple[float, float], ...] = ()

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "ScoreCalibrator":
        raw_points = raw.get("points") or []
        if not isinstance(raw_points, Sequence) or isinstance(raw_points, (str, bytes)):
            raise ValueError("calibration points must be an array")
        points: list[tuple[float, float]] = []
        for point in raw_points:
            if not isinstance(point, Sequence) or len(point) != 2:
                raise ValueError("each calibration point must contain input and output")
            points.append((float(point[0]), float(point[1])))
        calibrator = cls(
            version=str(raw.get("version") or "").strip(),
            kind=str(raw.get("kind") or "identity").strip().lower(),
            slope=float(raw.get("slope", 1.0)),
            intercept=float(raw.get("intercept", 0.0)),
            points=tuple(points),
        )
        calibrator.validate()
        return calibrator

    def validate(self) -> None:
        if not self.version:
            raise ValueError("calibration version is required")
        if self.kind not in {"identity", "platt", "isotonic"}:
            raise ValueError(f"unsupported calibration kind: {self.kind}")
        if not math.isfinite(self.slope) or not math.isfinite(self.intercept):
            raise ValueError("calibration coefficients must be finite")
        if self.kind == "isotonic":
            if len(self.points) < 2:
                raise ValueError("isotonic calibration requires at least two points")
            inputs = [point[0] for point in self.points]
            outputs = [point[1] for point in self.points]
            if inputs != sorted(inputs) or len(inputs) != len(set(inputs)):
                raise ValueError("isotonic calibration inputs must be strictly increasing")
            if outputs != sorted(outputs) or any(not 0 <= value <= 1 for value in outputs):
                raise ValueError("isotonic calibration outputs must be monotonic in [0, 1]")

    def apply(self, raw_score: float) -> float:
        value = float(raw_score)
        if not math.isfinite(value):
            raise ValueError("raw model score must be finite")
        if self.kind == "identity":
            if not 0 <= value <= 1:
                raise ValueError("identity calibration requires a score between 0 and 1")
            return value
        if self.kind == "platt":
            logit = self.slope * value + self.intercept
            if logit >= 0:
                return 1.0 / (1.0 + math.exp(-logit))
            exp_value = math.exp(logit)
            return exp_value / (1.0 + exp_value)

        if value <= self.points[0][0]:
            return self.points[0][1]
        if value >= self.points[-1][0]:
            return self.points[-1][1]
        right = bisect_right([point[0] for point in self.points], value)
        left_x, left_y = self.points[right - 1]
        right_x, right_y = self.points[right]
        fraction = (value - left_x) / (right_x - left_x)
        return left_y + fraction * (right_y - left_y)


def load_calibrator(
    path: str | Path,
    engine_id: str,
    *,
    feature_contract_id: str = "",
) -> ScoreCalibrator:
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(document, Mapping):
        raise ValueError("calibration document must be an object")
    if document.get("schema_version") != "sensel.calibration.v1":
        raise ValueError("calibration schema_version must be sensel.calibration.v1")
    declared_contract = str(document.get("feature_contract_id") or "").strip()
    if feature_contract_id and declared_contract != feature_contract_id:
        raise ValueError(
            f"calibration feature_contract_id {declared_contract!r} does not match "
            f"runtime {feature_contract_id!r}"
        )
    calibrators = document.get("calibrators")
    if not isinstance(calibrators, Mapping):
        raise ValueError("calibration document requires calibrators")
    raw = calibrators.get(engine_id)
    if not isinstance(raw, Mapping):
        raise ValueError(f"calibration is missing engine: {engine_id}")
    return ScoreCalibrator.from_mapping(raw)
