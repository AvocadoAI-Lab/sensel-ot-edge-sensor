"""Local immutable feature-contract registry for Site ingestion/training gates."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sensel_site.lineage import canonical_json


@dataclass(frozen=True)
class FeatureContract:
    contract_id: str
    version: str
    definition_sha256: str
    feature_count: int
    feature_names: tuple[str, ...]
    sequence_length: int


class FeatureContractRegistry:
    def __init__(self, directory: str | Path) -> None:
        self.directory = Path(directory)
        self._contracts: dict[str, FeatureContract] = {}
        for path in sorted(self.directory.glob("feature-contract.*.json")):
            document: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
            expected = str(document.pop("definition_sha256", "")).strip()
            actual = hashlib.sha256(canonical_json(document)).hexdigest()
            if not expected or actual != expected:
                raise ValueError(f"feature contract definition digest mismatch: {path}")
            contract_id = str(document.get("contract_id") or "").strip()
            version = str(document.get("version") or "").strip()
            features = document.get("features")
            sequence_length = int(document.get("sequence_length") or 0)
            if (
                not contract_id
                or not version
                or not isinstance(features, list)
                or not features
                or sequence_length <= 0
            ):
                raise ValueError(f"invalid feature contract: {path}")
            feature_names = tuple(
                str(item.get("name") or "").strip()
                for item in features
                if isinstance(item, dict)
            )
            feature_indices = tuple(
                item.get("index") for item in features if isinstance(item, dict)
            )
            if (
                len(feature_names) != len(features)
                or any(not name for name in feature_names)
                or len(set(feature_names)) != len(feature_names)
                or feature_indices != tuple(range(len(features)))
            ):
                raise ValueError(f"feature contract indices/names are invalid: {path}")
            if contract_id in self._contracts:
                raise ValueError(f"duplicate feature contract_id: {contract_id}")
            self._contracts[contract_id] = FeatureContract(
                contract_id=contract_id,
                version=version,
                definition_sha256="sha256:" + expected,
                feature_count=len(features),
                feature_names=feature_names,
                sequence_length=sequence_length,
            )
        if not self._contracts:
            raise ValueError(f"no feature contracts found in {self.directory}")

    def require(self, contract_id: str) -> FeatureContract:
        try:
            return self._contracts[contract_id]
        except KeyError as exc:
            raise ValueError(f"unknown feature contract: {contract_id}") from exc

    def validate_episode(
        self,
        *,
        contract_id: str,
        feature_count: int,
        sequence_length: int,
    ) -> FeatureContract:
        contract = self.require(contract_id)
        if feature_count != contract.feature_count:
            raise ValueError("Trust Episode feature vector length does not match contract")
        if sequence_length != contract.sequence_length:
            raise ValueError("Trust Episode sequence length does not match contract")
        return contract
