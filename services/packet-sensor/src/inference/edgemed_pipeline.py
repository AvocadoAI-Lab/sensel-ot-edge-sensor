"""Remote EdgeMed inference orchestration for feature windows."""

from __future__ import annotations

from typing import TYPE_CHECKING, Mapping

from src.features.contract import FeatureContractSpec, FeatureSequence
from src.inference.edgemed_client import EdgeMedFeatureMapping, EdgeMedScoreClient, runtime_states
from src.inference.onnx_sequence import ModelRuntimeState
from src.inference.pipeline import LocalInferenceOutcome

if TYPE_CHECKING:
    from src.config.settings import InferenceConfig


class EdgeMedInferencePipeline:
    def __init__(self, client: EdgeMedScoreClient) -> None:
        self._client = client
        self._states = runtime_states(client._feature_contract_id)

    @property
    def states(self) -> tuple[ModelRuntimeState, ...]:
        return self._states

    def evaluate(
        self,
        sequence: FeatureSequence,
        *,
        baseline_profile: Mapping[str, Any] | None = None,
    ) -> LocalInferenceOutcome:
        return self._client.score_sequence(sequence, baseline_profile=baseline_profile)


def build_edgemed_inference_pipeline(
    config: "InferenceConfig",
    *,
    feature_contract_id: str,
    feature_contract_path: str,
) -> EdgeMedInferencePipeline:
    edgemed = config.edgemed
    if not edgemed.enabled:
        raise ValueError("edgemed backend requires inference.edgemed.enabled=true")
    if not edgemed.base_url.strip():
        raise ValueError("edgemed backend requires inference.edgemed.base_url")

    contract = FeatureContractSpec.load(feature_contract_path)
    if contract.contract_id != feature_contract_id:
        raise ValueError("configured feature contract ID does not match contract file")

    mapping = EdgeMedFeatureMapping.load(edgemed.mapping_path)
    client = EdgeMedScoreClient(
        base_url=edgemed.base_url,
        timeout_sec=edgemed.timeout_sec,
        device_type=edgemed.device_type,
        operating_state=edgemed.operating_state,
        criticality=edgemed.criticality,
        feature_contract_id=feature_contract_id,
        alert_threshold=config.fusion_alert_threshold,
        policy_version=config.fusion_policy_version,
        mapping=mapping,
        contract=contract,
        investigate_enabled=edgemed.investigate_enabled,
        investigate_on_decisions=tuple(edgemed.investigate_on_decisions),
        investigate_timeout_sec=edgemed.investigate_timeout_sec,
    )
    return EdgeMedInferencePipeline(client)
