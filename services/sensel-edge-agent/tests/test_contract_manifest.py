from __future__ import annotations

import hashlib
import json
from pathlib import Path

from google.protobuf import descriptor_pb2

from sensel.common.v1 import common_pb2
from sensel.device.v1 import device_management_pb2
from sensel.episode.v1 import trust_episode_pb2
from sensel.feature.v1 import feature_contract_pb2
from sensel.federation.v1 import federation_pb2
from sensel.security.v1 import security_event_pb2
from src.contracts.security_event_codec import encode_security_event


SERVICE_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = Path(__file__).parent / "fixtures" / "security_event.v1.bin"
MANIFEST_PATH = SERVICE_ROOT / "sensel" / "CONTRACT_MANIFEST.json"


def _descriptor_sha256() -> str:
    descriptors = (
        common_pb2.DESCRIPTOR,
        device_management_pb2.DESCRIPTOR,
        trust_episode_pb2.DESCRIPTOR,
        feature_contract_pb2.DESCRIPTOR,
        federation_pb2.DESCRIPTOR,
        security_event_pb2.DESCRIPTOR,
    )
    descriptor_set = descriptor_pb2.FileDescriptorSet()
    for descriptor in sorted(descriptors, key=lambda item: item.name):
        descriptor.CopyToProto(descriptor_set.file.add())
    value = descriptor_set.SerializeToString(deterministic=True)
    return hashlib.sha256(value).hexdigest()


def _legacy_event() -> dict:
    return {
        "event_id": "evt-golden-security-v1-0001",
        "sequence": 42,
        "asset_id": "asset-plc-golden",
        "rule_id": "OT-019",
        "event_type": "CTI_IOC_OBSERVED",
        "severity": "high",
        "risk_score": 90.5,
        "protocol": "tcp",
        "src_ip": "203.0.113.55",
        "dst_ip": "192.0.2.10",
        "dst_port": 102,
        "description": "SenseL protobuf golden security event",
        "timestamp": "2026-08-12T00:00:00Z",
        "evidence": {
            "confidence": 0.975,
            "context": {"direction": "src", "tags": ["cti", "ot"]},
            "mirror_passive": True,
            "sid": 9000001,
            "source": "golden-fixture",
        },
        "evidence_ref": "sha256:golden-evidence",
        "feature_contract_id": "flow-v1",
        "inference_scores": [
            {
                "model_id": "tiny-lstm",
                "model_version": "0.1.0-smoke",
                "score": 0.91,
                "calibrated_score": 0.87,
                "label": "anomaly",
                "feature_contract_id": "flow-v1",
            }
        ],
        "fusion": {
            "policy_version": "fusion-v1",
            "score": 0.93,
            "threshold": 0.8,
            "decision": "alert",
        },
    }


def test_generated_descriptors_match_canonical_manifest() -> None:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))

    assert manifest["contract_version"] == "0.2.0"
    assert _descriptor_sha256() == manifest["descriptor_sha256"]


def test_edge_encoder_matches_canonical_golden_wire() -> None:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    expected_wire = FIXTURE_PATH.read_bytes()
    actual_wire = encode_security_event(
        _legacy_event(),
        tenant_id="tenant-golden",
        site_id="site-golden",
        sensor_id="sensor-golden",
        producer_version="0.1.0",
        trace_id="trace-golden-0001",
    )

    assert actual_wire == expected_wire
    assert hashlib.sha256(actual_wire).hexdigest() == (
        manifest["golden_fixtures"]["security_event.v1.bin"]["sha256"]
    )
