"""Packet processing pipeline — L2/L3/L4 + MVP + IEC 61850."""

from __future__ import annotations

import json
import logging
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from src.baseline.collector import BaselineCollector
from src.coverage.counter import CoverageCounter
from src.detection.iec61850 import Iec61850Detector
from src.detection.ioc import IocMatcher
from src.detection.mvp import MvpDetector
from src.events.generator import EventStore
from src.episode.builder import build_trust_episode
from src.episode.writer import TrustEpisodeWriter
from src.evidence.ring_buffer import PcapRingBuffer
from src.features.publisher import FeaturePublisher
from src.features.contract import (
    FeatureContractSpec,
    FeatureSequence,
    FeatureSequenceBuilder,
)
from src.parser.l2.ethernet import L2Stats, parse_ethernet, record_l2, reset_l2_window
from src.parser.l3.ip import L3Stats, parse_ip, record_l3
from src.parser.l4.transport import parse_transport
from src.parser.l7.iec61850.goose import (
    GooseStats,
    parse_goose_packet,
    record_goose,
    reset_goose_window,
)
from src.parser.l7.iec61850.mms import (
    MmsStats,
    parse_mms_packet,
    record_mms,
    reset_mms_window,
)
from src.parser.l7.modbus.tcp import parse_modbus_tcp
from src.policy.loader import load_policy
from src.policy.detection_policy_store import DetectionPolicyStore
from src.policy.managed_listfile_enforcement import ManagedListfileEnforcer
from src.policy.operational_mode_store import OperationalModeStore

if TYPE_CHECKING:
    from src.config.settings import InferenceConfig
    from src.inference.pipeline import LocalInferenceOutcome

from src.inference.pipeline import (
    LocalInferencePipeline,
    build_local_inference_pipeline,
)

logger = logging.getLogger(__name__)


@dataclass
class PipelineState:
    l2: L2Stats = field(default_factory=L2Stats)
    l3: L3Stats = field(default_factory=L3Stats)
    goose: GooseStats = field(default_factory=GooseStats)
    mms: MmsStats = field(default_factory=MmsStats)


class PacketPipeline:
    def __init__(
        self,
        sensor_id: str,
        site_id: str,
        policy_path: str,
        assets_dir: str,
        tenant_id: str = "default",
        producer_version: str = "0.1.0",
        rules_enabled: list[str] | None = None,
        mqtt_host: str = "",
        mqtt_port: int = 1883,
        topic_prefix: str = "sensel/ot",
        edgex_device_name: str = "packet-sensor-features",
        edgex_data_topic: str = "",
        feature_window_sec: int = 60,
        feature_contract_id: str = "ot-window-v1",
        feature_contract_path: str = "/app/config/model/feature-contract.ot-window-v1.json",
        inference_config: "InferenceConfig | None" = None,
        ring_buffer_max_packets: int = 5000,
        ioc_enabled: bool = True,
        ioc_cache_path: str = "/app/data/agent/ioc-cache.json",
        ioc_stamp_path: str = "/app/data/agent/ioc-cache.stamp",
        ioc_cooldown_sec: int = 300,
        ioc_reload_check_sec: int = 5,
        detection_policy_path: str = "/app/data/agent/detection-policy.json",
        detection_policy_stamp_path: str = "/app/data/agent/detection-policy.stamp",
        detection_policy_reload_sec: int = 5,
        operational_mode_path: str = "/app/data/agent/operational-mode.json",
        operational_mode_stamp_path: str = "/app/data/agent/operational-mode.stamp",
        operational_mode_reload_sec: int = 5,
        baseline_profile_path: str = "/app/data/agent/baseline-profile.json",
        baseline_profile_stamp_path: str = "/app/data/agent/baseline-profile.stamp",
        managed_listfile_cache_path: str = "/app/data/managed-listfiles.json",
        managed_listfile_stamp_path: str = "/app/data/managed-listfiles.stamp",
        managed_listfile_reload_sec: float = 5.0,
        coverage_enabled: bool = True,
    ) -> None:
        self.state = PipelineState()
        self._sensor_id = sensor_id
        self._site_id = site_id
        self._tenant_id = tenant_id
        self._producer_version = producer_version
        self._feature_window_sec = feature_window_sec
        self._feature_sequence_number = 0
        self._latest_feature_sequence: FeatureSequence | None = None
        self._feature_sequence_builder: FeatureSequenceBuilder | None = None
        self._inference_pipeline: LocalInferencePipeline | None = None
        self._episode_writer: TrustEpisodeWriter | None = None
        self._emit_decisions: set[str] = set()
        self._model_runtime_status_path: Path | None = None
        self._model_episode_count = 0
        self._last_model_episode_id = ""
        self._feature_contract_id = feature_contract_id
        if inference_config is not None:
            self._model_runtime_status_path = Path(inference_config.runtime_status_path)
        try:
            feature_contract = FeatureContractSpec.load(feature_contract_path)
            if feature_contract.contract_id != feature_contract_id:
                raise ValueError(
                    "configured feature contract ID does not match contract file"
                )
            if feature_contract.frame_interval_seconds != feature_window_sec:
                raise ValueError(
                    "feature window interval does not match contract file"
                )
            self._feature_sequence_builder = FeatureSequenceBuilder(feature_contract)
            if inference_config is not None and inference_config.enabled:
                self._inference_pipeline = build_local_inference_pipeline(
                    inference_config,
                    feature_contract_id=feature_contract.contract_id,
                )
                self._episode_writer = TrustEpisodeWriter(
                    inference_config.episode_output_path
                )
                self._emit_decisions = {
                    decision.strip().lower()
                    for decision in inference_config.emit_decisions
                    if decision.strip()
                }
                self._write_model_runtime()
        except (OSError, ValueError, TypeError) as exc:
            logger.warning(
                "Feature sequence disabled; deterministic detection remains active: %s",
                exc,
            )
        self._mode_store = OperationalModeStore(
            mode_path=operational_mode_path,
            stamp_path=operational_mode_stamp_path,
            reload_check_sec=float(operational_mode_reload_sec),
        )
        self._policy_store = DetectionPolicyStore(
            policy_path=detection_policy_path,
            stamp_path=detection_policy_stamp_path,
            fallback_policy_path=policy_path,
            baseline_profile_path=baseline_profile_path,
            baseline_profile_stamp_path=baseline_profile_stamp_path,
            reload_check_sec=float(detection_policy_reload_sec),
        )
        policy = self._policy_store.policy()
        enabled = self._policy_store.rules_enabled() or set(rules_enabled or [])
        self._listfile = ManagedListfileEnforcer(
            cache_path=managed_listfile_cache_path,
            stamp_path=managed_listfile_stamp_path,
            reload_check_sec=managed_listfile_reload_sec,
        )
        self._listfile.maybe_reload(force=True)
        self._mvp = MvpDetector(
            site_id=site_id,
            sensor_id=sensor_id,
            policy=policy,
            listfile_enforcer=self._listfile,
            rules_enabled=enabled,
        )
        self._detector = Iec61850Detector(
            site_id=site_id,
            sensor_id=sensor_id,
            policy=policy,
            rules_enabled=enabled,
        )
        self._ioc: IocMatcher | None = None
        if ioc_enabled:
            from src.policy.ioc_cache import IocCacheStore

            self._ioc = IocMatcher(
                site_id=site_id,
                sensor_id=sensor_id,
                cache=IocCacheStore(
                    cache_path=Path(ioc_cache_path),
                    stamp_path=Path(ioc_stamp_path),
                    reload_check_sec=float(ioc_reload_check_sec),
                ),
                policy=policy,
                listfile_enforcer=self._listfile,
                rules_enabled=enabled,
                cooldown_sec=ioc_cooldown_sec,
            )
        self._ring = PcapRingBuffer(max_packets=ring_buffer_max_packets)
        # Passive observer for drift detection (live vs active baseline). It
        # accumulates identities seen since start; it never emits events.
        self._baseline = BaselineCollector(sensor_id=sensor_id)
        self._events = EventStore(assets_dir)
        self._coverage = CoverageCounter(
            assets_dir=assets_dir,
            sensor_id=sensor_id,
            site_id=site_id,
            enabled=coverage_enabled,
        )
        self._features = FeaturePublisher(
            sensor_id=sensor_id,
            site_id=site_id,
            output_dir=assets_dir,
            mqtt_host=mqtt_host,
            mqtt_port=mqtt_port,
            topic_prefix=topic_prefix,
            edgex_device_name=edgex_device_name,
            edgex_data_topic=edgex_data_topic,
            feature_contract_id=feature_contract_id,
        )

    def reload_detection_policy(self) -> bool:
        self._listfile.maybe_reload()
        if not self._policy_store.maybe_reload():
            return False
        policy = self._policy_store.policy()
        enabled = self._policy_store.rules_enabled()
        self._mvp.policy = policy
        if enabled:
            self._mvp.rules_enabled = enabled
        self._detector.policy = policy
        if enabled:
            self._detector.rules_enabled = enabled
        if self._ioc is not None:
            self._ioc.policy = policy
            if enabled:
                self._ioc.rules_enabled = enabled
        logger.info(
            "Detection policy reloaded version=%s rules=%s",
            self._policy_store.version,
            len(enabled),
        )
        return True

    def reload_operational_mode(self) -> bool:
        changed = self._mode_store.maybe_reload()
        if changed:
            logger.info("Operational mode reloaded mode=%s", self._mode_store.mode)
        return changed

    def _emit(self, events) -> None:
        if not self._mode_store.alerts_enabled():
            return
        for event in events:
            self._events.append(event, ring_buffer=self._ring)
            self._coverage.record(event)
            logger.warning(
                "Security event %s (%s): %s",
                event.rule_id,
                event.event_type,
                event.description,
            )

    def process(self, packet) -> None:
        self.reload_detection_policy()
        self.reload_operational_mode()
        self._listfile.maybe_reload()
        accumulate_baseline = self._mode_store.baseline_accumulation_enabled()
        try:
            packet_bytes = bytes(packet)
        except Exception:
            packet_bytes = b""
        if packet_bytes:
            self._ring.append(packet_bytes)

        src_mac, _ = parse_ethernet(packet)
        record_l2(self.state.l2, src_mac)
        src_ip, dst_ip, version = parse_ip(packet)
        record_l3(self.state.l3, src_ip, version)
        if accumulate_baseline:
            self._baseline.note_packet()
            self._baseline.feed_endpoints(src_mac, src_ip, dst_ip)

        flow = parse_transport(packet)
        if accumulate_baseline:
            if flow is not None:
                self._baseline.feed_transport(flow)
        if self._ioc:
            self._emit(
                self._ioc.evaluate(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    dst_port=flow.dst_port if flow else None,
                    protocol=flow.protocol if flow else None,
                )
            )
        obs = self._mvp.inventory.observe(
            src_mac=src_mac,
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=flow.dst_port if flow else None,
            protocol=flow.protocol if flow else None,
        )
        self._emit(self._mvp.evaluate_observation(obs))

        modbus = parse_modbus_tcp(packet)
        if modbus:
            if accumulate_baseline:
                self._baseline.feed_modbus(modbus)
            self._emit(self._mvp.evaluate_modbus(modbus))

        goose = parse_goose_packet(packet)
        if goose:
            record_goose(self.state.goose, goose)
            if accumulate_baseline:
                self._baseline.feed_goose(goose)
            self._emit(self._detector.evaluate_goose(goose))

        mms = parse_mms_packet(packet)
        if mms:
            record_mms(self.state.mms, mms)
            if accumulate_baseline:
                self._baseline.feed_mms(mms)
            self._emit(self._detector.evaluate_mms(mms))

    def flush_features(self) -> None:
        self._emit(self._mvp.evaluate_window(self._feature_window_sec))
        summary = self._features.publish_window(
            self.state.l2,
            self._feature_window_sec,
            self.state.goose,
            self.state.mms,
        )
        if self._feature_sequence_builder is not None:
            self._feature_sequence_number += 1
            try:
                sequence = self._feature_sequence_builder.add_frame(
                    entity_id=self._sensor_id,
                    observed_at=summary["timestamp"],
                    sequence_number=self._feature_sequence_number,
                    values=summary,
                )
                if sequence is not None:
                    self._latest_feature_sequence = sequence
                    self._evaluate_feature_sequence(sequence)
            except (TypeError, ValueError):
                logger.exception("Feature frame rejected by contract")
        if self._mode_store.alerts_enabled():
            self._coverage.flush()
        reset_l2_window(self.state.l2)
        reset_goose_window(self.state.goose)
        reset_mms_window(self.state.mms)

    def _evaluate_feature_sequence(self, sequence: FeatureSequence) -> None:
        if self._inference_pipeline is None or self._episode_writer is None:
            return
        outcome = self._inference_pipeline.evaluate(sequence)
        if not outcome.has_available_signal:
            self._write_model_runtime(outcome)
            logger.warning("All local model signals unavailable; Trust Episode not emitted")
            return
        if outcome.fusion.decision not in self._emit_decisions:
            self._write_model_runtime(outcome)
            return
        episode_uuid = uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"sensel:{self._tenant_id}:{self._site_id}:{self._sensor_id}:"
            f"{sequence.sequence_sha256}:{outcome.fusion.policy_version}",
        )
        operational_artifact = self._mode_store.artifact
        episode = build_trust_episode(
            episode_id=f"episode-{episode_uuid}",
            asset_id=f"sensor:{self._sensor_id}",
            tenant_id=self._tenant_id,
            site_id=self._site_id,
            sensor_id=self._sensor_id,
            sequence_number=sequence.frames[-1].sequence_number,
            trace_id=str(episode_uuid),
            producer_version=self._producer_version,
            feature_sequence=sequence,
            detections=outcome.signals,
            fusion=outcome.fusion,
            asset_identity={
                "confidence": 1.0,
                "attributes": {"identity_source": "sensor-scope"},
            },
            policy={
                "policy_id": "local-detection",
                "policy_version": outcome.fusion.policy_version,
                "operational_mode": str(
                    operational_artifact.get("mode") or "detect"
                ),
                "attributes": {"source": "local-cache"},
            },
        )
        self._episode_writer.append(episode)
        self._model_episode_count += 1
        self._last_model_episode_id = episode["episode_id"]
        self._write_model_runtime(outcome, last_episode_id=episode["episode_id"])
        logger.info(
            "Trust Episode emitted id=%s score=%.4f severity=%s",
            episode["episode_id"],
            outcome.fusion.score,
            outcome.fusion.severity,
        )

    def _write_model_runtime(
        self,
        outcome: "LocalInferenceOutcome | None" = None,
        *,
        last_episode_id: str = "",
    ) -> None:
        path = self._model_runtime_status_path
        pipeline = self._inference_pipeline
        if path is None or pipeline is None:
            return
        results = {
            result.engine_id: result.to_dict()
            for result in (outcome.results if outcome is not None else ())
        }
        models = []
        for state in pipeline.states:
            model = state.to_dict()
            if state.engine_id in results:
                model["last_result"] = results[state.engine_id]
            models.append(model)
        body = {
            "enabled": True,
            "updated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
            "feature_contract_id": self._feature_contract_id,
            "episode_count": self._model_episode_count,
            "last_episode_id": last_episode_id or self._last_model_episode_id,
            "models": models,
            "fusion": (
                {
                    "policy_version": outcome.fusion.policy_version,
                    "score": outcome.fusion.score,
                    "decision": outcome.fusion.decision,
                    "severity": outcome.fusion.severity,
                }
                if outcome is not None
                else {}
            ),
        }
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            temporary = path.with_suffix(f"{path.suffix}.tmp")
            temporary.write_text(
                json.dumps(body, indent=2, sort_keys=True),
                encoding="utf-8",
            )
            os.chmod(temporary, 0o600)
            os.replace(temporary, path)
        except OSError:
            logger.exception("Unable to persist model runtime status")

    def close(self) -> None:
        self._features.close()

    def live_baseline_snapshot(self, window_sec: float | None = None) -> dict:
        artifact = self._mode_store.artifact
        self._baseline.tenant_id = str(artifact.get("tenant_id") or "")
        self._baseline.sensor_id = self._sensor_id
        return self._baseline.to_candidate(
            source="live_observed", source_ref="live", window_sec=window_sec
        )

    @property
    def event_store(self) -> EventStore:
        return self._events

    @property
    def ring_buffer(self) -> PcapRingBuffer:
        return self._ring

    @property
    def latest_feature_sequence(self) -> FeatureSequence | None:
        return self._latest_feature_sequence
