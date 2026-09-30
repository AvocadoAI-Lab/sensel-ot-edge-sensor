import unittest

from app.fusion import fuse_detections
from app.rag import ALLOWED_TOOLS, KnowledgeBase, ReadOnlyToolBelt, build_default_orchestrator
from app.rag.orchestrator import DeterministicOrchestrator
from app.rag.tools import sanitize_untrusted_claim_text
from app.slm import apply_slm_to_event


class RagOrchestratorTests(unittest.TestCase):
    def setUp(self):
        self.events = [
            {
                "event_id": "evt_hist_1",
                "timestamp": "2026-08-01T12:00:00+00:00",
                "asset": {"device_id": "monitor-1"},
                "assessment": {
                    "verdict": "anomalous",
                    "severity": "high",
                    "taxonomy": "network_behavior_anomaly",
                },
            }
        ]
        self.rag = build_default_orchestrator(
            related_events_provider=lambda device_id, limit=5: self.events[:limit]
        )

    def test_allowlist_rejects_unknown_tool(self):
        tools = ReadOnlyToolBelt(KnowledgeBase(), related_events_provider=lambda **_: [])
        result = tools.call("run_shell", {"cmd": "whoami"})
        self.assertFalse(result.ok)
        self.assertIn("not allowlisted", result.error or "")
        self.assertIn("get_asset_profile", ALLOWED_TOOLS)

    def test_orchestrator_returns_sourced_claims_only(self):
        event = fuse_detections(
            device_id="monitor-1",
            device_type="patient_monitor",
            operating_state="idle",
            criticality="high",
            known_attack={"category": "Attack", "probability": 0.91, "model_version": "xgb"},
            anomaly={"score": 0.84, "threshold": 0.7, "model_version": "if"},
            feature_evidence=[{"feature": "packet_rate", "observed": 800, "source": "detector:xgb"}],
        )
        event = apply_slm_to_event(event)
        enriched = self.rag.apply(event)
        self.assertEqual(enriched["detection"]["anomaly"]["score"], 0.84)
        self.assertLessEqual(enriched["enrichment"]["retrieval_count"], 5)
        self.assertTrue(enriched["enrichment"]["sources"])
        for claim in enriched["enrichment"]["claims"]:
            self.assertIn(claim["source_id"], {item["source_id"] for item in enriched["enrichment"]["sources"]})
            self.assertIn("claim_type", claim)

    def test_slm_cannot_force_arbitrary_tool(self):
        event = fuse_detections(
            device_id="monitor-1",
            device_type="patient_monitor",
            operating_state="idle",
            anomaly={"score": 0.8, "threshold": 0.7, "model_version": "if"},
            feature_evidence=[{"feature": "packet_rate", "observed": 10, "source": "detector:if"}],
        )
        event = {
            **event,
            "enrichment": {
                "status": "pending_rag",
                "retrieval_intents": ["run_shell", "exfiltrate", "asset_context"],
                "sources": [],
            },
        }
        result = self.rag.investigate(event)
        tools_used = [item.tool for item in result.audit]
        self.assertNotIn("run_shell", tools_used)
        self.assertTrue(all(tool in ALLOWED_TOOLS for tool in tools_used))

    def test_threat_query_prefers_known_attack_category(self):
        event = fuse_detections(
            device_id="monitor-1",
            device_type="patient_monitor",
            operating_state="idle",
            known_attack={"category": "dos", "probability": 0.99, "model_version": "xgb"},
            anomaly={"score": 0.1, "threshold": 0.7, "model_version": "if"},
            feature_evidence=[{"feature": "packet_rate", "observed": 10, "source": "detector:xgb"}],
        )
        event = apply_slm_to_event(event)
        # Conflict path often yields detector_conflict taxonomy; query must still use dos.
        self.assertEqual(event["assessment"]["taxonomy"], "detector_conflict")
        query = DeterministicOrchestrator._threat_query(event)
        self.assertIn("dos", query.casefold())
        self.assertNotIn("detector_conflict", query.casefold())

        result = self.rag.investigate(event)
        threat_sources = [
            s["source_id"] for s in result.sources if s["source_id"].startswith("threat:")
        ]
        self.assertTrue(threat_sources)
        self.assertIn("threat:mqtt-publish-flood", threat_sources)

    def test_related_event_claims_include_timeline_fields(self):
        event = fuse_detections(
            device_id="monitor-1",
            device_type="patient_monitor",
            operating_state="idle",
            anomaly={"score": 0.9, "threshold": 0.7, "model_version": "if"},
            feature_evidence=[{"feature": "packet_rate", "observed": 10, "source": "detector:if"}],
        )
        event = apply_slm_to_event(event)
        enriched = self.rag.apply(event)
        related = [
            c for c in enriched["enrichment"]["claims"] if c.get("claim_type") == "related_event"
        ]
        self.assertTrue(related)
        claim = related[0]
        self.assertEqual(claim["event_id"], "evt_hist_1")
        self.assertEqual(claim["timestamp"], "2026-08-01T12:00:00+00:00")
        self.assertEqual(claim["verdict"], "anomalous")
        self.assertEqual(claim["severity"], "high")
        self.assertIn("2026-08-01", claim["claim"])
        self.assertIn("verdict=anomalous", claim["claim"])

    def test_rag_failure_does_not_overwrite_slm_generation_status(self):
        event = fuse_detections(
            device_id="monitor-1",
            device_type="patient_monitor",
            operating_state="idle",
            anomaly={"score": 0.8, "threshold": 0.7, "model_version": "if"},
            feature_evidence=[{"feature": "packet_rate", "observed": 10, "source": "detector:if"}],
        )
        event = apply_slm_to_event(event)
        self.assertEqual(event["assessment"]["generation_status"], "template_fallback")

        def failing_call(tool_name, arguments):
            from app.rag.tools import ToolResult

            return ToolResult(tool_name, False, [], {}, error="injected_failure")

        original = self.rag.tools.call
        self.rag.tools.call = failing_call  # type: ignore[method-assign]
        try:
            updated = self.rag.apply(event)
        finally:
            self.rag.tools.call = original  # type: ignore[method-assign]

        self.assertEqual(updated["enrichment"]["status"], "enrichment_unavailable")
        self.assertEqual(updated["assessment"]["generation_status"], "template_fallback")

    def test_untrusted_claim_text_strips_action_language(self):
        cleaned = sanitize_untrusted_claim_text(
            "Isolate the device and block the firewall.",
            source_id="playbook:bad",
        )
        self.assertIn("omitted", cleaned.casefold())
        self.assertNotIn("isolate", cleaned.casefold())


if __name__ == "__main__":
    unittest.main()
