import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from app.events import EventStore
from app.fusion import fuse_detections, template_fallback_event
from app.schema import assert_detector_fields_unchanged, detector_owned_snapshot, validate_security_event


class FusionTests(unittest.TestCase):
    def test_fuse_preserves_both_detector_outputs(self):
        event = fuse_detections(
            device_id="monitor-1",
            device_type="patient_monitor",
            operating_state="idle",
            criticality="high",
            baseline={
                "compliant": True,
                "score": 0.1,
                "violations": [],
                "profile_id": "cic-template-medical-camera-v1",
                "model_version": "baseline-profile",
            },
            known_attack={
                "category": "Attack",
                "probability": 0.91,
                "model_version": "xgb-0.1.0",
            },
            anomaly={
                "score": 0.88,
                "threshold": 0.70,
                "model_version": "lstm-ae-0.1.0",
            },
            feature_evidence=[{"feature": "packet_rate", "observed": 900, "source": "detector:xgb"}],
        )
        self.assertEqual(event["schema_version"], "0.1")
        self.assertEqual(event["detection"]["status"], "ok")
        self.assertEqual(event["detection"]["baseline"]["score"], 0.1)
        self.assertEqual(event["detection"]["known_attack"]["probability"], 0.91)
        self.assertEqual(event["detection"]["anomaly"]["score"], 0.88)
        self.assertEqual(event["assessment"]["severity_source"], "fusion-policy-0.1")
        self.assertEqual(event["response"]["mode"], "advisory_only")
        self.assertFalse(validate_security_event(event))

    def test_baseline_violation_verdict(self):
        event = fuse_detections(
            device_id="gateway-1",
            device_type="medical_gateway",
            operating_state="idle",
            baseline={
                "compliant": False,
                "score": 0.9,
                "violations": ["syn_flood"],
                "profile_id": "live-profile",
                "model_version": "baseline-profile",
            },
            known_attack={"category": "Benign", "probability": 0.2, "model_version": "xgb"},
            anomaly={"score": 0.1, "threshold": 0.7, "model_version": "if"},
        )
        self.assertEqual(event["assessment"]["verdict"], "policy_violation_suspected")
        self.assertEqual(event["detection"]["status"], "ok")

    def test_partial_detection_and_disagreement(self):
        partial = fuse_detections(
            device_id="pump-1",
            device_type="infusion_pump",
            operating_state="active",
            known_attack={"category": "Attack", "probability": 0.9, "model_version": "xgb"},
            anomaly=None,
        )
        self.assertEqual(partial["detection"]["status"], "partial_detection")

        disagreed = fuse_detections(
            device_id="pump-1",
            device_type="infusion_pump",
            operating_state="active",
            known_attack={"category": "Attack", "probability": 0.92, "model_version": "xgb"},
            anomaly={"score": 0.1, "threshold": 0.7, "model_version": "if"},
        )
        self.assertTrue(disagreed["detection"]["disagreement"])

    def test_all_detectors_unavailable_raises(self):
        with self.assertRaises(ValueError) as ctx:
            fuse_detections(
                device_id="x",
                device_type="medical_aiot",
                operating_state="unknown",
                baseline=None,
                known_attack=None,
                anomaly=None,
            )
        self.assertIn("All detectors unavailable", str(ctx.exception))

    def test_detector_owned_fields_are_immutable(self):
        event = template_fallback_event(
            device_id="gateway-1",
            device_type="medical_gateway",
            operating_state="idle",
            reason="slm_invalid",
            anomaly={"score": 0.8, "threshold": 0.5, "model_version": "if"},
        )
        before = detector_owned_snapshot(event)
        mutated = {
            **event,
            "detection": {
                **event["detection"],
                "anomaly": {"score": 0.01, "threshold": 0.5, "model_version": "if"},
            },
        }
        with self.assertRaises(ValueError):
            assert_detector_fields_unchanged(
                {"detection": before["detection"], "evidence": before["evidence"]},
                mutated,
            )

    def test_fuse_preserves_category_and_parallel_anomalies(self):
        event = fuse_detections(
            device_id="monitor-2",
            device_type="patient_monitor",
            operating_state="idle",
            known_attack={
                "category": "ddos",
                "probability": 0.88,
                "task": "category",
                "model_version": "xgb-cat",
            },
            anomalies={
                "isolation_forest": {
                    "score": 0.4,
                    "threshold": 0.7,
                    "detector": "isolation_forest",
                    "model_version": "if",
                },
                "lstm_autoencoder": {
                    "score": 0.86,
                    "threshold": 0.7,
                    "detector": "lstm_autoencoder",
                    "model_version": "lstm",
                },
            },
        )
        self.assertEqual(event["detection"]["anomaly"]["detector"], "lstm_autoencoder")
        self.assertEqual(event["detection"]["anomalies"]["isolation_forest"]["score"], 0.4)
        self.assertEqual(event["assessment"]["taxonomy"], "ddos")


class EventStoreTests(unittest.TestCase):
    def test_save_get_related(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = EventStore(Path(tmp) / "events.jsonl")
            first = fuse_detections(
                device_id="dev-a",
                device_type="patient_monitor",
                operating_state="idle",
                anomaly={"score": 0.9, "threshold": 0.5, "model_version": "if"},
            )
            second = fuse_detections(
                device_id="dev-a",
                device_type="patient_monitor",
                operating_state="idle",
                anomaly={"score": 0.2, "threshold": 0.5, "model_version": "if"},
            )
            store.save(first)
            store.save(second)
            self.assertEqual(store.get(first["event_id"])["event_id"], first["event_id"])
            related = store.related(device_id="dev-a", exclude_event_id=second["event_id"])
            self.assertEqual(len(related), 1)
            self.assertEqual(related[0]["event_id"], first["event_id"])


class ApiFusionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from app.main import app
        cls.client = TestClient(app)

    def test_health_lists_components(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["mode"], "advisory_only")
        self.assertIn("isolation_forest", payload["components"])
        self.assertIn("xgboost_category", payload["components"])
        self.assertIn("lstm_autoencoder", payload["components"])


if __name__ == "__main__":
    unittest.main()
