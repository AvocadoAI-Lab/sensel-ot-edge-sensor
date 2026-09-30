import unittest

from app.fusion import fuse_detections
from app.sft import generate_sft_dataset, write_sft_splits
from app.slm import apply_slm_to_event, hard_grounding_errors, template_slm_output, validate_slm_output


class SlmGuardrailTests(unittest.TestCase):
    def test_template_output_is_valid(self):
        event = fuse_detections(
            device_id="m1",
            device_type="patient_monitor",
            operating_state="idle",
            known_attack={"category": "Attack", "probability": 0.9, "model_version": "xgb"},
            anomaly={"score": 0.8, "threshold": 0.7, "model_version": "if"},
            feature_evidence=[{"feature": "packet_rate", "observed": 10, "source": "detector:xgb"}],
        )
        output = template_slm_output(event)
        self.assertEqual(validate_slm_output(output, event), [])

    def test_unknown_evidence_id_triggers_fallback(self):
        event = fuse_detections(
            device_id="m1",
            device_type="patient_monitor",
            operating_state="idle",
            anomaly={"score": 0.8, "threshold": 0.7, "model_version": "if"},
            feature_evidence=[{"feature": "packet_rate", "observed": 10, "source": "detector:if"}],
        )
        bad = {
            "summary_en": "Invented evidence",
            "taxonomy": "network_behavior_anomaly",
            "evidence_ids": ["ev_does_not_exist"],
            "retrieval_intents": ["asset_context"],
            "status": "ok",
        }
        updated = apply_slm_to_event(event, bad)
        self.assertEqual(updated["assessment"]["generation_status"], "template_fallback")
        self.assertEqual(updated["assessment"]["summary_source"], "template_fallback")
        self.assertTrue(
            any("unknown evidence_id" in err for err in updated["assessment"]["slm_validation_errors"])
        )
        self.assertEqual(updated["detection"]["anomaly"]["score"], 0.8)

    def test_ungrounded_ip_triggers_fallback(self):
        event = fuse_detections(
            device_id="m1",
            device_type="patient_monitor",
            operating_state="idle",
            anomaly={"score": 0.8, "threshold": 0.7, "model_version": "if"},
            feature_evidence=[{"feature": "packet_rate", "observed": 10, "source": "detector:if"}],
        )
        evidence_ids = [item["evidence_id"] for item in event["evidence"]]
        bad = {
            "summary_en": "Attack from 203.0.113.50 targeting the ward gateway.",
            "taxonomy": "network_behavior_anomaly",
            "evidence_ids": evidence_ids,
            "retrieval_intents": ["asset_context"],
            "status": "ok",
        }
        self.assertTrue(any("ungrounded ipv4" in e for e in hard_grounding_errors(bad, event)))
        updated = apply_slm_to_event(event, bad)
        self.assertEqual(updated["assessment"]["generation_status"], "template_fallback")

    def test_disagreement_requires_conflict_abstention(self):
        event = fuse_detections(
            device_id="m1",
            device_type="patient_monitor",
            operating_state="idle",
            criticality="high",
            known_attack={"category": "dos", "probability": 0.95, "model_version": "xgb"},
            anomaly={"score": 0.1, "threshold": 0.7, "model_version": "if", "anomalous": False},
            feature_evidence=[{"feature": "packet_rate", "observed": 10, "source": "detector:xgb"}],
        )
        self.assertTrue(event["detection"]["disagreement"])
        template = template_slm_output(event)
        self.assertEqual(template["taxonomy"], "detector_conflict")
        self.assertEqual(template["status"], "conflict")
        self.assertIn("disagree", template["summary_en"].lower())

        confident = {
            "summary_en": "Clear dos attack confirmed.",
            "taxonomy": "known_attack_suspected",
            "evidence_ids": [item["evidence_id"] for item in event["evidence"]],
            "retrieval_intents": ["threat_context"],
            "status": "ok",
        }
        updated = apply_slm_to_event(event, confident)
        self.assertEqual(updated["assessment"]["generation_status"], "template_fallback")
        self.assertEqual(updated["assessment"]["taxonomy"], "detector_conflict")
        self.assertEqual(updated["assessment"]["slm_status"], "conflict")

    def test_compliant_generated_output_accepted(self):
        event = fuse_detections(
            device_id="m1",
            device_type="patient_monitor",
            operating_state="idle",
            known_attack={"category": "dos", "probability": 0.95, "model_version": "xgb"},
            anomaly={"score": 0.9, "threshold": 0.7, "model_version": "if"},
            feature_evidence=[{"feature": "packet_rate", "observed": 10, "source": "detector:xgb"}],
        )
        good = {
            "summary_en": (
                "patient_monitor event is assessed as suspected_attack using only supplied "
                "detector evidence. Severity remains policy-owned; no detector scores were modified."
            ),
            "taxonomy": "known_attack_suspected",
            "evidence_ids": [item["evidence_id"] for item in event["evidence"]],
            "retrieval_intents": ["asset_context", "playbook_lookup"],
            "status": "ok",
        }
        updated = apply_slm_to_event(event, good)
        self.assertEqual(updated["assessment"]["generation_status"], "generated")
        self.assertNotEqual(updated["assessment"]["summary_source"], "template_fallback")

    def test_sft_test_has_enough_negatives(self):
        import tempfile
        from pathlib import Path

        splits = generate_sft_dataset(records_per_kind=10, seed=1)
        with tempfile.TemporaryDirectory() as tmp:
            report = write_sft_splits(splits, Path(tmp))
            self.assertGreaterEqual(report["negative_ratio_test"], 0.30)
            self.assertGreater(report["counts"]["test"], 0)


if __name__ == "__main__":
    unittest.main()
