import unittest

from app.baseline_scorer import resolve_baseline_profile, score_baseline_features
from app.baseline_templates import load_template


class BaselineScorerTests(unittest.TestCase):
    def test_compliant_traffic_scores_low(self):
        profile = load_template("cic-template-bp-monitor-v1")
        result = score_baseline_features(
            {"rate": 10.0, "syn_count": 0.0, "ack_count": 10.0, "tcp": 10.0, "icmp": 0.0},
            profile,
        )
        self.assertTrue(result["compliant"])
        self.assertEqual(result["violations"], [])
        self.assertEqual(result["score"], 0.0)
        self.assertEqual(result["detector"], "baseline_profile")

    def test_syn_flood_violation_when_forbidden(self):
        profile = {
            "profile_id": "test-profile",
            "version": "1",
            "observed": {
                "iomt": {"forbidden_patterns": ["syn_flood", "sustained_flood"]},
                "thresholds": {"max_sustained_syn_ratio": 0.15},
            },
        }
        result = score_baseline_features(
            {"rate": 100.0, "syn_count": 90.0, "ack_count": 10.0, "tcp": 100.0, "icmp": 0.0},
            profile,
        )
        self.assertFalse(result["compliant"])
        self.assertIn("syn_flood", result["violations"])
        self.assertGreater(result["score"], 0.65)

    def test_resolve_uses_request_profile_when_present(self):
        custom = {
            "profile_id": "live-profile",
            "observed": {"iomt": {"forbidden_patterns": []}, "thresholds": {}},
        }
        resolved = resolve_baseline_profile(
            device_type="bp_monitor",
            baseline_profile=custom,
        )
        self.assertEqual(resolved["profile_id"], "live-profile")

    def test_resolve_falls_back_to_device_type_template(self):
        resolved = resolve_baseline_profile(device_type="bp_monitor")
        self.assertEqual(resolved["profile_id"], "cic-template-bp-monitor-v1")


if __name__ == "__main__":
    unittest.main()
