import unittest

from app.baseline_learning import (
    RESOLUTION_LIVE_LEARNING,
    build_learned_profile,
    synthesize_lab_live_candidate,
    validate_live_candidate,
)


class BaselineLearningTests(unittest.TestCase):
    def test_lab_candidate_has_no_cic_statistics(self):
        candidate = synthesize_lab_live_candidate()
        self.assertEqual(candidate["source"], "live_observed")
        self.assertEqual(validate_live_candidate(candidate), [])
        observed = candidate["observed"]
        self.assertNotIn("cic_profiling_stats", observed)
        self.assertNotIn("rate_p95_hint", observed.get("thresholds") or {})

    def test_reject_candidate_with_borrowed_rates(self):
        candidate = synthesize_lab_live_candidate()
        candidate["observed"]["thresholds"] = {"rate_p95_hint": 999}
        errors = validate_live_candidate(candidate)
        self.assertTrue(any("rate_p95_hint" in error for error in errors))

    def test_approve_produces_live_learning_profile(self):
        candidate = synthesize_lab_live_candidate()
        profile = build_learned_profile(
            candidate,
            device_type="unknown_medical_device",
            asset_id="unknown-asset-01",
            sensor_id="ot-edge-pi4",
            site_id="factory-lab-pi",
        )
        self.assertEqual(profile["stats_source"], "live_learning")
        provenance = profile["observed"]["provenance"]
        self.assertEqual(provenance["resolution"], RESOLUTION_LIVE_LEARNING)
        self.assertEqual(provenance["stats_source"], "live_learning")
        self.assertFalse(provenance["requires_local_learning"])
        self.assertEqual(profile["onboarding"]["initial_mode"], "detect")
        self.assertTrue(profile["observed"]["comm_pairs"])
        self.assertIn("vendor-cloud", profile["observed"]["iomt"]["allowed_destination_categories"])
        self.assertIn("internal_port_scan", profile["observed"]["iomt"]["forbidden_patterns"])
        self.assertIs(profile["observed"]["thresholds"]["assert_rate_thresholds"], False)
        self.assertNotIn("rate_p95_hint", profile["observed"]["thresholds"])
        self.assertNotIn("cic_profiling_stats", profile["observed"])


if __name__ == "__main__":
    unittest.main()
