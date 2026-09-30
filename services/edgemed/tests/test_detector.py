import unittest

import numpy as np
import pandas as pd

from app.detector import security_event, train_detector


class DetectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        rng = np.random.default_rng(7)
        cls.frame = pd.DataFrame({
            "packet_rate": rng.normal(20, 2, 200),
            "connection_rate": rng.normal(4, 0.5, 200),
            "label": "Benign",
        })
        cls.bundle = train_detector(cls.frame, "label", "Benign")

    def test_attack_like_flow_scores_higher(self):
        normal = self.bundle.score({"packet_rate": 20, "connection_rate": 4})[0]
        attack = self.bundle.score({"packet_rate": 500, "connection_rate": 90})[0]
        self.assertGreater(attack, normal)

    def test_event_is_advisory(self):
        event = security_event(
            self.bundle, "monitor-1", "patient_monitor", "idle",
            {"packet_rate": 500, "connection_rate": 90},
        )
        self.assertEqual(event["schema_version"], "0.1")
        self.assertEqual(event["response"]["mode"], "advisory_only")
        self.assertTrue(event["evidence"])


if __name__ == "__main__":
    unittest.main()
