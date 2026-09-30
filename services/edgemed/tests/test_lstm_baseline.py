import unittest

import numpy as np
import pandas as pd

from app.lstm_ae import lstm_security_event, train_lstm_detector
from app.ticks import build_sequences, build_ticks


def _synthetic_flows(seed: int = 11) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    rows = []
    start = np.datetime64("2026-01-01T00:00:00")
    for device_index, device_id in enumerate(["dev-a", "dev-b"]):
        for minute in range(25):
            attack = minute >= 20 and device_id == "dev-a"
            for offset in (0, 20, 40):
                rows.append({
                    "timestamp": start + np.timedelta64(device_index * 3600 + minute * 60 + offset, "s"),
                    "device_id": device_id,
                    "session_id": f"sess-{device_id}",
                    "packet_rate": float(rng.normal(80 if not attack else 400, 5)),
                    "connection_rate": float(rng.normal(6 if not attack else 40, 0.5)),
                    "byte_rate": float(rng.normal(20000 if not attack else 120000, 500)),
                    "device_type": "patient_monitor",
                    "label": "Attack" if attack else "Benign",
                })
    return pd.DataFrame(rows)


class TickSequenceTests(unittest.TestCase):
    def test_ticks_do_not_cross_devices(self):
        frame = _synthetic_flows()
        ticks = build_ticks(frame, tick_seconds=60)
        self.assertTrue({"device_id", "session_id", "tick_start", "packet_rate"} <= set(ticks.columns))
        self.assertTrue((ticks.groupby(["device_id", "session_id", "tick_start"]).size() == 1).all())
        self.assertGreaterEqual(len(ticks), 20)

    def test_sequences_stay_inside_groups(self):
        frame = _synthetic_flows()
        ticks = build_ticks(frame, tick_seconds=60)
        sequences, labels, meta = build_sequences(
            ticks,
            feature_columns=["packet_rate", "connection_rate", "byte_rate"],
            seq_len=5,
        )
        self.assertEqual(len(sequences), len(meta))
        self.assertIsNotNone(labels)
        for item in meta:
            self.assertIn(item["device_id"], {"dev-a", "dev-b"})
            self.assertEqual(item["session_id"], f"sess-{item['device_id']}")


class LSTMBaselineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.frame = _synthetic_flows()
        cls.bundle = train_lstm_detector(
            cls.frame,
            tick_seconds=60,
            seq_len=5,
            epochs=8,
            hidden_size=16,
            latent_size=8,
            batch_size=8,
        )

    def test_attack_sequence_scores_higher(self):
        ticks = build_ticks(self.frame, tick_seconds=60, feature_columns=self.bundle.features)
        sequences, labels, _ = build_sequences(
            ticks,
            feature_columns=self.bundle.features,
            seq_len=self.bundle.seq_len,
            benign_only=False,
        )
        benign = sequences[labels == "Benign"]
        attack = sequences[labels == "Attack"]
        self.assertTrue(len(benign) and len(attack))
        benign_score = self.bundle.score_sequence(benign[0])[0]
        attack_score = self.bundle.score_sequence(attack[-1])[0]
        self.assertGreaterEqual(attack_score, benign_score)

    def test_event_is_advisory_with_evidence_window(self):
        ticks = build_ticks(self.frame, tick_seconds=60, feature_columns=self.bundle.features)
        sequences, _, meta = build_sequences(
            ticks,
            feature_columns=self.bundle.features,
            seq_len=self.bundle.seq_len,
        )
        event = lstm_security_event(
            self.bundle,
            sequences[0],
            device_id=str(meta[0]["device_id"]),
            device_type="patient_monitor",
            operating_state="idle",
            window_meta=meta[0],
        )
        self.assertEqual(event["response"]["mode"], "advisory_only")
        self.assertEqual(event["detection"]["detector"], "lstm_autoencoder")
        self.assertIn("tick_start", event["detection"]["evidence_window"])
        self.assertTrue(event["evidence"])


if __name__ == "__main__":
    unittest.main()
