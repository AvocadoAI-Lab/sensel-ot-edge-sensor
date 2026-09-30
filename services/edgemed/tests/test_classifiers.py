import unittest

import numpy as np
import pandas as pd

from app.classifier import evaluate_classifier, score_known_attack, train_classifier
from app.eval import compare_logreg_and_xgboost, leave_one_attack_family_out
from app.tick_buffer import DeviceTickBuffer


def _frame(seed: int = 0) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    rows = []
    for family, attack in [("benign", False), ("ddos", True), ("recon", True), ("mqtt", True)]:
        for _ in range(80):
            rows.append({
                "rate": float(rng.normal(10 if not attack else 80, 3)),
                "srate": float(rng.normal(8 if not attack else 70, 3)),
                "syn_count": float(rng.normal(1 if not attack else 20, 1)),
                "tcp": float(rng.normal(0.4 if not attack else 0.9, 0.05)),
                "label": "Benign" if not attack else family.upper(),
                "attack_family": family,
            })
    return pd.DataFrame(rows)


class ClassifierTests(unittest.TestCase):
    def test_xgboost_binary_beats_chance(self):
        frame = _frame()
        train = frame.sample(frac=0.7, random_state=1)
        test = frame.drop(train.index)
        bundle = train_classifier(train, model_name="xgboost", task="binary", calibrate=False)
        metrics = evaluate_classifier(bundle, test)
        self.assertGreater(metrics["roc_auc"], 0.8)
        self.assertEqual(bundle.metadata["model_name"], "xgboost")

    def test_logreg_category_and_comparison(self):
        frame = _frame(seed=2)
        train = frame.sample(frac=0.7, random_state=2)
        test = frame.drop(train.index)
        report = compare_logreg_and_xgboost(train, test)
        self.assertIn("logreg", report["binary"])
        self.assertIn("xgboost", report["category"])
        self.assertIn("macro_f1", report["category"]["xgboost"])

    def test_leave_one_attack_family_out_runs(self):
        frame = _frame(seed=3)
        result = leave_one_attack_family_out(frame, model_name="logreg")
        self.assertGreaterEqual(len(result["folds"]), 1)
        self.assertIn("mean_roc_auc", result)

    def test_score_known_attack_category_payload(self):
        frame = _frame(seed=4)
        train = frame.sample(frac=0.8, random_state=4)
        bundle = train_classifier(train, model_name="xgboost", task="category", calibrate=False)
        row = train.iloc[0]
        features = {name: float(row[name]) for name in bundle.features}
        payload = score_known_attack(bundle, features)
        self.assertIsNotNone(payload)
        self.assertEqual(payload["task"], "category")
        self.assertIn(payload["category"], bundle.classes)
        self.assertIn("probabilities", payload)

    def test_tick_buffer_builds_sequence(self):
        buffer = DeviceTickBuffer(maxlen=20)
        features = {"packet_rate": 1.0, "byte_rate": 2.0}
        for i in range(5):
            buffer.push(device_id="dev", session_id="s1", features={**features, "packet_rate": float(i)})
        self.assertIsNone(
            buffer.sequence_matrix(
                device_id="dev", session_id="s1", feature_names=["packet_rate", "byte_rate"], seq_len=10
            )
        )
        for i in range(5):
            buffer.push(device_id="dev", session_id="s1", features={**features, "packet_rate": float(i + 5)})
        matrix = buffer.sequence_matrix(
            device_id="dev", session_id="s1", feature_names=["packet_rate", "byte_rate"], seq_len=10
        )
        self.assertEqual(matrix.shape, (10, 2))


if __name__ == "__main__":
    unittest.main()
