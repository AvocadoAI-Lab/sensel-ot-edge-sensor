import json
import tempfile
import unittest
from pathlib import Path

import numpy as np
import pandas as pd

from app.data import (
    apply_manifest,
    assert_manifest_reproducible,
    audit_frame,
    build_manifest,
    fit_preprocessor,
    inventory_dataset,
    is_leakage_column,
    leakage_hits,
)
from app.data.columns import apply_column_mapping
from app.data.inventory import infer_attack_family


def _frame() -> pd.DataFrame:
    rows = []
    for device_index, device_id in enumerate(["dev-a", "dev-b", "dev-c", "dev-d"]):
        for minute in range(20):
            attack = device_id == "dev-d" and minute >= 15
            label = "DDoS SYN" if attack else "Benign"
            rows.append({
                "timestamp": f"2026-01-01T00:{minute:02d}:00Z",
                "device_id": device_id,
                "session_id": f"sess-{device_id}",
                "source_file": f"{device_id}.csv",
                "packet_rate": 20 + device_index + (200 if attack else 0),
                "connection_rate": 4 + (30 if attack else 0),
                "byte_rate": 1000 + (50000 if attack else 0),
                "src_ip": "10.0.0.1",
                "label": label,
                "attack_family": infer_attack_family(label),
            })
    return pd.DataFrame(rows)


class LeakageAndMappingTests(unittest.TestCase):
    def test_leakage_denylist(self):
        self.assertTrue(is_leakage_column("Src IP"))
        self.assertTrue(is_leakage_column("capture_id"))
        self.assertFalse(is_leakage_column("packet_rate"))
        self.assertEqual(leakage_hits(["packet_rate", "dst_ip", "label"]), ["dst_ip", "label"])

    def test_column_mapping_normalizes_aliases(self):
        mapping = apply_column_mapping(["Header Length", "Protocol Type", "AVG"])
        self.assertEqual(mapping["Header Length"], "header_length")
        self.assertEqual(mapping["Protocol Type"], "protocol_type")
        self.assertEqual(mapping["AVG"], "avg_packet_size")


class ManifestTests(unittest.TestCase):
    def test_manifest_is_reproducible(self):
        frame = _frame()
        first = build_manifest(frame, strategy="device_holdout", seed=7)
        second = build_manifest(frame, strategy="device_holdout", seed=7)
        self.assertEqual(first["membership_sha256"], second["membership_sha256"])
        self.assertEqual(first["splits"], second["splits"])
        assert_manifest_reproducible(frame, first)

    def test_device_holdout_does_not_share_devices(self):
        frame = _frame()
        manifest = build_manifest(frame, strategy="device_holdout", seed=3)
        splits = apply_manifest(frame, manifest)
        train_devices = set(splits["train"]["device_id"])
        test_devices = set(splits["test"]["device_id"])
        self.assertTrue(train_devices.isdisjoint(test_devices))

    def test_session_aware_does_not_share_sessions(self):
        frame = _frame()
        manifest = build_manifest(frame, strategy="session_aware", seed=5)
        splits = apply_manifest(frame, manifest)
        train_sessions = set(splits["train"]["session_id"])
        test_sessions = set(splits["test"]["session_id"])
        self.assertTrue(train_sessions.isdisjoint(test_sessions))


class PreprocessTests(unittest.TestCase):
    def test_preprocessor_fit_only_on_train(self):
        frame = _frame()
        manifest = build_manifest(frame, strategy="device_holdout", seed=11)
        splits = apply_manifest(frame, manifest)
        train_bundle = fit_preprocessor(splits["train"], label_column="label")
        all_bundle = fit_preprocessor(frame, label_column="label")

        train_center = train_bundle.pipeline.named_steps["scaler"].center_
        all_center = all_bundle.pipeline.named_steps["scaler"].center_
        self.assertFalse(np.allclose(train_center, all_center))

        transformed = train_bundle.transform(splits["test"])
        self.assertEqual(transformed.shape[1], len(train_bundle.features))
        self.assertNotIn("src_ip", train_bundle.features)
        self.assertNotIn("label", train_bundle.features)

    def test_audit_reports_leakage_and_quality(self):
        frame = _frame()
        report = audit_frame(frame, label_column="label")
        self.assertIn("src_ip", report["leakage_columns_present"])
        self.assertGreater(report["row_count"], 0)
        self.assertIn("packet_rate", report["usable_numeric_features"])


class InventoryTests(unittest.TestCase):
    def test_inventory_hashes_csv(self):
        frame = _frame()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            csv_path = root / "Benign_train.csv"
            frame.to_csv(csv_path, index=False)
            payload = inventory_dataset(root)
            self.assertEqual(payload["csv_count"], 1)
            self.assertEqual(payload["files"][0]["inferred_label"], "Benign")
            self.assertEqual(len(payload["files"][0]["sha256"]), 64)

    def test_infer_label_strips_pcap_csv(self):
        from app.data.inventory import infer_attack_family, infer_label_from_filename
        label = infer_label_from_filename(Path("Benign_train.pcap.csv"))
        self.assertEqual(label, "Benign")
        self.assertEqual(infer_attack_family(label), "benign")
        self.assertEqual(
            infer_attack_family(infer_label_from_filename(Path("TCP_IP-DDoS-SYN1_train.pcap.csv"))),
            "ddos",
        )


if __name__ == "__main__":
    unittest.main()
