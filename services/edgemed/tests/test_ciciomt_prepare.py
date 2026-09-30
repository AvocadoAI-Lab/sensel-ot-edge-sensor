import tempfile
import unittest
from pathlib import Path

import pandas as pd

from app.data.ciciomt import (
    assert_file_manifest_reproducible,
    build_official_file_manifest,
    discover_ciciomt_csv_dirs,
    resolve_manifest_files,
)


class OfficialFileManifestTests(unittest.TestCase):
    def _touch_csvs(self, folder: Path, names: list[str]) -> list[Path]:
        folder.mkdir(parents=True, exist_ok=True)
        paths = []
        for name in names:
            path = folder / name
            pd.DataFrame({"Rate": [1.0, 2.0, 3.0], "TCP": [0.1, 0.2, 0.3]}).to_csv(path, index=False)
            paths.append(path)
        return paths

    def test_official_test_never_enters_train(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            train_dir = root / "WiFI_and_MQTTattacksCSVtrain"
            test_dir = root / "WiFI_and_MQTTattacksCSVtest"
            train_files = self._touch_csvs(train_dir, [
                "Benign_train.pcap.csv",
                "ARP_Spoofing_train.pcap.csv",
                "Recon-Port_Scan_train.pcap.csv",
                "TCP_IP-DDoS-SYN1_train.pcap.csv",
                "MQTT-DoS-Connect_Flood_train.pcap.csv",
            ])
            test_files = self._touch_csvs(test_dir, [
                "Benign_test.pcap.csv",
                "ARP_Spoofing_test.pcap.csv",
            ])
            dirs = discover_ciciomt_csv_dirs(root)
            self.assertEqual(dirs["train"].resolve(), train_dir.resolve())
            self.assertEqual(dirs["test"].resolve(), test_dir.resolve())

            manifest = build_official_file_manifest(
                train_files=train_files,
                test_files=test_files,
                seed=42,
                validation_file_ratio=0.2,
            )
            assert_file_manifest_reproducible(train_files, test_files, manifest)
            train_names = set(manifest["group_splits"]["train"])
            val_names = set(manifest["group_splits"]["validation"])
            test_names = set(manifest["group_splits"]["test"])
            self.assertTrue(test_names.isdisjoint(train_names | val_names))
            self.assertEqual(test_names, {"Benign_test.pcap.csv", "ARP_Spoofing_test.pcap.csv"})
            resolved = resolve_manifest_files(manifest, dirs)
            self.assertTrue(resolved["test"])
            self.assertTrue(all(path.name.endswith("_test.pcap.csv") for path in resolved["test"]))


if __name__ == "__main__":
    unittest.main()
