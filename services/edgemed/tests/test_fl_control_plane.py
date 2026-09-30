from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.fl_control_plane import federation_artifact_uri, publish_global_model


def test_federation_artifact_uri() -> None:
    assert federation_artifact_uri("lab-round-001") == "file://federation/lab-round-001.joblib"


def test_publish_global_model(tmp_path: Path) -> None:
    source = tmp_path / "source.joblib"
    source.write_bytes(b"round-model")
    dest_dir = tmp_path / "cp-store"
    uri, size = publish_global_model(
        source,
        round_id="lab-round-001",
        cp_artifacts_dir=dest_dir,
    )
    assert uri == "file://federation/lab-round-001.joblib"
    assert size == len(b"round-model")
    published = dest_dir / "lab-round-001.joblib"
    assert published.is_file()
    assert published.read_bytes() == b"round-model"


def test_publish_global_model_skips_without_destination(tmp_path: Path) -> None:
    source = tmp_path / "source.joblib"
    source.write_bytes(b"x")
    assert publish_global_model(source, round_id="lab-round-002", cp_artifacts_dir=None) == (
        None,
        None,
    )
