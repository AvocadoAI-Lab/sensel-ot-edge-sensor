from __future__ import annotations

import json

from src.config.settings import load_config


def test_verified_xgboost_deployment_is_loaded_after_pointer_switch(
    tmp_path, monkeypatch
) -> None:
    release_dir = tmp_path / "releases" / "release-a"
    release_dir.mkdir(parents=True)
    (release_dir / "model.onnx").write_bytes(b"onnx")
    manifest = release_dir / "deployment.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": "sensel.edge.verified-model-deployment.v1",
                "adapter": "xgboost",
                "release_id": "release-a",
                "model_id": "ot-xgb",
                "model_version": "0.1.0+site.aaaa",
                "feature_contract_id": "ot-window-v1",
                "artifact_sha256": "a" * 64,
                "model_filename": "model.onnx",
                "output_index": 1,
                "anomaly_class_index": 1,
            }
        ),
        encoding="utf-8",
    )
    current = tmp_path / "current"
    current.symlink_to(release_dir, target_is_directory=True)
    config_file = tmp_path / "sensor.yaml"
    config_file.write_text(
        "sensor:\n  id: edge-a\n  site_id: site-a\n"
        "features:\n  contract_id: ot-window-v1\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("XGB_DEPLOYMENT_MANIFEST_PATH", str(current / "deployment.json"))
    monkeypatch.delenv("XGB_ENABLED", raising=False)

    config = load_config(config_file)

    assert config.inference.xgboost.enabled is True
    assert config.inference.xgboost.model_path == str(current / "model.onnx")
    assert config.inference.xgboost.model_version == "0.1.0+site.aaaa"
    assert config.inference.xgboost.artifact_sha256 == "a" * 64

