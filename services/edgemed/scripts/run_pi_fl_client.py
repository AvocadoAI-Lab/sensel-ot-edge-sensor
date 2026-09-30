#!/usr/bin/env python3
"""One physical Pi FL client: local continue-training, return trees only."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import numpy as np
from xgboost import XGBClassifier

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
EDGE = Path(
    r"D:\實習\sensel-ot-edge-sensor-feat-sensel-fl-protobuf-foundation"
    r"\sensel-ot-edge-sensor-feat-sensel-fl-protobuf-foundation"
)
sys.path.insert(0, str(EDGE / "scripts"))

from app.classifier import DEFAULT_XGB_BINARY, load_classifier
from app.data.columns import load_column_map
from scripts.run_three_site_fl_experiment import (
    _align,
    _model_document,
    _tree_update_bytes,
    _uncalibrated_federation_base,
    _xgb_estimator,
    continue_binary,
    load_site_frames,
)
from _pi_reboot_bringup import connect

REMOTE = "/tmp/sensel-pi-fl"


def main() -> int:
    frames = load_site_frames(
        splits_dir=ROOT / "artifacts" / "fl-experiment" / "splits",
        dataset_root=Path(r"D:\實習\資料集"),
        mapping=load_column_map(),
        max_train=2000,
        max_test=2000,
        max_benign=3000,
        seed=20260818,
    )
    bundle = _uncalibrated_federation_base(
        load_classifier(ROOT / "artifacts" / "classifiers" / "xgboost_binary.joblib")
    )
    train = _align(frames["site-bpm"]["train"], bundle.features)
    x = bundle.preprocess.transform(train)
    y = (train["label"].astype(str).str.casefold() != "benign").astype(int).to_numpy()
    booster_json = _xgb_estimator(bundle.pipeline).get_booster().save_raw(raw_format="json")
    work = ROOT / "artifacts" / "fl-experiment" / "pi-client"
    work.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(work / "site-bpm-train.npz", x=x, y=y)
    (work / "global-booster.json").write_bytes(booster_json)
    client = connect()
    sftp = client.open_sftp()
    try:
        try:
            sftp.mkdir(REMOTE)
        except OSError:
            pass
        for name in ("site-bpm-train.npz", "global-booster.json"):
            sftp.put(str(work / name), f"{REMOTE}/{name}")
        remote_script = r"""
python3 - <<'PY'
import json, time
from pathlib import Path
import numpy as np
from xgboost import XGBClassifier
root = Path("/tmp/sensel-pi-fl")
data = np.load(root / "site-bpm-train.npz")
x, y = data["x"], data["y"]
started = time.perf_counter()
model = XGBClassifier(n_estimators=8, max_depth=6, learning_rate=0.08, subsample=0.9,
                      colsample_bytree=0.9, objective="binary:logistic", eval_metric="logloss",
                      tree_method="hist", n_jobs=2)
model.fit(x, y, xgb_model=str(root / "global-booster.json"))
elapsed = time.perf_counter() - started
raw = json.loads(model.get_booster().save_raw(raw_format="json"))
trees = raw["learner"]["gradient_booster"]["model"]["trees"][-8:]
info = raw["learner"]["gradient_booster"]["model"]["tree_info"][-8:]
payload = {"site_id": "site-bpm", "new_trees": 8, "sample_count": int(len(y)),
           "training_seconds": elapsed, "trees": trees, "tree_info": info}
(root / "update.json").write_text(json.dumps(payload), encoding="utf-8")
print(json.dumps({"ok": True, "trees": len(trees), "seconds": elapsed, "bytes": (root/"update.json").stat().st_size}))
PY
"""
        # Prefer EdgeMed venv if xgboost exists there.
        cmd = (
            "PYBIN=/home/fju/sensel-ot-edge-sensor/services/edgemed/.venv/bin/python; "
            "if [ ! -x \"$PYBIN\" ]; then PYBIN=python3; fi; "
            + remote_script.replace("python3 - <<'PY'", "$PYBIN - <<'PY'", 1)
        )
        started = time.perf_counter()
        _, stdout, stderr = client.exec_command(cmd, timeout=300)
        out = stdout.read().decode("utf-8", "replace")
        err = stderr.read().decode("utf-8", "replace")
        remote_seconds = time.perf_counter() - started
        sftp.get(f"{REMOTE}/update.json", str(work / "update.json"))
    finally:
        sftp.close()
        client.close()

    update = json.loads((work / "update.json").read_text(encoding="utf-8"))
    local = continue_binary(bundle, train, extra_trees=8, seed=20260818)
    report = {
        "role": "physical_pi_client_for_site-bpm",
        "pi_training_seconds": update.get("training_seconds"),
        "wall_including_transfer": round(remote_seconds, 6),
        "sample_count": update.get("sample_count"),
        "new_trees": update.get("new_trees"),
        "update_bytes": (work / "update.json").stat().st_size,
        "pc_equivalent_update_bytes": _tree_update_bytes(bundle, local),
        "pi_stdout": out.strip(),
        "pi_stderr": err.strip()[-1000:],
        "note": "Raw CSV stayed on PC packaging step; Pi received only transformed X/y and returned trees.",
    }
    (work / "pi-fl-client-report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    dest = Path(
        r"D:\實習\SenseLControlPlane-feat-i1-integration\SenseLControlPlane-feat-i1-integration"
        r"\artifacts\lab-validation\pi-fl-client-report.json"
    )
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if update.get("new_trees") == 8 else 1


if __name__ == "__main__":
    raise SystemExit(main())
