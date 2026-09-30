from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
import torch
from sklearn.preprocessing import RobustScaler
from torch import nn
from torch.utils.data import DataLoader, TensorDataset

from .detector import numeric_feature_columns
from .ticks import DEFAULT_SEQ_LEN, DEFAULT_TICK_SECONDS, build_sequences, build_ticks


ARTIFACT_VERSION = "0.1.0-lstm-ae"


class LSTMAutoencoder(nn.Module):
    def __init__(self, n_features: int, hidden_size: int = 32, latent_size: int = 16):
        super().__init__()
        self.encoder = nn.LSTM(n_features, hidden_size, batch_first=True)
        self.to_latent = nn.Linear(hidden_size, latent_size)
        self.from_latent = nn.Linear(latent_size, hidden_size)
        self.decoder = nn.LSTM(hidden_size, hidden_size, batch_first=True)
        self.output = nn.Linear(hidden_size, n_features)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        _, (hidden, _) = self.encoder(x)
        latent = torch.tanh(self.to_latent(hidden[-1]))
        decoded_input = self.from_latent(latent).unsqueeze(1).repeat(1, x.size(1), 1)
        decoded, _ = self.decoder(decoded_input)
        return self.output(decoded)


@dataclass
class LSTMBundle:
    model_state: dict[str, Any]
    scaler: RobustScaler
    features: list[str]
    threshold: float
    seq_len: int
    tick_seconds: int
    hidden_size: int
    latent_size: int
    metadata: dict[str, Any]

    def _model(self) -> LSTMAutoencoder:
        model = LSTMAutoencoder(len(self.features), self.hidden_size, self.latent_size)
        model.load_state_dict(self.model_state)
        model.eval()
        return model

    def reconstruction_errors(self, sequences: np.ndarray) -> np.ndarray:
        if sequences.ndim != 3 or sequences.shape[-1] != len(self.features):
            raise ValueError(
                f"Expected sequences with shape (n, {self.seq_len}, {len(self.features)})"
            )
        flat = sequences.reshape(-1, len(self.features))
        scaled = self.scaler.transform(np.nan_to_num(flat, nan=0.0, posinf=0.0, neginf=0.0))
        scaled = scaled.reshape(sequences.shape)
        tensor = torch.tensor(scaled, dtype=torch.float32)
        model = self._model()
        with torch.no_grad():
            reconstructed = model(tensor).numpy()
        return ((scaled - reconstructed) ** 2).mean(axis=(1, 2))

    def score_sequence(self, sequence: np.ndarray) -> tuple[float, float, bool, list[dict[str, Any]]]:
        errors = self.reconstruction_errors(sequence.reshape(1, self.seq_len, -1))
        raw = float(errors[0])
        scale = max(abs(self.threshold), 1e-6)
        normalized = float(1.0 / (1.0 + np.exp(-(raw - self.threshold) / scale)))
        anomalous = raw >= self.threshold

        flat = sequence.reshape(-1, len(self.features))
        scaled = self.scaler.transform(np.nan_to_num(flat, nan=0.0, posinf=0.0, neginf=0.0))
        scaled = scaled.reshape(1, self.seq_len, -1)
        model = self._model()
        with torch.no_grad():
            reconstructed = model(torch.tensor(scaled, dtype=torch.float32)).numpy()[0]
        per_feature = ((scaled[0] - reconstructed) ** 2).mean(axis=0)
        order = np.argsort(per_feature)[::-1]
        evidence = [
            {
                "feature": self.features[index],
                "reconstruction_mse": float(per_feature[index]),
                "observed_mean": float(sequence[:, index].mean()),
            }
            for index in order[:3]
        ]
        return normalized, raw, anomalous, evidence


def _device_holdout_mask(meta: list[dict[str, Any]], holdout_fraction: float = 0.2) -> np.ndarray:
    devices = sorted({str(item.get("device_id")) for item in meta})
    if len(devices) < 2:
        cut = max(1, int(len(meta) * (1.0 - holdout_fraction)))
        mask = np.zeros(len(meta), dtype=bool)
        mask[:cut] = True
        return mask

    holdout_count = max(1, int(round(len(devices) * holdout_fraction)))
    holdout = set(devices[-holdout_count:])
    return np.asarray([str(item.get("device_id")) not in holdout for item in meta], dtype=bool)


def train_lstm_detector(
    frame: pd.DataFrame,
    *,
    label_column: str | None = "label",
    benign_value: str = "Benign",
    timestamp_column: str = "timestamp",
    tick_seconds: int = DEFAULT_TICK_SECONDS,
    seq_len: int = DEFAULT_SEQ_LEN,
    hidden_size: int = 32,
    latent_size: int = 16,
    epochs: int = 25,
    batch_size: int = 32,
    learning_rate: float = 1e-3,
    threshold_quantile: float = 0.99,
    seed: int = 42,
) -> LSTMBundle:
    torch.manual_seed(seed)
    np.random.seed(seed)

    features = numeric_feature_columns(frame, label_column)
    ticks = build_ticks(
        frame,
        timestamp_column=timestamp_column,
        label_column=label_column,
        benign_value=benign_value,
        tick_seconds=tick_seconds,
        feature_columns=features,
    )
    sequences, labels, meta = build_sequences(
        ticks,
        feature_columns=features,
        seq_len=seq_len,
        label_column=label_column,
        benign_value=benign_value,
        benign_only=True,
    )
    if len(sequences) < 8:
        raise ValueError("At least 8 benign sequences are required to train the LSTM AE")

    train_mask = _device_holdout_mask(meta)
    if train_mask.sum() < 4 or (~train_mask).sum() < 1:
        train_mask = np.ones(len(sequences), dtype=bool)

    train_sequences = sequences[train_mask]
    val_sequences = sequences[~train_mask] if (~train_mask).any() else train_sequences

    scaler = RobustScaler()
    train_flat = train_sequences.reshape(-1, len(features))
    scaler.fit(np.nan_to_num(train_flat, nan=0.0, posinf=0.0, neginf=0.0))

    def _scale(batch: np.ndarray) -> np.ndarray:
        flat = np.nan_to_num(batch.reshape(-1, len(features)), nan=0.0, posinf=0.0, neginf=0.0)
        return scaler.transform(flat).reshape(batch.shape)

    train_scaled = _scale(train_sequences)
    val_scaled = _scale(val_sequences)

    dataset = TensorDataset(torch.tensor(train_scaled, dtype=torch.float32))
    loader = DataLoader(dataset, batch_size=min(batch_size, len(dataset)), shuffle=True)

    model = LSTMAutoencoder(len(features), hidden_size, latent_size)
    optimizer = torch.optim.Adam(model.parameters(), lr=learning_rate)
    loss_fn = nn.MSELoss()

    model.train()
    final_loss = 0.0
    for _ in range(epochs):
        epoch_loss = 0.0
        batches = 0
        for (batch,) in loader:
            optimizer.zero_grad()
            reconstructed = model(batch)
            loss = loss_fn(reconstructed, batch)
            loss.backward()
            optimizer.step()
            epoch_loss += float(loss.item())
            batches += 1
        final_loss = epoch_loss / max(batches, 1)

    model.eval()
    with torch.no_grad():
        val_tensor = torch.tensor(val_scaled, dtype=torch.float32)
        val_recon = model(val_tensor).numpy()
    val_errors = ((val_scaled - val_recon) ** 2).mean(axis=(1, 2))
    threshold = float(np.quantile(val_errors, threshold_quantile))

    metadata = {
        "artifact_version": ARTIFACT_VERSION,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "training_sequences": int(len(train_sequences)),
        "validation_sequences": int(len(val_sequences)),
        "benign_sequences": int(len(sequences)),
        "tick_count": int(len(ticks)),
        "label_column": label_column,
        "benign_value": benign_value,
        "threshold_quantile": threshold_quantile,
        "final_train_loss": final_loss,
        "epochs": epochs,
        "hidden_size": hidden_size,
        "latent_size": latent_size,
    }
    return LSTMBundle(
        model_state={key: value.detach().cpu() for key, value in model.state_dict().items()},
        scaler=scaler,
        features=features,
        threshold=threshold,
        seq_len=seq_len,
        tick_seconds=tick_seconds,
        hidden_size=hidden_size,
        latent_size=latent_size,
        metadata=metadata,
    )


def save_lstm_bundle(bundle: LSTMBundle, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, path)


def load_lstm_bundle(path: Path) -> LSTMBundle:
    return joblib.load(path)


def _device_type_map(frame: pd.DataFrame) -> dict[str, str]:
    if "device_id" not in frame.columns or "device_type" not in frame.columns:
        return {}
    mapping: dict[str, str] = {}
    for device_id, group in frame.groupby("device_id", sort=False):
        mode = group["device_type"].mode()
        mapping[str(device_id)] = str(mode.iloc[0] if not mode.empty else "medical_aiot")
    return mapping


def score_frame_sequences(
    bundle: LSTMBundle,
    frame: pd.DataFrame,
    *,
    timestamp_column: str = "timestamp",
    label_column: str | None = "label",
    limit: int | None = None,
) -> list[dict[str, Any]]:
    ticks = build_ticks(
        frame,
        timestamp_column=timestamp_column,
        label_column=label_column,
        tick_seconds=bundle.tick_seconds,
        feature_columns=bundle.features,
    )
    sequences, _, meta = build_sequences(
        ticks,
        feature_columns=bundle.features,
        seq_len=bundle.seq_len,
        label_column=label_column,
        benign_only=False,
    )
    if limit is not None:
        sequences = sequences[-limit:]
        meta = meta[-limit:]

    device_types = _device_type_map(frame)
    events = []
    for sequence, info in zip(sequences, meta, strict=True):
        device_id = str(info.get("device_id", "unknown-device"))
        events.append(lstm_security_event(
            bundle,
            sequence,
            device_id=device_id,
            device_type=device_types.get(device_id, "medical_aiot"),
            operating_state="unknown",
            window_meta=info,
        ))
    return events


def lstm_security_event(
    bundle: LSTMBundle,
    sequence: np.ndarray,
    *,
    device_id: str,
    device_type: str,
    operating_state: str,
    window_meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    score, raw, anomalous, evidence = bundle.score_sequence(sequence)
    severity = "high" if score >= 0.85 else "medium" if score >= 0.65 else "low"
    verdict = "anomalous" if anomalous else "baseline"
    window = window_meta or {}
    event_key = json.dumps(
        [device_id, window.get("tick_start"), window.get("tick_end"), score, raw],
        sort_keys=True,
        default=str,
    ).encode()
    event_id = "evt_" + hashlib.sha256(event_key).hexdigest()[:16]
    return {
        "schema_version": "0.1",
        "event_id": event_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "asset": {
            "device_id": device_id,
            "device_type": device_type,
            "operating_state": operating_state,
            "session_id": window.get("session_id"),
        },
        "detection": {
            "detector": "lstm_autoencoder",
            "verdict": verdict,
            "anomaly_score": round(score, 6),
            "reconstruction_error": round(raw, 6),
            "threshold_raw": round(bundle.threshold, 6),
            "model_version": bundle.metadata["artifact_version"],
            "seq_len": bundle.seq_len,
            "tick_seconds": bundle.tick_seconds,
            "evidence_window": {
                "tick_start": window.get("tick_start"),
                "tick_end": window.get("tick_end"),
            },
        },
        "evidence": evidence,
        "assessment": {
            "severity": severity,
            "summary": (
                f"{device_type} tick sequence is {verdict} versus the LSTM benign baseline "
                f"({bundle.seq_len} ticks x {bundle.tick_seconds}s)."
            ),
        },
        "response": {
            "mode": "advisory_only",
            "recommended_actions": [
                "Verify the device operating state",
                "Review the evidence window tick range",
                "Preserve relevant flow metadata",
            ] if anomalous else [],
        },
    }
