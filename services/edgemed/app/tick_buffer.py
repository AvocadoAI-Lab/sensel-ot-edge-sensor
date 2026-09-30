from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any

import numpy as np


class DeviceTickBuffer:
    """In-memory per-device feature ticks for online LSTM scoring."""

    def __init__(self, maxlen: int = 64):
        self.maxlen = maxlen
        self._ticks: dict[tuple[str, str], deque[dict[str, Any]]] = defaultdict(
            lambda: deque(maxlen=maxlen)
        )

    def push(
        self,
        *,
        device_id: str,
        session_id: str | None,
        features: dict[str, float],
        timestamp: str | None = None,
    ) -> int:
        key = (device_id, session_id or "default")
        self._ticks[key].append({
            "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
            "features": dict(features),
        })
        return len(self._ticks[key])

    def sequence_matrix(
        self,
        *,
        device_id: str,
        session_id: str | None,
        feature_names: list[str],
        seq_len: int,
    ) -> np.ndarray | None:
        key = (device_id, session_id or "default")
        ticks = self._ticks.get(key)
        if not ticks or len(ticks) < seq_len:
            return None
        window = list(ticks)[-seq_len:]
        rows = []
        for tick in window:
            row = [float(tick["features"].get(name, 0.0)) for name in feature_names]
            rows.append(row)
        return np.asarray(rows, dtype=float)
