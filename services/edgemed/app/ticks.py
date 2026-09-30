from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd

from .detector import numeric_feature_columns


DEFAULT_TICK_SECONDS = 60
DEFAULT_SEQ_LEN = 10
GROUP_COLUMNS = ("device_id", "session_id")


def _require_columns(frame: pd.DataFrame, columns: list[str]) -> None:
    missing = [name for name in columns if name not in frame.columns]
    if missing:
        raise ValueError(f"Missing required columns: {missing}")


def resolve_group_columns(frame: pd.DataFrame) -> list[str]:
    present = [name for name in GROUP_COLUMNS if name in frame.columns]
    if "device_id" not in present:
        raise ValueError("device_id is required to build ticks without crossing devices")
    return present


def build_ticks(
    frame: pd.DataFrame,
    *,
    timestamp_column: str = "timestamp",
    label_column: str | None = "label",
    benign_value: str = "Benign",
    tick_seconds: int = DEFAULT_TICK_SECONDS,
    feature_columns: list[str] | None = None,
) -> pd.DataFrame:
    """Aggregate flow rows into fixed-length ticks per device/session.

    Rows from different devices or sessions are never mixed. When a label column
    is present, a tick is Benign only if every flow in the window is benign.
    """
    if tick_seconds <= 0:
        raise ValueError("tick_seconds must be positive")

    group_columns = resolve_group_columns(frame)
    _require_columns(frame, [timestamp_column, *group_columns])

    features = feature_columns or numeric_feature_columns(frame, label_column)
    if not features:
        raise ValueError("No usable numeric features were found for ticks")

    work = frame.copy()
    timestamps = pd.to_datetime(work[timestamp_column], utc=True, errors="coerce")
    if timestamps.isna().any():
        raise ValueError(f"Column {timestamp_column!r} contains invalid timestamps")

    epoch = timestamps.astype("int64") // 10**9
    work["_tick_start"] = (epoch // tick_seconds) * tick_seconds
    work["_tick_end"] = work["_tick_start"] + tick_seconds

    grouped = work.groupby([*group_columns, "_tick_start", "_tick_end"], sort=True)
    ticks = grouped.agg(**{
        **{name: (name, "mean") for name in features},
        "flow_count": (features[0], "count"),
    }).reset_index()

    if label_column and label_column in work.columns:
        def _tick_label(values: pd.Series) -> str:
            normalized = values.astype(str)
            return benign_value if (normalized.str.casefold() == benign_value.casefold()).all() else "Attack"

        labels = grouped[label_column].agg(_tick_label).reset_index(name=label_column)
        ticks = ticks.merge(labels, on=[*group_columns, "_tick_start", "_tick_end"], how="left")

    ticks = ticks.rename(columns={"_tick_start": "tick_start", "_tick_end": "tick_end"})
    ticks["tick_start"] = pd.to_datetime(ticks["tick_start"], unit="s", utc=True)
    ticks["tick_end"] = pd.to_datetime(ticks["tick_end"], unit="s", utc=True)
    ticks["tick_seconds"] = tick_seconds
    return ticks.reset_index(drop=True)


def build_sequences(
    ticks: pd.DataFrame,
    *,
    feature_columns: list[str],
    seq_len: int = DEFAULT_SEQ_LEN,
    label_column: str | None = "label",
    benign_value: str = "Benign",
    benign_only: bool = False,
) -> tuple[np.ndarray, np.ndarray | None, list[dict[str, Any]]]:
    """Build sliding-window sequences that never cross device/session boundaries."""
    if seq_len < 2:
        raise ValueError("seq_len must be at least 2")
    if ticks.empty:
        raise ValueError("No ticks available to build sequences")

    group_columns = resolve_group_columns(ticks)
    _require_columns(ticks, [*feature_columns, "tick_start", *group_columns])

    sequences: list[np.ndarray] = []
    labels: list[str] = []
    meta: list[dict[str, Any]] = []

    ordered = ticks.sort_values([*group_columns, "tick_start"], kind="mergesort")
    for group_values, group in ordered.groupby(list(group_columns), sort=False):
        if not isinstance(group_values, tuple):
            group_values = (group_values,)
        values = group[feature_columns].to_numpy(dtype=np.float64)
        if len(values) < seq_len:
            continue

        group_labels = None
        if label_column and label_column in group.columns:
            group_labels = group[label_column].astype(str).to_numpy()

        for start in range(0, len(values) - seq_len + 1):
            window = values[start : start + seq_len]
            window_label = None
            if group_labels is not None:
                chunk = group_labels[start : start + seq_len]
                window_label = (
                    benign_value
                    if all(label.casefold() == benign_value.casefold() for label in chunk)
                    else "Attack"
                )
                if benign_only and window_label.casefold() != benign_value.casefold():
                    continue

            sequences.append(window)
            if window_label is not None:
                labels.append(window_label)

            row = group.iloc[start + seq_len - 1]
            meta.append({
                **{name: group_values[index] for index, name in enumerate(group_columns)},
                "tick_start": str(group.iloc[start]["tick_start"]),
                "tick_end": str(row["tick_end"]),
                "seq_len": seq_len,
                "label": window_label,
            })

    if not sequences:
        raise ValueError(
            f"No sequences of length {seq_len} could be built; "
            "need enough ticks within each device/session group"
        )

    array = np.stack(sequences).astype(np.float64)
    label_array = np.asarray(labels) if labels else None
    return array, label_array, meta
