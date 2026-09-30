from pathlib import Path

import numpy as np
import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
rng = np.random.default_rng(42)
DEVICES = [
    ("monitor-01", "patient_monitor", "session-a"),
    ("monitor-02", "patient_monitor", "session-b"),
    ("pump-01", "infusion_pump", "session-c"),
    ("gateway-01", "medical_gateway", "session-d"),
]
# 30 benign minutes + optional attack tail => enough 60s ticks for seq_len=10.
BENIGN_MINUTES = 30
ATTACK_MINUTES = 8
FLOWS_PER_TICK = 3


def _flow_row(
    timestamp: np.datetime64,
    device_id: str,
    device_type: str,
    session_id: str,
    attack: bool,
) -> dict:
    multiplier = 8 if attack else 1
    return {
        "timestamp": timestamp,
        "device_id": device_id,
        "session_id": session_id,
        "flow_duration": float(rng.lognormal(0.1, 0.7)),
        "packet_rate": float(rng.lognormal(3.2, 0.45) * multiplier),
        "byte_rate": float(rng.lognormal(9.2, 0.6) * multiplier),
        "syn_count": int(rng.poisson(2 if not attack else 28)),
        "ack_count": int(rng.poisson(8 if not attack else 2)),
        "connection_rate": float(rng.lognormal(1.3, 0.4) * multiplier),
        "mean_packet_size": float(max(40.0, rng.normal(340 if not attack else 90, 45))),
        "iat_mean": float(rng.lognormal(-2.2 if not attack else -5, 0.5)),
        "device_type": device_type,
        "operating_state": str(rng.choice(["idle", "active", "interaction"])),
        "label": "Attack" if attack else "Benign",
    }


rows: list[dict] = []
start = np.datetime64("2026-01-01T00:00:00")
for device_index, (device_id, device_type, session_id) in enumerate(DEVICES):
    device_start = start + np.timedelta64(device_index * 24 * 3600, "s")
    for minute in range(BENIGN_MINUTES):
        for flow_index in range(FLOWS_PER_TICK):
            timestamp = device_start + np.timedelta64(minute * 60 + flow_index * 15, "s")
            rows.append(_flow_row(timestamp, device_id, device_type, session_id, attack=False))
    # Put attacks only after a long benign stretch so sequence training stays contiguous.
    if device_id in {"monitor-01", "pump-01"}:
        for minute in range(ATTACK_MINUTES):
            for flow_index in range(FLOWS_PER_TICK):
                timestamp = (
                    device_start
                    + np.timedelta64((BENIGN_MINUTES + minute) * 60 + flow_index * 15, "s")
                )
                rows.append(_flow_row(timestamp, device_id, device_type, session_id, attack=True))

frame = pd.DataFrame(rows).sort_values(["device_id", "session_id", "timestamp"]).reset_index(drop=True)
path = ROOT / "data" / "sample_flows.csv"
path.parent.mkdir(parents=True, exist_ok=True)
frame.to_csv(path, index=False)
print(f"wrote {len(frame)} rows to {path}")
