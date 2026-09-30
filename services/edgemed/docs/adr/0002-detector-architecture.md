# ADR-0002: XGBoost and LSTM Autoencoder run in parallel

- Status: accepted for Q3 Alpha
- Date: 2026-08-02

## Decision

Use XGBoost for known-threat classification and an LSTM Autoencoder for
benign-baseline anomaly detection. They run in parallel over compatible feature
representations. A deterministic fusion layer preserves both raw outputs.

## Rationale

Tabular classification and temporal anomaly detection are different tasks. A
serial black-box pipeline would obscure errors and make calibration difficult.
Parallel detectors allow independent evaluation, degraded operation, and clear
evidence ownership.

## Consequences

- Sequence construction must not cross devices or capture sessions.
- If trustworthy sequence metadata is unavailable, the LSTM result is marked
  unavailable and Isolation Forest remains the anomaly baseline.
- The SLM cannot change detector-owned values.
