"""Shared lab paths for Edge Sensor + EdgeMed integration."""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
EDGEMED_ROOT = REPO_ROOT / "services" / "edgemed"

PI_EDGE_ROOT = "/home/fju/sensel-ot-edge-sensor"
PI_EDGEMED_ROOT = f"{PI_EDGE_ROOT}/services/edgemed"
