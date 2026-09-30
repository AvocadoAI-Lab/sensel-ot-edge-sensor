"""Baseline learning — derive a detection baseline from observed traffic.

The collector reuses the existing L2/L3/L7 parsers to accumulate observations
of GOOSE publishers, MMS IED↔client pairs and Modbus servers, then serialises
a *candidate* baseline whose ``iec61850`` block matches the schema the
detector already consumes (see ``config/policy/baseline.example.json``).
"""

from src.baseline.collector import BaselineCollector

__all__ = ["BaselineCollector"]
