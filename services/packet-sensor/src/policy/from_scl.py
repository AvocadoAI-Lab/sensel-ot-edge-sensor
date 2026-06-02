"""Derive a detection baseline policy from a parsed SCD/SCL model.

Produces exactly the policy structure the existing detectors consume (see
config/policy/baseline.example.json and policy/schema.py), so nothing downstream
changes — only the *source of truth* moves from hand-authored JSON to the
engineered substation file.

Key mapping decisions (see parser/scl/scd.py):
- GOOSE is matched on **APPID** (authoritative + wire-observable). The SCL
  MAC-Address is the destination multicast, not the publisher source MAC, so
  ``publisher_mac`` is left blank and not used as a match key.
- ``max_silence_sec`` for OT-017 is derived from the GSE MaxTime keep-alive
  (× silence_factor); a publisher with no MaxTime gets 0 (silence check off).
- MMS servers are IEDs exposing a Server; allowed MMS clients default to the
  non-server IED endpoints (HMI/SCADA) — a sensible engineered starting point
  the operator can tighten.
"""

from __future__ import annotations

from typing import Any

from src.parser.scl.scd import ScdModel, parse_scd

_DEFAULT_THRESHOLDS = {
    "port_scan_unique_ports": 10,
    "port_scan_window_sec": 60,
    "traffic_rate_multiplier": 3.0,
}
_DEFAULT_IEC_THRESHOLDS = {
    "goose_stnum_jump_max": 100,
    "mms_new_sessions_per_min": 20,
}


def derive_baseline(
    model: ScdModel,
    *,
    site_id: str = "",
    policy_version: str = "scd-derived",
    silence_factor: float = 4.0,
) -> dict[str, Any]:
    client_ips = sorted({ied.ip for ied in model.ieds if ied.ip and not ied.has_server})

    assets: list[dict[str, Any]] = []
    for ied in model.ieds:
        if not ied.ip:
            continue
        assets.append({"asset_id": ied.ied_name, "addresses": [ied.ip]})

    goose_publishers: list[dict[str, Any]] = []
    for g in model.goose:
        if g.appid is None:
            continue  # cannot match without an APPID
        if g.max_time_ms:
            max_silence = round(g.max_time_ms / 1000.0 * silence_factor, 1)
        else:
            max_silence = 0.0
        goose_publishers.append(
            {
                "asset_id": g.ied_name,
                "publisher_mac": "",  # SCL MAC is the multicast dest, not source
                "appid": g.appid,
                "gocb_ref": "",       # match on APPID only
                "production": True,
                "max_silence_sec": max_silence,
            }
        )

    mms_ieds: list[dict[str, Any]] = []
    for ied in model.servers():
        mms_ieds.append(
            {
                "asset_id": ied.ied_name,
                "ied_ip": ied.ip,
                "allowed_mms_clients": list(client_ips),
            }
        )

    return {
        "policy_version": policy_version,
        "site_id": site_id,
        "assets": assets,
        "global_allowlists": {
            "mac": [],
            "ip": [],
            "communication_pairs": [],
            "ports": [],
            "protocols": [],
        },
        "thresholds": dict(_DEFAULT_THRESHOLDS),
        "iec61850": {
            "goose_publishers": goose_publishers,
            "mms_ieds": mms_ieds,
            "thresholds": dict(_DEFAULT_IEC_THRESHOLDS),
        },
        "ioc": [],
    }


def baseline_from_scd(path, **kwargs) -> dict[str, Any]:
    """Convenience: parse an SCD file and derive the baseline in one call."""
    return derive_baseline(parse_scd(path), **kwargs)
