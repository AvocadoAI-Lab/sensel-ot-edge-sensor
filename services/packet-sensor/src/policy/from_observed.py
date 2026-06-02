"""Derive a *candidate* detection baseline from observed (learned) state.

Used during commissioning: after running in learning mode for a while, export
what was actually seen on the wire as a baseline in the SAME policy schema the
detectors consume (and that scd-to-baseline produces). The operator reviews it,
then switches to monitoring. When the engineered SCD later arrives, the two
baselines — observed vs engineered — can be reconciled.

Unlike the SCL source, observation gives us the real GOOSE *source* MAC, so the
candidate keys GOOSE on (publisher_mac, APPID).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from src.policy.from_scl import _DEFAULT_IEC_THRESHOLDS, _DEFAULT_THRESHOLDS


def derive_baseline_from_observed(
    *,
    known_ips: Iterable[str] = (),
    mac_to_ip: Mapping[str, str] | None = None,
    ip_to_mac: Mapping[str, str] | None = None,
    goose_keys: Iterable[str] = (),
    mms_pairs: Iterable[str] = (),
    site_id: str = "",
    policy_version: str = "observed-candidate",
) -> dict[str, Any]:
    assets = [{"asset_id": f"host-{ip}", "addresses": [ip]} for ip in sorted(set(known_ips))]

    # GOOSE keys are "publisher_mac|appid|gocb_ref" (see Iec61850Detector).
    goose_seen: dict[tuple[str, int], str] = {}
    for key in goose_keys:
        parts = key.split("|")
        if len(parts) != 3:
            continue
        mac, appid_s, gocb = parts
        try:
            appid = int(appid_s)
        except ValueError:
            continue
        goose_seen.setdefault((mac, appid), gocb)
    goose_publishers = [
        {
            "asset_id": "",
            "publisher_mac": mac,
            "appid": appid,
            "gocb_ref": "",
            "production": True,
            "max_silence_sec": 0.0,
        }
        for mac, appid in sorted(goose_seen)
    ]

    # MMS pairs are "client->ied:102".
    clients_by_ied: dict[str, set[str]] = {}
    for pair in mms_pairs:
        if "->" not in pair:
            continue
        client, rest = pair.split("->", 1)
        ied = rest.rsplit(":", 1)[0]
        if client and ied:
            clients_by_ied.setdefault(ied, set()).add(client)
    mms_ieds = [
        {"asset_id": "", "ied_ip": ied, "allowed_mms_clients": sorted(clients)}
        for ied, clients in sorted(clients_by_ied.items())
    ]

    return {
        "policy_version": policy_version,
        "site_id": site_id,
        "assets": assets,
        "global_allowlists": {
            "mac": [], "ip": [], "communication_pairs": [], "ports": [], "protocols": [],
        },
        "thresholds": dict(_DEFAULT_THRESHOLDS),
        "iec61850": {
            "goose_publishers": goose_publishers,
            "mms_ieds": mms_ieds,
            "thresholds": dict(_DEFAULT_IEC_THRESHOLDS),
        },
        "ioc": [],
    }


def baseline_from_state_db(db_path: str, **kwargs) -> dict[str, Any]:
    """Load a learning StateStore DB and derive the candidate baseline."""
    from src.assets.inventory import AssetInventory
    from src.assets.store import StateStore
    from src.detection.iec61850 import Iec61850Detector

    inv = AssetInventory()
    iec = Iec61850Detector(site_id="", sensor_id="", policy={})
    store = StateStore(db_path)
    store.load(inv, iec)
    store.close()
    return derive_baseline_from_observed(
        known_ips=inv.known_ips,
        mac_to_ip=inv.mac_to_ip,
        ip_to_mac=inv.ip_to_mac,
        goose_keys=iec.known_goose,
        mms_pairs=iec.known_mms_pairs,
        **kwargs,
    )
