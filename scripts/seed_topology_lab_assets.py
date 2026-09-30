#!/usr/bin/env python3
"""Seed Lab topology assets/conduits to satisfy PRD §11.3 (≥10 assets, ≥5 conduits)."""

from __future__ import annotations

import hashlib
import json
import os
import sys
import urllib.request
from datetime import datetime, timezone
from typing import Any

BASE = os.environ.get("CONTROL_PLANE_BASE_URL", "http://192.168.1.108:8081").rstrip("/")
TENANT = os.environ.get("TENANT_ID", "company-a9ae1234648ee138")
SENSOR = os.environ.get("BASELINE_SENSOR_ID", "ot-edge-001")
SITE = os.environ.get("SITE_ID", "factory-lab-001")
INGEST_SECRET = os.environ.get("OT_SECURITY_INGEST_SECRET", "sensel-ot-ingest-lab-2026")
MIN_ASSETS = int(os.environ.get("LAB_MIN_TOPOLOGY_ASSETS", "10"))
MIN_CONDUITS = int(os.environ.get("LAB_MIN_TOPOLOGY_CONDUITS", "5"))


def _asset_id(ip: str) -> str:
    raw = f"{TENANT}|{SENSOR}|ip:{ip}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _seed_assets() -> list[dict[str, Any]]:
    specs = [
        ("192.168.10.1", "plc", "L1", ["modbus-tcp"], 0.85),
        ("192.168.10.2", "plc", "L1", ["modbus-tcp"], 0.84),
        ("192.168.10.3", "ied", "L1", ["mms"], 0.82),
        ("192.168.10.11", "hmi", "L2", ["modbus-tcp"], 0.8),
        ("192.168.10.12", "hmi", "L2", ["modbus-tcp", "s7"], 0.79),
        ("192.168.10.20", "engineering_workstation", "L3", ["s7", "rdp"], 0.77),
        ("192.168.10.30", "historian", "L3.5", ["opc-ua"], 0.76),
        ("192.168.10.40", "it_server", "L4", ["dns", "ldap"], 0.74),
        ("192.168.10.41", "it_server", "L4", ["http", "tls"], 0.73),
        ("192.168.10.60", "gateway", "L2", ["modbus-tcp", "smb"], 0.72),
    ]
    assets = []
    for ip, asset_type, purdue, protos, conf in specs:
        assets.append(
            {
                "schema": "sensel.ot_topology.asset.v1",
                "asset_id": _asset_id(ip),
                "tenant_id": TENANT,
                "sensor_id": SENSOR,
                "site_id": SITE,
                "ip": ip,
                "asset_type": asset_type,
                "purdue_level": purdue,
                "protocols": protos,
                "confidence": conf,
                "evidence_sources": ["lab_seed", "modbus_role"],
            }
        )
    return assets


def _seed_conduits(assets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_ip = {a["ip"]: a["asset_id"] for a in assets}
    pairs = [
        ("192.168.10.11", "192.168.10.1", "modbus-tcp", "L2", "L1"),
        ("192.168.10.11", "192.168.10.2", "modbus-tcp", "L2", "L1"),
        ("192.168.10.12", "192.168.10.3", "mms", "L2", "L1"),
        ("192.168.10.20", "192.168.10.1", "s7", "L3", "L1"),
        ("192.168.10.40", "8.8.8.8", "dns", "L4", "EXTERNAL"),
        ("192.168.10.11", "192.168.10.40", "ldap", "L2", "L4"),
    ]
    conduits = []
    for idx, (src_ip, dst, proto, src_lvl, dst_lvl) in enumerate(pairs, start=1):
        src_id = by_ip.get(src_ip) or _asset_id(src_ip)
        dst_ref = (
            {"kind": "external", "id": f"ext-{dst}"}
            if dst_lvl == "EXTERNAL"
            else {"kind": "asset", "id": by_ip.get(dst) or _asset_id(dst)}
        )
        conduits.append(
            {
                "schema": "sensel.ot_topology.conduit.v1",
                "conduit_id": f"lab-seed-conduit-{idx:02d}",
                "tenant_id": TENANT,
                "sensor_id": SENSOR,
                "site_id": SITE,
                "src_asset_id": src_id,
                "dst_ref": dst_ref,
                "protocol": proto,
                "src_level": src_lvl,
                "dst_level": dst_lvl,
                "baseline_status": "allowed",
                "policy_status": "review",
                "session_count": 3,
            }
        )
    return conduits


def ingest(body: dict[str, Any]) -> dict[str, Any]:
    req = urllib.request.Request(
        f"{BASE}/api/v1/internal/ot-security/topology/ingest",
        data=json.dumps(body, ensure_ascii=False).encode(),
        headers={
            "Content-Type": "application/json",
            "X-Ot-Security-Ingest-Secret": INGEST_SECRET,
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        return json.loads(resp.read().decode())


def main() -> int:
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    assets = _seed_assets()
    conduits = _seed_conduits(assets)
    zone_counts: dict[str, int] = {}
    for a in assets:
        z = str(a.get("purdue_level") or "unknown")
        zone_counts[z] = zone_counts.get(z, 0) + 1

    body = {
        "tenant_id": TENANT,
        "site_id": SITE,
        "sensor_id": SENSOR,
        "observed_at": now,
        "operational_mode": "detect",
        "assets": assets,
        "conduits": conduits,
        "external_entities": [
            {
                "entity_id": "ext-8.8.8.8",
                "ip": "8.8.8.8",
                "domain": None,
                "service_type": "dns",
                "risk": "medium",
            }
        ],
        "zone_counts": zone_counts,
    }
    print(f"==> Seed topology lab assets={len(assets)} conduits={len(conduits)} sensor={SENSOR}")
    try:
        result = ingest(body)
        print(
            f"OK  ingested assets={result.get('assets_upserted')} "
            f"conduits={result.get('conduits_upserted')} external={result.get('external_upserted')}"
        )
    except Exception as exc:
        print(f"FAIL ingest: {exc}", file=sys.stderr)
        return 1

    if len(assets) < MIN_ASSETS:
        print(f"WARN seed assets {len(assets)} < min {MIN_ASSETS}", file=sys.stderr)
    if len(conduits) < MIN_CONDUITS:
        print(f"WARN seed conduits {len(conduits)} < min {MIN_CONDUITS}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
