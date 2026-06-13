"""MITRE ATT&CK for ICS mapping keyed by SenseL OT detection rule id.

Ported from ``services/edge-console/static/core/mitreMap.js`` so the edge can
attribute raw detections to ATT&CK techniques *before* any Control-Plane
episode aggregation. Curated reference data (not live). Keep in sync with the
JS table and ``services/packet-sensor/src/detection/rules.py``.
"""

from __future__ import annotations

MITRE_ICS: dict[str, list[dict[str, str]]] = {
    "OT-001": [{"id": "T0840", "technique": "Network Connection Enumeration", "tactic": "Discovery"}],
    "OT-002": [{"id": "T0840", "technique": "Network Connection Enumeration", "tactic": "Discovery"}],
    "OT-003": [{"id": "T0830", "technique": "Adversary-in-the-Middle", "tactic": "Collection"}],
    "OT-004": [{"id": "T0840", "technique": "Network Connection Enumeration", "tactic": "Discovery"}],
    "OT-005": [{"id": "T0846", "technique": "Remote System Discovery", "tactic": "Discovery"}],
    "OT-006": [{"id": "T0846", "technique": "Remote System Discovery", "tactic": "Discovery"}],
    "OT-007": [
        {"id": "T0855", "technique": "Unauthorized Command Message", "tactic": "Impair Process Control"},
        {"id": "T0836", "technique": "Modify Parameter", "tactic": "Impair Process Control"},
    ],
    "OT-008": [{"id": "T0814", "technique": "Denial of Service", "tactic": "Inhibit Response Function"}],
    "OT-009": [{"id": "T0816", "technique": "Device Restart/Shutdown", "tactic": "Inhibit Response Function"}],
    "OT-010": [
        {"id": "T0859", "technique": "Valid Accounts", "tactic": "Lateral Movement"},
        {"id": "T0855", "technique": "Unauthorized Command Message", "tactic": "Impair Process Control"},
    ],
    "OT-011": [{"id": "T0856", "technique": "Spoof Reporting Message", "tactic": "Impair Process Control"}],
    "OT-012": [
        {"id": "T0855", "technique": "Unauthorized Command Message", "tactic": "Impair Process Control"},
        {"id": "T0856", "technique": "Spoof Reporting Message", "tactic": "Impair Process Control"},
    ],
    "OT-013": [{"id": "T0856", "technique": "Spoof Reporting Message", "tactic": "Impair Process Control"}],
    "OT-014": [
        {"id": "T0859", "technique": "Valid Accounts", "tactic": "Lateral Movement"},
        {"id": "T0855", "technique": "Unauthorized Command Message", "tactic": "Impair Process Control"},
    ],
    "OT-015": [{"id": "T0814", "technique": "Denial of Service", "tactic": "Inhibit Response Function"}],
    "OT-016": [
        {"id": "T0855", "technique": "Unauthorized Command Message", "tactic": "Impair Process Control"},
        {"id": "T0836", "technique": "Modify Parameter", "tactic": "Impair Process Control"},
    ],
    "OT-017": [
        {"id": "T0813", "technique": "Denial of Control", "tactic": "Inhibit Response Function"},
        {"id": "T0815", "technique": "Denial of View", "tactic": "Inhibit Response Function"},
    ],
    "OT-018": [
        {"id": "T0859", "technique": "Valid Accounts", "tactic": "Lateral Movement"},
        {"id": "T0855", "technique": "Unauthorized Command Message", "tactic": "Impair Process Control"},
    ],
    "OT-019": [{"id": "T0885", "technique": "Commonly Used Port", "tactic": "Command and Control"}],
}

# Keyword fallback for events without a known rule id.
KEYWORD_FALLBACK: dict[str, list[dict[str, str]]] = {
    "GOOSE": [{"id": "T0856", "technique": "Spoof Reporting Message", "tactic": "Impair Process Control"}],
    "MMS": [{"id": "T0855", "technique": "Unauthorized Command Message", "tactic": "Impair Process Control"}],
    "MODBUS": [{"id": "T0836", "technique": "Modify Parameter", "tactic": "Impair Process Control"}],
    "IOC": [{"id": "T0885", "technique": "Commonly Used Port", "tactic": "Command and Control"}],
    "SCAN": [{"id": "T0846", "technique": "Remote System Discovery", "tactic": "Discovery"}],
    "DEFAULT": [{"id": "T0840", "technique": "Network Connection Enumeration", "tactic": "Discovery"}],
}


def techniques_for(rule_id: str, event_type: str = "", description: str = "") -> list[dict[str, str]]:
    """Return ATT&CK-ICS techniques for a rule id, with keyword fallback."""
    rid = str(rule_id or "").strip().upper()
    if rid in MITRE_ICS:
        return MITRE_ICS[rid]
    blob = f"{rule_id or ''} {event_type or ''} {description or ''}".upper()
    for key in ("GOOSE", "MMS", "MODBUS", "IOC", "SCAN"):
        if key in blob:
            return KEYWORD_FALLBACK[key]
    return KEYWORD_FALLBACK["DEFAULT"]
