<<<<<<< Updated upstream
"""
Detection rule registry — maps to PRD section 15.2 and S1-02b IEC 61850.

MVP OT-001 ~ OT-010 (Sprint 2)
IEC 61850 OT-011 ~ OT-018 (S1-02b)
"""

RULES = [
    {"id": "OT-001", "name": "New MAC detected", "severity": "medium"},
    {"id": "OT-002", "name": "New IP detected", "severity": "medium"},
    {"id": "OT-003", "name": "MAC/IP mapping changed", "severity": "high"},
    {"id": "OT-004", "name": "New communication pair", "severity": "medium"},
    {"id": "OT-005", "name": "New destination port", "severity": "medium"},
    {"id": "OT-006", "name": "Port scan behavior", "severity": "high"},
    {"id": "OT-007", "name": "Unexpected Modbus write", "severity": "high"},
    {"id": "OT-008", "name": "Abnormal traffic rate", "severity": "medium"},
    {"id": "OT-009", "name": "Relay offline", "severity": "high"},
    {"id": "OT-010", "name": "Unauthorized host accessing relay", "severity": "high"},
]

IEC61850_RULES = [
    {"id": "OT-011", "name": "New GOOSE publisher", "severity": "medium"},
    {"id": "OT-012", "name": "GOOSE test bit in production", "severity": "high"},
    {"id": "OT-013", "name": "GOOSE stNum anomaly", "severity": "medium"},
    {"id": "OT-014", "name": "New MMS client to IED", "severity": "medium"},
    {"id": "OT-015", "name": "MMS session rate anomaly", "severity": "medium"},
    {"id": "OT-016", "name": "Unexpected MMS write", "severity": "high"},
    {"id": "OT-017", "name": "GOOSE silence (IED offline)", "severity": "high"},
    {"id": "OT-018", "name": "Unauthorized MMS to relay IED", "severity": "high"},
]

CTI_RULES = [
    {"id": "OT-019", "name": "CTI IOC observed", "severity": "high"},
]
=======
"""
Detection rule registry — maps to PRD section 15.2 and S1-02b IEC 61850.

MVP OT-001 ~ OT-010 (Sprint 2)
IEC 61850 OT-011 ~ OT-018 (S1-02b)
"""

RULES = [
    {"id": "OT-001", "name": "New MAC detected", "severity": "medium"},
    {"id": "OT-002", "name": "New IP detected", "severity": "medium"},
    {"id": "OT-003", "name": "MAC/IP mapping changed", "severity": "high"},
    {"id": "OT-004", "name": "New communication pair", "severity": "medium"},
    {"id": "OT-005", "name": "New destination port", "severity": "medium"},
    {"id": "OT-006", "name": "Port scan behavior", "severity": "high"},
    {"id": "OT-007", "name": "Unexpected Modbus write", "severity": "high"},
    {"id": "OT-008", "name": "Abnormal traffic rate", "severity": "medium"},
    {"id": "OT-009", "name": "Relay offline", "severity": "high"},
    {"id": "OT-010", "name": "Unauthorized host accessing relay", "severity": "high"},
]

IEC61850_RULES = [
    {"id": "OT-011", "name": "New GOOSE publisher", "severity": "medium"},
    {"id": "OT-012", "name": "GOOSE test bit in production", "severity": "high"},
    {"id": "OT-013", "name": "GOOSE stNum anomaly", "severity": "medium"},
    {"id": "OT-014", "name": "New MMS client to IED", "severity": "medium"},
    {"id": "OT-015", "name": "MMS session rate anomaly", "severity": "medium"},
    {"id": "OT-016", "name": "Unexpected MMS write", "severity": "high"},
    {"id": "OT-017", "name": "GOOSE silence (IED offline)", "severity": "high"},
    {"id": "OT-018", "name": "Unauthorized MMS to relay IED", "severity": "high"},
]

CTI_RULES = [
    {"id": "OT-019", "name": "CTI IOC observed", "severity": "high"},
]
>>>>>>> Stashed changes
