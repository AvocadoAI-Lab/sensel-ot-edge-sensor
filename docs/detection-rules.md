# 偵測規則（MVP）

## Baseline

每台資產維護本地 baseline，範例見 `config/policy/baseline.example.json`。

## 規則表 — MVP（Sprint 2）

| Rule ID | 名稱 | 嚴重度 | 模組 |
|---------|------|--------|------|
| OT-001 | New MAC detected | medium | `detection/` |
| OT-002 | New IP detected | medium | `detection/` |
| OT-003 | MAC/IP mapping changed | high | `detection/` |
| OT-004 | New communication pair | medium | `detection/` |
| OT-005 | New destination port | medium | `detection/` |
| OT-006 | Port scan behavior | high | `detection/` |
| OT-007 | Unexpected Modbus write | high | `parser/l7/modbus` |
| OT-008 | Abnormal traffic rate | medium | `detection/` |
| OT-009 | Relay offline | high | `detection/` + EdgeX telemetry |
| OT-010 | Unauthorized host accessing relay | high | `detection/` |

## 規則表 — IEC 61850 被動（S1-02b）

Mirror 上 GOOSE（L2）與 MMS（TCP/102）專用。詳細觸發條件、schema、lab 拓撲見 [`sprint-s1-02b-iec61850.md`](sprint-s1-02b-iec61850.md)。

| Rule ID | 名稱 | 嚴重度 | 模組 |
|---------|------|--------|------|
| OT-011 | New GOOSE publisher | medium | `detection/iec61850` |
| OT-012 | GOOSE test bit in production | high | `parser/l7/iec61850/goose` |
| OT-013 | GOOSE stNum anomaly | medium | `detection/iec61850` |
| OT-014 | New MMS client to IED | medium | `detection/` |
| OT-015 | MMS session rate anomaly | medium | `detection/` |
| OT-016 | Unexpected MMS write | high | `parser/l7/iec61850/mms` |
| OT-017 | GOOSE silence (IED offline) | high | `detection/iec61850` |
| OT-018 | Unauthorized MMS to relay IED | high | `detection/` |

## 規則表 — CTI IoC（Track B-S2）

| Rule ID | 名稱 | 嚴重度 | 模組 |
|---------|------|--------|------|
| OT-019 | CTI IOC observed | high | `detection/ioc` |

被動 mirror 上比對 `data/agent/ioc-cache.json`（由 edge-agent policy sync 寫入）。命中寫入 `security-events.jsonl`，事件類型 `CTI_IOC_OBSERVED`。

## Phase 2

EWMA、Z-score、Isolation Forest 等見 PRD §15.3。  
IEC 61850 SV 解析、SCL 全模型語意對照 — Phase 2（PRD 非目標：完整 decoder）。
