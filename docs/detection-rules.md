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

## OT-003 與 ARP 路徑

OT-003 涵蓋兩種「映射改變」：

- **MAC→IP 改變**（IP 流量）：同一 MAC 換了 source IP。比對在 `MvpDetector.evaluate_observation` 完成，於 `inventory.observe()` 更新映射「之前」讀取舊值（順序修正），且 key 一律小寫。
- **IP→MAC 改變（ARP spoofing）**：`parser/l3/arp.py` 解析 ARP，`MvpDetector.evaluate_arp` 追蹤 `ip_to_mac` 綁定；同一 IP 被不同 MAC 宣告即觸發（`evidence.indicator = "arp_spoofing"`）。

> 注意：被動擷取要看得到 ARP，BPF filter 必須含 `arp`。attack-lab overlay 會自動放寬。

## 攻擊 / 驗證

- 離線（決定性）：`make verify-attacks` → `scripts/attacks-selftest.py`，斷言 **OT-001 ~ OT-018 全數觸發**。
- 真實流量 lab：`make up-attack-lab` 後 `make attack-all` / `attack-arp` / `attack-goose` / `attack-mms`，見 [`lab/attack/README.md`](../lab/attack/README.md)。
- pcap replay 整合測試：`tests/integration/test_pcap_replay.py`（封包→pcap→rdpcap→pipeline 全鏈，CI 可跑、不需 root）。

## 偵測準確度備註

- **MMS 解析**：`parser/l7/iec61850/mms.py` 解析 TPKT/COTP 後以 BER 走訪 MMS PDU（confirmedRequest `0xa0` + service tag read `0xa4` / write `0xa5`），容忍中間的 ISO session/presentation 層；保留字串/簽章 fallback 相容簡化探針。
- **OT-013 stNum**：以 modulo 2³² 的「前向距離」判斷，正常 +1 與合法回繞（2³²-1 → 0）不誤報，replay 倒退與大跳躍（> `goose_stnum_jump_max`）才告警。
- **OT-017 GOOSE silence**：用 baseline `max_silence_sec`，於每個 feature window（`flush_features`）檢查；曾出現後靜默超時才告警，恢復後可再次觸發。
- **OT-015 MMS session rate**：trailing 60s 內新 session 數超過 `mms_new_sessions_per_min` 即告警（含冷卻）。
- **證據時間軸**：seen / silence 與 `evidence_ref` / 落盤 pcap 統一用 wall-clock（epoch）；NTP 跳動對 60–120s 窗為可接受誤差。

## 政策驗證

baseline 政策載入時以 `policy/schema.py` 驗證（型別、必填、未知欄位），警告但不致命；JSON Schema 見 [`schemas/policy-baseline.schema.json`](../schemas/policy-baseline.schema.json)。

## Phase 2

EWMA、Z-score、Isolation Forest 等見 PRD §15.3。  
IEC 61850 SV 解析、SCL 全模型語意對照 — Phase 2（PRD 非目標：完整 decoder）。
