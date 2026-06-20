<<<<<<< Updated upstream
# PRD 摘要

完整產品需求文件由產品/架構團隊維護。本檔為邊緣 repo 內的快速參照。

## 產品

- **名稱**：SenseL OT Edge Sensor（RelayGuard）
- **定位**：Pi4 / 工業閘道器上的 OT 資安與遙測邊緣閘道

## MVP 範圍（Sprint 1–3）

1. Docker Compose 部署
2. EdgeX Core + device-mqtt + device-modbus
3. Packet Sensor：L2/L3/L4 + Modbus TCP
4. 規則偵測 OT-001 ~ OT-010
5. PCAP ring buffer
6. SenseL 事件 / 遙測 / 健康上傳
7. SenseL OT Dashboard 基本整合

## MVP 非目標

- 1Gbps 線速 DPI
- 加密 OPC-UA payload 被動解密
- 自動阻斷
- HA / 多站點
- 完整 IEC 61850 decoder

## Sprint 對照

| Sprint | 週期 | 重點 |
|--------|------|------|
| 1 Foundation | 1–2 週 | Compose、EdgeX、擷取驗證、健康上傳 |
| 2 Passive MVP | 1–2 週 | 解析、資產發現、Modbus、PCAP |
| 3 Dashboard | 1–2 週 | SenseL UI、政策、AI 摘要模板 |

## 驗收標準

見 PRD §18 — 72 小時 lab 穩定運行、新設備/Modbus write 事件可於 SenseL 檢視。

## Portal Baseline Live Learning（Cloud）

SMB Portal 三模式（聆聽 / 學習 / 偵測）、Baseline Profile 與中斷 Rollback 之完整 PRD 見 **guacamole-ai** repo：

- `guacamole-ai/docs/PRD_OT_BASELINE_LIVE_LEARNING.md`（主文件）

Edge 本機 baseline 生命週期（pcap / drift）見 [baseline-prd.md](baseline-prd.md)。

## Sprint 執行

詳細 backlog 與 checklist 見 [sprint-plan.md](sprint-plan.md)。
=======
# PRD 摘要

完整產品需求文件由產品/架構團隊維護。本檔為邊緣 repo 內的快速參照。

## 產品

- **名稱**：SenseL OT Edge Sensor（RelayGuard）
- **定位**：Pi4 / 工業閘道器上的 OT 資安與遙測邊緣閘道

## MVP 範圍（Sprint 1–3）

1. Docker Compose 部署
2. EdgeX Core + device-mqtt + device-modbus
3. Packet Sensor：L2/L3/L4 + Modbus TCP
4. 規則偵測 OT-001 ~ OT-010
5. PCAP ring buffer
6. SenseL 事件 / 遙測 / 健康上傳
7. SenseL OT Dashboard 基本整合

## MVP 非目標

- 1Gbps 線速 DPI
- 加密 OPC-UA payload 被動解密
- 自動阻斷
- HA / 多站點
- 完整 IEC 61850 decoder

## Sprint 對照

| Sprint | 週期 | 重點 |
|--------|------|------|
| 1 Foundation | 1–2 週 | Compose、EdgeX、擷取驗證、健康上傳 |
| 2 Passive MVP | 1–2 週 | 解析、資產發現、Modbus、PCAP |
| 3 Dashboard | 1–2 週 | SenseL UI、政策、AI 摘要模板 |

## 驗收標準

見 PRD §18 — 72 小時 lab 穩定運行、新設備/Modbus write 事件可於 SenseL 檢視。

## Portal Baseline Live Learning（Cloud）

SMB Portal 三模式（聆聽 / 學習 / 偵測）、Baseline Profile 與中斷 Rollback 之完整 PRD 見 **guacamole-ai** repo：

- `guacamole-ai/docs/PRD_OT_BASELINE_LIVE_LEARNING.md`（主文件）

Edge 本機 baseline 生命週期（pcap / drift）見 [baseline-prd.md](baseline-prd.md)。

## Sprint 執行

詳細 backlog 與 checklist 見 [sprint-plan.md](sprint-plan.md)。
>>>>>>> Stashed changes
