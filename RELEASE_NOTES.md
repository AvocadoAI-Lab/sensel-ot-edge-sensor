# Release Notes — SenseL OT Edge Sensor

## P3-A — Site dataset lineage / trainer boundary（2026-08-12）

新增獨立 Tier 2 Site Node 服務，接收 Tier 1 以 protobuf 發布的 `TrustEpisode`，並在
MQTT ACK 前完成驗證與 durable receipt。Site Node 只保存訓練必要的 episode、label 與
lineage metadata，不保存原始封包，也不允許 trainer 直接讀取 Tier 1、EdgeX 或 Site DB。

### 新增

- **Site ingestion skeleton** — MQTT v5 / QoS 1 persistent session、mTLS、明確 topic ACL、
  protobuf content type / schema / identity / finite-value / feature contract 驗證，以及 poison
  message dead-letter metadata。
- **可重播 dataset lineage** — SQLite WAL receipt 與 append-only label、確定性 dataset ID、
  feature contract definition digest、來源 episode digest、保留等級與時間窗皆寫入 manifest。
- **簽章資料集匯出** — dataset manifest 與 detached Ed25519 signature；trainer 入口會重新
  驗證簽章、scope、樣本 digest、保留期限與演算法邊界。
- **Trainer isolation boundary** — trainer inbox 只接收已驗證的 manifest、signature 與
  NDJSON samples；不掛載 Site DB、PCAP、EdgeX 或 Tier 1 runtime state。
- **部署與 CI** — `docker-compose.site.yml`、非 root / read-only Site image、Mosquitto mTLS
  overlay、環境範例、P3-A 測試 workflow 與架構文件。

### 已知限制 / 後續

- P3-A 建立資料與信任邊界，尚未執行實際 trainer，也尚未產生或啟用 signed candidate
  model；建議由 P3-B 實作隔離的 XGBoost trainer、候選模型驗證與 quarantine。
- 目前 episode 只帶最新 feature vector 與 sequence reference，因此可供 XGBoost handoff；
  Tiny LSTM 必須等完整且可驗證的 sequence materialization，Isolation Forest 維持 Tier 1
  local-only。
- Manifest 會綁定並驗證 retention class / expiry；實體資料清除 worker 尚未納入此切片。

## v0.2 — NDR Edge（2026-06-19）

軟體 NDR 偵測能力上線：在內建 OT 規則偵測之外，加入 Snort 3 / Suricata 引擎橋接、
CTI-origin sighting、Control Plane MQTT 憑證自動下發，以及 OpenWrt 部署路徑與
Edge Console 的引擎 / 憑證可視化。所有引擎橋接皆為 opt-in overlay，未啟用時不影響
既有的 MQTT / buffer / sighting 熱路徑。

### 新增

- **Snort 3 橋接** — sidecar 輸出 `alert_json`（NDJSON）；`SnortAlertSource` 將每筆
  告警映射為 `SecurityEvent`，寫入 `snort-events.jsonl` 供 edge-agent 北向上傳。
  （`docker-compose.snort.yml`）
- **Suricata EVE JSON 橋接** — 對稱的 `SuricataEveSource` 處理 EVE `alert` 記錄；
  可單獨或與 Snort 並行（各自獨立的 `*-events.jsonl` 與 tailer）。
  （`docker-compose.suricata.yml`）
- **CTI-origin sighting** — Snort/Suricata 告警 SID 落在設定的 CTI 範圍
  （`SNORT_CTI_SID_MIN/MAX`，引擎共用）時上報為 sighting；一般告警不會。
- **MQTT 憑證自動下發（edge 端，P4）** — 註冊回應中的憑證會套用到 live MQTT client
  並持久化（`mqtt-credentials.json`，`0600`）；開機時覆寫 env 並觸發重連。
- **OpenWrt 部署** — 獨立 `docker-compose.openwrt.yml` + `.env.openwrt.example` +
  `docs/deployment-openwrt.md`（硬體分層、extroot/block-mount、port mirroring）。
- **Edge Console 可視化** — `/api/status` 新增每引擎狀態（Snort/Suricata：status、
  規則版本、啟用規則數、規則最後更新、事件新鮮度）與不含密碼的 MQTT 憑證落地狀態；
  接入精靈新增「落地狀態」面板。明文密碼永不外洩。
- **DMS 引擎健康** — 回報 IDS 引擎狀態 + 規則版本（FR-008），現涵蓋兩個引擎。

### 平台 / 架構支援

| 引擎 | 鏡像 | 架構 | 建議硬體 |
|------|------|------|----------|
| Snort 3 | `ciscotalos/snort3:latest` | **僅 amd64** | x86 ≥ 4GB |
| Suricata | `jasonish/suricata:latest` | amd64 + **arm64** | x86 或 ARM（含 Pi4） |

> **ARM / Pi4**：Snort 官方鏡像無 arm64，無法在 Pi4 原生執行；ARM 平台請改用
> Suricata 或維持內建 OT 偵測。

### 驗證

- E2E 腳本：`scripts/verify_snort_e2e.py`、`verify_suricata_e2e.py`、
  `verify_mqtt_provisioning_e2e.py`（含 shell wrapper）。
- 單元測試：Snort/Suricata source、sighting reporter、MQTT 憑證（含不外洩密碼）、
  註冊自動落地、北向重連、IDS 引擎探測。

### 已知限制 / 後續

- Snort/Suricata 規則集由 CTI HTTP feed 管理，不在 OT Portal 政策 UI；Edge Console
  目前能「顯示」其版本 / 新鮮度，但 Portal 尚無 Snort/Suricata 規則管理介面。
- Snort/Suricata 事件與原生 OT 事件寫入同一張 `smb_ot_security_events` 表 / UI；
  Portal 尚未依引擎 / 來源做視覺區分。
