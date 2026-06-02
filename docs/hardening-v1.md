# hardening-v1 — 偵測強化、真實攻擊 lab、測試隔離

> 分支：`hardening-v1`（基於 `main`）
> 一句話：把既有 MVP 偵測器從「能 demo」修到「對得起電驛場景」，補上真實攻擊驗證與可重現測試。

本版**不改變架構**，只強化既有雙路徑感測器的被動側（Packet Sensor）與其驗證。

## 架構總覽

![architecture](diagrams/architecture.png)

- **主動遙測（上）**：OT → EdgeX → Core Data → Edge Agent → 平台。
- **被動資安（下，本版重點）**：OT 鏡像流量 →(SPAN/TAP 唯讀)→ Packet Sensor 解析偵測 → `security-events.jsonl` → Edge Agent →(MQTT/HTTP)→ 平台。
- **特徵橋接（虛線）**：Packet Sensor 的視窗統計經 Local MQTT 回灌 EdgeX。

綠色 = 本版強化的元件。圖檔由 `docs/diagrams/render.py` 產生（`python3 docs/diagrams/render.py`）。

## 封包偵測管線

![detection-pipeline](diagrams/detection-pipeline.png)

每個封包先進 ring buffer（證據保全），再逐層解析、逐條規則評估；速率/離線/靜默類規則掛在每 60s 的 feature window。綠色節點為本版修正/強化處。

---

## 九項強化（before → after）

### 1. OT-003 順序/大小寫 bug + ARP 解析
- **Before**：`inventory.observe()` 在規則讀取前就覆蓋 `mac_to_ip`，加上大小寫不一致 → **OT-003 在 live pipeline 幾乎不可能觸發**；且 `parse_ip()` 完全不解析 ARP，ARP spoofing 封包進不了引擎。
- **After**：比對移到覆寫之前、key 一律小寫；新增 `parser/l3/arp.py` 與 `MvpDetector.evaluate_arp()`，以 **IP→MAC 綁定翻轉** 偵測 ARP 欺騙（`evidence.indicator = "arp_spoofing"`）。
- **注意**：被動擷取要看得到 ARP，BPF filter 需含 `arp`（attack-lab overlay 會自動放寬）。

### 2. 真正的 MMS BER/COTP 解析
- **Before**：`classify_mms_payload` 用 `b"write" in payload` 字串比對 → 真實二進位 MMS 會漏判、含字面 "write" 的雜訊會誤判。
- **After**：解析 TPKT/COTP 後以 BER 走訪 MMS PDU（`confirmedRequest 0xa0` + service tag：read `0xa4` / write `0xa5`），容忍中間的 ISO session/presentation 層；保留字串/簽章 fallback 相容簡化探針。`build_mms_write_probe()` 改發真實 write PDU。

### 3. OT-013 GOOSE stNum 32-bit wrap
- **Before**：`frame.st_num < prev` 會對**每次合法計數回繞**（2³²-1 → 0）誤報。
- **After**：用 modulo 2³² 的「前向距離」；正常 +1 與合法回繞不誤報，replay 倒退與大跳躍（> `goose_stnum_jump_max`）才告警。

### 4. 補實作 OT-015 / OT-017
- **OT-017 GOOSE silence**：baseline `max_silence_sec`，每個 feature window 檢查；曾出現後靜默超時才告警，恢復後可再次觸發。
- **OT-015 MMS session rate**：trailing 60s 新 session 數超過 `mms_new_sessions_per_min` 即告警（含冷卻）。

### 5. 證據時間軸統一
- seen / silence 與 `evidence_ref` / 落盤 pcap 統一用 **wall-clock（epoch）**，使事件與證據可對齊。權衡：對 NTP 跳動敏感（60–120s 窗可接受）。

### 6. Tailer log rotation
- **Before**：`SecurityEventTailer` 只比對 `offset > len`，等長/更長的輪替會**靜默漏讀**。
- **After**：追蹤 inode + 首行簽章，偵測輪替/截斷並從頭重讀（重送由 `event_id` 冪等吸收）。

### 7. PCAP ring buffer 落盤
- **Before**：純記憶體，重啟即失去證據。
- **After**：滾動寫 libpcap segment（retention + 磁碟上限），事件帶 `evidence.pcap_file`。預設關閉（`pcap.ring_buffer_path` 設定才開）。

### 8. 政策 baseline schema 驗證
- 載入時以 `policy/schema.py`（pydantic）驗證型別/必填/未知欄位，**只告警不致命**；JSON Schema：`schemas/policy-baseline.schema.json`。

### 9. 測試隔離（消除 `src` 命名衝突 hack）
- 兩個 service 都叫 `src`，舊測試每檔都手動 `del sys.modules`。改用集中化 `tests/service_loader.py` + conftest，**順序無關**、零執行期影響。

---

## 真實攻擊 lab（OT-001 ~ OT-018）

所有攻擊腳本**真的發封包**（非造資料），見 [`lab/attack/README.md`](../lab/attack/README.md)。

```bash
make verify-attacks        # 離線決定性 self-test：OT-001~018 全部觸發（不需網路）
make up-attack-lab         # Linux+Docker：拉起 61850 模擬 + 廣域擷取
make attack-all            # 發真實攻擊流量
make attack-arp            # 真 MITM ARP 毒化 → OT-003（僅限隔離網段！）
```

> ⚠️ `attack-arp` 會真的中斷受害者流量，務必只在隔離測試網段執行。

## 驗證與測試

| 指令 | 作用 | 需要 |
|------|------|------|
| `make test` / `pytest tests` | 單元 + 整合（含 pcap-replay 全鏈） | Python |
| `make verify-attacks` | OT-001~018 偵測覆蓋 | Python |
| `scripts/attacks-selftest.py` | 18 條規則決定性自測 | Python |

測試結構：`tests/unit/`（規則邏輯、解析、ring buffer、tailer、schema）、`tests/integration/`（edge-agent ↔ mock 平台、pcap replay）。

## 變更檔案速覽

- 偵測：`detection/mvp.py`、`detection/iec61850.py`、`parser/l3/arp.py`、`parser/l7/iec61850/mms.py`
- 證據/狀態：`evidence/ring_buffer.py`、`events/generator.py`
- 韌性：`sensel-edge-agent/src/upload/events.py`
- 政策：`policy/loader.py`、`policy/schema.py`、`schemas/policy-baseline.schema.json`
- lab/測試：`lab/attack/*`、`docker-compose.attack-lab.yml`、`scripts/{attacks-selftest.py,verify-attacks.sh}`、`tests/service_loader.py`、`tests/unit/test_*`、`tests/integration/test_pcap_replay.py`
