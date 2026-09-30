# Sprint S1-02b — IEC 61850 被動分析（GOOSE + MMS）

插入 **S1-02（Modbus 主動）** 與 **S1-03（MQTT 橋接）** 之間的 lab spike。  
定位：**mirror 被動為主**；MMS 被動做連線/Write 可見性，必要時以 **選配主動 MMS client** 補 telemetry gap。

> PRD 對齊：不做「完整 IEC 61850 decoder / SCL 全模型」；只做 frame/PDU 級解析 + 資安規則 + 特徵摘要。  
> 參見 [`PRD.md`](PRD.md) MVP 非目標。

## 目標與退出條件

| 項目 | 說明 |
|------|------|
| **目標** | Mirror 上辨識 GOOSE / MMS；產生 feature summary 與高風險 security event |
| **週期** | 1 週（可與 S1-03 並行） |
| **退出** | Lab 注入 GOOSE pcap + MMS 流量後，`make verify-61850` 綠燈；至少 1 條 OT-011~OT-018 事件與 1 份 61850 feature summary 進 local-mqtt |

## 架構位置

```
                    ┌─────────────────────────────────────┐
  SPAN/TAP (mirror) │  Packet Sensor (host network)       │
                    │  capture → parser/l7/iec61850/*     │
                    │         → detection OT-011~018      │
                    └──────────┬────────────┬─────────────┘
                               │            │
                    Security Event      Feature Summary
                               │            │
                               ▼            ▼
                    sensel-edge-agent   local-mqtt ──► device-mqtt (S1-03)
                               │                         │
                               ▼                         ▼
                         SenseL API                  Core Data

  Lab only (L2 segment):
    goose-publisher ──► mirror bridge ◄── packet-sensor
    61850-sim (MMS:102) ──► mirror (TCP) / optional mms-probe (active)
```

**原則**：原始 61850 封包不進 EdgeX；與 [`architecture.md`](architecture.md) 一致。

---

## Lab Compose 拓撲

### 模式 A — 推薦（bridge + GOOSE publisher + MMS server）

適用：無實體 SPAN switch 的 Ubuntu lab。

```
┌─────────────────────────────────────────────────────────────────────────┐
│  docker network: sensel-61850-lab (bridge)                              │
│                                                                         │
│  ┌──────────────────┐     ┌──────────────────┐                        │
│  │ goose-publisher  │     │ 61850-sim        │                        │
│  │ (libiec61850     │     │ (MMS :102)       │                        │
│  │  or custom)      │     │ stinging/61850-sim│                        │
│  └────────┬─────────┘     └────────┬─────────┘                        │
│           │ L2 GOOSE 0x88B8         │ TCP 102                          │
│           └──────────┬──────────────┘                                   │
│                      ▼                                                  │
│           ┌──────────────────────┐                                      │
│           │ lab-mirror-bridge    │  (linux bridge / compose macvlan)    │
│           │  iface: mirror0      │                                      │
│           └──────────┬───────────┘                                      │
└──────────────────────┼──────────────────────────────────────────────────┘
                       │ promisc / attached NIC
                       ▼
           ┌──────────────────────┐
           │ packet-sensor        │  network_mode: host
           │ CAPTURE_INTERFACE=   │  或 macvlan 掛 mirror0
           │   mirror0            │
           └──────────────────────┘

  既有 stack（不變）:
    sensel-edge-agent, local-mqtt, EdgeX, modbus-simulator ...
```

**規劃檔案**（實作時新增）：

| 檔案 | 用途 |
|------|------|
| `docker-compose.lab-61850.yml` | overlay：`goose-publisher`、`61850-sim-mms`、`lab-mirror-bridge` |
| `lab/61850/goose-publisher/` | GOOSE 發送容器（libiec61850 publisher 或 pcap loop） |
| `lab/61850/pcap/` | 樣本 GOOSE/MMS pcap |
| `scripts/61850-lab-setup.sh` | 建立 bridge、設定 promisc |
| `scripts/verify-61850.sh` | 驗證 parser 計數 + MQTT 訊息 |

**啟動（規劃）**：

```bash
docker compose -f docker-compose.yml -f docker-compose.lab-61850.yml up -d
export CAPTURE_INTERFACE=mirror0   # 或 host 上對應 mirror 介面
make verify-61850
```

### 模式 B — pcap replay（CI / 無 L2 simulator）

```
tcpreplay -i ${CAPTURE_INTERFACE} lab/61850/pcap/goose_sample.pcap
tcpreplay -i ${CAPTURE_INTERFACE} lab/61850/pcap/mms_sample.pcap
make verify-61850
```

### 模式 C — 實體 SPAN

```
Substation switch SPAN ──► Pi4/Server mirror NIC (eth1)
                              └── packet-sensor (promisc)
Lab IED / 61850-sim 接在同一 OT VLAN，由 switch mirror 轉發。
```

### 服務清單（lab overlay）

| Compose service | 映像 / 來源 | Port / 流量 | 角色 |
|-----------------|-------------|-------------|------|
| `goose-publisher` | 自建（libiec61850 publisher） | L2 GOOSE | 持續 stNum/sqNum 變化 |
| `61850-sim-mms` | `stinging/61850-sim` + SCL volume | TCP 102 | MMS read/write/report |
| `mms-probe`（選配） | 自建 MMS client | → 61850-sim:102 | 觸發 MMS 流量供 mirror 抓 |
| `lab-mirror-bridge` | `alpine` + `bridge-utils` 或 host 腳本 | — | 匯聚 L2 給 capture |

**與 S1-02 Modbus 共存**：`modbus-simulator:1502` 走 EdgeX 主動路徑；61850 lab 走 **被動 mirror**，互不干擾。

---

## BPF 過濾

設定位置：`config/sensor.yaml` → `capture.bpf_filter`，或 `.env` → `CAPTURE_BPF_FILTER`。  
範例檔：[`config/capture/bpf.filters.example`](../config/capture/bpf.filters.example)。

### 建議預設（61850 lab）

```text
(ether proto 0x88b8) or (tcp port 102)
```

### 分項

| 名稱 | BPF | 用途 |
|------|-----|------|
| `iec61850-gouse-only` | `ether proto 0x88b8` | 僅 GOOSE（L2） |
| `iec61850-mms-only` | `tcp port 102` | 僅 MMS |
| `iec61850-combined` | `(ether proto 0x88b8) or (tcp port 102)` | GOOSE + MMS |
| `iec61850-vlan` | `vlan and ((ether proto 0x88b8) or (tcp port 102))` | 含 VLAN tag 的 substation trunk |
| `ot-lab-mixed` | `(ether proto 0x88b8) or (tcp port 102) or (tcp port 502)` | 61850 + Modbus 同 mirror（慎用，Pi4 負載較高） |
| `exclude-llmnr-mdns` | `(ether proto 0x88b8 or tcp port 102) and not broadcast and not multicast` | 部分環境減噪（**注意**：GOOSE 本身為 L2 multicast，此 filter 僅用於 MMS-heavy lab） |

### 設定範例（sensor.yaml）

```yaml
capture:
  interface: ${CAPTURE_INTERFACE}
  promiscuous: true
  bpf_filter: "(ether proto 0x88b8) or (tcp port 102)"
```

### 實作注意

- GOOSE **不可**只做 `tcp port 102`；必須含 `ether proto 0x88b8`。
- SV（Sampled Values, 0x88BA）**不在 S1-02b 範圍**；若誤入鏡像，可先用 BPF 排除：`not ether proto 0x88ba`。
- `packet-sensor` 為 host network 時，BPF 在 host 介面生效。

---

## Epic 與 Story Backlog

### Epic B.1 — 擷取與 Lab

| ID | Story | 產出 | 優先 |
|----|-------|------|------|
| S1-02b-01 | Lab overlay compose（模式 A） | `docker-compose.lab-61850.yml` | P0 |
| S1-02b-02 | GOOSE publisher 容器 | `lab/61850/goose-publisher/` | P0 |
| S1-02b-03 | 樣本 pcap + replay 腳本 | `lab/61850/pcap/`, `scripts/61850-pcap-replay.sh` | P0 |
| S1-02b-04 | BPF 預設與文件 | `bpf.filters.example`, 本文件 | P1 |
| S1-02b-05 | `make verify-61850` | `scripts/verify-61850.sh` | P0 |

### Epic B.2 — GOOSE 被動解析

| ID | Story | 產出 | 優先 |
|----|-------|------|------|
| S1-02b-06 | GOOSE frame 解析（APPID, gocbRef, stNum, sqNum, test, confRev） | `parser/l7/iec61850/goose.py` | P0 |
| S1-02b-07 | GOOSE publisher 資產索引（MAC + APPID + gocbRef） | `assets/inventory.py` 擴充 | P1 |
| S1-02b-08 | GOOSE 1-min 特徵聚合 | `features/iec61850.py` | P0 |

### Epic B.3 — MMS 被動解析

| ID | Story | 產出 | 優先 |
|----|-------|------|------|
| S1-02b-09 | TCP:102 session 追蹤（五元組） | `parser/l4/transport.py` 擴充 | P0 |
| S1-02b-10 | MMS PDU 粗分類（Read/Write/GetNameList/Report） | `parser/l7/iec61850/mms.py` | P1 |
| S1-02b-11 | MMS Write 事件提取 | `parser/l7/iec61850/mms.py` | P0 |
| S1-02b-12 | 選配：輕量 MMS active probe | `lab/61850/mms-probe/` | P2 |

### Epic B.4 — 偵測、輸出、測試

| ID | Story | 產出 | 優先 |
|----|-------|------|------|
| S1-02b-13 | OT-011 ~ OT-018 規則引擎 | `detection/rules.py`, `detection/iec61850.py` | P0 |
| S1-02b-14 | Security event + evidence_ref | `events/generator.py` | P0 |
| S1-02b-15 | Feature summary → MQTT topic | 對齊 S1-03 topic | P1 |
| S1-02b-16 | baseline 61850 區段 | `config/policy/baseline.example.json` | P1 |
| S1-02b-17 | Unit test（GOOSE/MMS parser fixtures） | `tests/fixtures/61850/` | P0 |

---

## 偵測規則 ID（OT-011 ~ OT-018）

擴充 [`detection-rules.md`](detection-rules.md)。S1-02b **至少實作 P0 規則**（011、012、013、016）。

| Rule ID | 名稱 | 嚴重度 | 觸發條件（摘要） | 模組 |
|---------|------|--------|------------------|------|
| **OT-011** | New GOOSE publisher | medium | 首次見到 `(src_mac, appid, gocb_ref)` 不在 baseline | `detection/iec61850` |
| **OT-012** | GOOSE test bit in production | high | `test=true` 且 asset/VLAN 標記為 production | `parser/l7/iec61850/goose` |
| **OT-013** | GOOSE stNum anomaly | medium | 窗口內 stNum 倒退或跳變超過 threshold | `detection/iec61850` |
| **OT-014** | New MMS client to IED | medium | 首次見到 `(src_ip → dst_ip:102)` pair | `detection/` |
| **OT-015** | MMS session rate anomaly | medium | 對同一 IED 的 102 新連線速率 > baseline × 倍數 | `detection/` |
| **OT-016** | Unexpected MMS write | high | 被動解析到 Write PDU，來源不在 `allowed_mms_clients` | `parser/l7/iec61850/mms` |
| **OT-017** | GOOSE silence (IED offline) | high | baseline 內 publisher 超過 N 秒無 GOOSE | `detection/iec61850` |
| **OT-018** | Unauthorized MMS to relay IED | high | 對 `baseline.assets[].ied_ip` 的 102 連線來源非 allowlist | `detection/` |

### 與既有 OT-001~010 關係

| 61850 規則 | 可復用 |
|------------|--------|
| OT-011 | OT-001（新 MAC）語意重疊；61850 版更精準（含 APPID/gocbRef） |
| OT-014 | OT-004（新 comm pair） |
| OT-016 | OT-007（unexpected write）之 61850 版 |
| OT-017 | OT-009（offline）之 GOOSE 版 |
| OT-018 | OT-010（unauthorized host） |

---

## Schema 欄位擴充（提案）

現有 schema 保持向後相容：**新增 optional 欄位** + `protocol` 區分。實作時更新 `schemas/*.schema.json`（S1-02b-17 前）。

### Feature Summary（`schemas/feature-summary.schema.json`）

既有欄位保留。61850 視窗新增：

| 欄位 | 型別 | 必填 | 說明 |
|------|------|------|------|
| `protocol` | string | 否 | `iec61850-goose` \| `iec61850-mms` \| 既有 `modbus-tcp` 等 |
| `goose_appid` | integer | 否 | GOOSE APPID（0–0xFFFF） |
| `goose_gocb_ref` | string | 否 | GOOSE 控制塊引用 |
| `goose_publisher_mac` | string | 否 | 發布者 MAC |
| `goose_message_count` | integer | 否 | 窗口內 GOOSE 幀數 |
| `goose_stnum_changes` | integer | 否 | stNum 變化次數 |
| `goose_test_flag_count` | integer | 否 | test bit 為真次數 |
| `mms_session_count` | integer | 否 | MMS TCP 會話數 |
| `mms_read_count` | integer | 否 | Read 類 PDU 數 |
| `mms_write_count` | integer | 否 | Write 類 PDU 數 |
| `mms_report_count` | integer | 否 | Report 類 PDU 數 |
| `ied_address` | string | 否 | 被動觀察到的 IED IP（MMS server） |

**MQTT topic（對齊 S1-03）**：

```text
sensel/ot/{sensor_id}/features/iec61850/goose
sensel/ot/{sensor_id}/features/iec61850/mms
```

### Security Event（`schemas/security-event.schema.json`）

`evidence` object 內 61850 專用鍵（皆 optional）：

| 欄位 | 型別 | 說明 |
|------|------|------|
| `rule_id` | string | e.g. `OT-016` |
| `goose_appid` | integer | |
| `goose_gocb_ref` | string | |
| `goose_stnum` | integer | |
| `goose_sqnum` | integer | |
| `goose_test` | boolean | |
| `goose_conf_rev` | integer | |
| `mms_pdu_type` | string | `read` \| `write` \| `getNameList` \| `report` \| `other` |
| `mms_invoke_id` | integer | 若可解析 |
| `ied_ip` | string | MMS 目標 IED |
| `pcap_ref` | string | 同既有 `local-ringbuffer://...` |

**event_type 範例**：

| event_type | 對應規則 |
|------------|----------|
| `GOOSE_NEW_PUBLISHER` | OT-011 |
| `GOOSE_TEST_MODE` | OT-012 |
| `GOOSE_STNUM_ANOMALY` | OT-013 |
| `MMS_NEW_CLIENT` | OT-014 |
| `MMS_WRITE_ANOMALY` | OT-016 |
| `GOOSE_SILENCE` | OT-017 |
| `MMS_UNAUTHORIZED_CLIENT` | OT-018 |

### Baseline 擴充（`config/policy/baseline.example.json`）

```json
{
  "iec61850": {
    "goose_publishers": [
      {
        "asset_id": "ied-01",
        "publisher_mac": "00:11:22:33:44:55",
        "appid": 1000,
        "gocb_ref": "simpleIOGenericIO/LLN0.gcbEvents",
        "vlan_id": null,
        "production": true,
        "max_silence_sec": 30
      }
    ],
    "mms_ieds": [
      {
        "asset_id": "ied-01",
        "ied_ip": "192.168.10.50",
        "allowed_mms_clients": ["192.168.10.10", "192.168.10.11"]
      }
    ],
    "thresholds": {
      "goose_stnum_jump_max": 100,
      "mms_new_sessions_per_min": 20
    }
  }
}
```

---

## 驗收腳本（規劃）

`scripts/verify-61850.sh` 檢查：

1. `packet-sensor` log 出現 GOOSE/MMS parse 計數 > 0  
2. `lab/61850/pcap/` replay 後 60s 內產生 feature summary（訂閱 local-mqtt 或讀 debug log）  
3. 注入 test GOOSE（test bit=1）→ 觸發 OT-012  
4. 注入 MMS write（非 allowlist）→ 觸發 OT-016  

**Makefile 目標**：

```makefile
verify-61850:
	./scripts/verify-61850.sh
```

---

## 風險與非目標

| 風險 | 緩解 |
|------|------|
| GOOSE 為 L2 multicast，lab 無 SPAN | bridge + publisher 同 segment；pcap replay |
| Scapy 解析 BER/MMS 效能不足 | Phase 1 粗分類；必要時 libiec61850 C binding |
| GOOSE dataSet 語意需 SCL | S1-02b 只做 metadata；SCL 對照留 Phase 2 |
| MMS 加密 | 僅 flow metadata + event「encrypted MMS session」 |
| Pi4 CPU | BPF 精簡；GOOSE-only lab 先測 |

**S1-02b 明確不做**：

- SV（0x88BA）線速解析  
- 完整 SCL / ICD 模型匯入  
- IEC 61850 主動控制 Write  
- EdgeX `device-61850` service  

---

## 與相鄰 Sprint 銜接

| Sprint | 銜接 |
|--------|------|
| **S1-02** | Modbus 主動遙測已驗證 EdgeX → Core Data；61850 不走此路 |
| **S1-02b** | 被動 GOOSE/MMS → Packet Sensor → events / MQTT features |
| **S1-03** | 复用 `local-mqtt` + `device-mqtt`；擴充 topic 與 profile |
| **S2** | Modbus 被動 OT-007 與 61850 OT-016 共用 baseline / inventory |

---

## Done Checklist

- [x] GOOSE/MMS parser + OT-011~018 detection（offline self-test）
- [x] Feature summary JSON + schema 擴充
- [x] `docker-compose.lab-61850.yml` + goose-publisher
- [x] `make verify-61850` + unit tests
- [ ] Live mirror lab（goose-publisher + packet-sensor 同 host）
- [ ] MQTT → device-mqtt 端到端（S1-03）
