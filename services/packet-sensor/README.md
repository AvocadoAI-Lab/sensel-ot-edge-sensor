# Packet Sensor Agent

被動鏡像流量感測器：擷取 → 解析 → 本地偵測 → 事件 / 特徵摘要 / PCAP 證據。

## 模組

| 模組 | 職責 |
|------|------|
| `capture/` | SPAN/TAP 介面擷取、BPF、健康監控 |
| `parser/l2` | MAC、VLAN、EtherType |
| `parser/l3` | IP、ARP |
| `parser/l4` | TCP/UDP port、session |
| `parser/l7/modbus` | Modbus TCP function code |
| `parser/l7/iec61850` | GOOSE (L2) + MMS (TCP/102) 被動解析 — S1-02b |
| `detection/` | OT-001~010、OT-019 CTI IoC 比對 |
| `policy/` | 讀取 edge-agent 寫入的 `ioc-cache.json` |
| `assets/` | 本地資產清冊 |
| `events/` | 安全事件產生 |
| `evidence/` | PCAP ring buffer |

## 輸出

1. **Security events** → SenseL Edge Agent → SenseL API
2. **Feature summaries** → Local MQTT → EdgeX device-mqtt
3. **Evidence refs** → metadata only (PCAP on-demand upload)

## MVP 技術選型

- Python 3.11+ / Scapy（MVP）
- 產品化可遷移至 Go gopacket

## 執行

```bash
python -m src.main
```

Docker：`docker compose up packet-sensor`

## CTI IoC Match（Track B-S2）

每個 IPv4 封包在 L3/L4 解析後比對 edge-agent 寫入的 `ioc-cache.json`（OT-019）。

| 項目 | 說明 |
|------|------|
| 規則 | OT-019 / `CTI_IOC_OBSERVED` |
| 快取路徑 | `/app/data/agent/ioc-cache.json`（host：`data/agent/`） |
| 熱重載 | 監看 `ioc-cache.stamp`，預設每 5s 檢查 |
| 冷卻 | 同一 IP + direction 預設 300s 內不重複告警 |
| 輸出 | `data/assets/security-events.jsonl` |

環境變數：`IOC_MATCH_ENABLED`、`IOC_CACHE_PATH`、`IOC_MATCH_COOLDOWN_SEC`（見 repo `.env.example`）。

若 `detection.rules_enabled` 有明確清單，需包含 `OT-019`。

## AF_XDP 加速擷取（Track A）

以 kernel XDP redirect + AF_XDP UMEM 取代 Scapy `sniff()`，降低 CPU；解析與偵測仍走既有 `PacketPipeline`。

| 項目 | 說明 |
|------|------|
| eBPF | `bpf/xdp_redirect.bpf.c` — GOOSE / MMS(102) / Modbus(502) redirect |
| Userspace | `native/libxdp_capture.so` + `capture/xdp_reader.py` |
| 後端 | `CAPTURE_BACKEND=scapy`（預設）或 `af_xdp` |
| Fallback | attach 失敗 / lib 缺失 → 自動 Scapy，服務不中斷 |

環境變數：

```bash
CAPTURE_BACKEND=af_xdp
XDP_MODE=native          # USB 網卡可改 generic
XDP_QUEUE_ID=0
AF_XDP_FRAME_SIZE=2048
AF_XDP_NUM_FRAMES=4096
```

**主機 kernel：** ≥ 5.10，且 **`CONFIG_XDP_SOCKETS=y`**（`bpftool feature probe kernel | grep XDP_SOCKETS`）。  
Raspberry Pi 預設 kernel 常為 `CONFIG_XDP_SOCKETS is not set` → `xsks_map` 建立失敗，會 **自動 fallback Scapy**（A-4）。
