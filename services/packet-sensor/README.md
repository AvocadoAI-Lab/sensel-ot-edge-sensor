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
| `detection/` | OT-001~010 規則引擎 |
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
