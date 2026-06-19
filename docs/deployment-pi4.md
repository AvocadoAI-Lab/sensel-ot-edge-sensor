# Raspberry Pi 4 部署指南

## 硬體建議

- Raspberry Pi 4 Model B，8 GB RAM
- 64 GB+ SSD（USB 或 NVMe HAT）
- 雙網路：內建 Ethernet + USB Ethernet（mirror）
- Raspberry Pi OS 64-bit 或 Ubuntu Server 22.04/24.04 for Pi

## 與 Ubuntu 差異

```bash
# 使用 Pi4 overlay 限制資源
docker compose -f docker-compose.yml -f docker-compose.pi4.yml up -d

# sensor.yaml
hardware: raspberry-pi-4
```

## 效能目標（MVP）

- 穩定監控 ≤ 100 Mbps 鏡像流量
- 特徵摘要週期 60 秒
- 規則事件延遲 < 3 秒

## 部署腳本

```bash
sudo ./deploy/pi4/setup.sh
```

## NDR 引擎：ARM 上用 Suricata 取代 Snort

Pi4 是 ARM64。**Snort 官方鏡像 `ciscotalos/snort3:latest` 只有 amd64**，無法在 Pi4
原生執行（QEMU 模擬不適用於封包檢測），因此在 Pi4 上：

- ✅ 用 **Suricata**：`jasonish/suricata:latest` 為 multi-arch（含 arm64），可原生執行。
- ✅ 或維持**內建 OT 偵測**（OT-001~019），不開外部引擎。
- ❌ 不要在 Pi4 上開 Snort overlay。

```bash
# Pi4 + Suricata（含 pi4 資源限制）
SURICATA_INTERFACE=eth1 \
docker compose -f docker-compose.yml -f docker-compose.pi4.yml \
  -f docker-compose.suricata.yml up -d
```

`docker-compose.pi4.yml` 已為 `suricata` 服務設定資源上限（1G / 1.5 CPU），可依實機微調。
引擎為重量級 sidecar，建議僅在 Pi4 8GB + 外接 SSD + 良好散熱下做 Lab/PoC；高流量現場請用 x86。

> Snort 仍可在 x86 sensor 上使用；引擎狀態與規則版本會顯示在 Edge Console「落地狀態」面板。

## 注意事項

- Pi4 僅建議 Lab / PoC；高流量現場請規劃 industrial gateway 或 x86
- 避免在 SD 卡上長期寫入 PCAP；使用 SSD
- 散熱與穩定電源影響持續擷取效能
- Pi4 上的外部 IDS 引擎請用 Suricata（Snort 鏡像無 arm64，見上節）
