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

## 注意事項

- Pi4 僅建議 Lab / PoC；高流量現場請規劃 industrial gateway 或 x86
- 避免在 SD 卡上長期寫入 PCAP；使用 SSD
- 散熱與穩定電源影響持續擷取效能
