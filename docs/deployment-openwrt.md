# OpenWrt 部署指南（SenseL NDR Edge v0.1 / FR-001）

把 SenseL 軟體 NDR sensor 部署到 **OpenWrt** 裝置。OpenWrt 路由器型號差異極大，請先依硬體分層選擇部署模式，再往下走安裝步驟。

> 對應 PRD：FR-001（開放軟體 NDR sensor 可安裝於 OpenWrt）。本指南只涵蓋 edge runtime；Control Plane（註冊 / 憑證下發）見 `guacamole-ai` repo。

---

## 1. 硬體分層與模式選擇

| 分層 | 典型硬體 | RAM / 儲存 | Docker | 建議模式 |
|------|----------|-----------|--------|----------|
| Tier 0 消費級路由器 | MT76xx / ath79（16–128 MB flash） | < 256 MB / 內建 flash | ✗ | **Mode B**（僅鏡像來源） |
| Tier 1 中階 ARM | NanoPi R4S/R5S、RPi（OpenWrt） | 1–4 GB / USB·SSD | ✓ | Mode A（自建規則，引擎關閉） |
| Tier 2 x86 防火牆機 | mini-PC、軟路由 x86_64 | ≥ 4 GB / SSD | ✓ | Mode A + Snort/Suricata sidecar |

- **Mode A — OpenWrt 主機跑 sensor**：在 OpenWrt 上安裝 Docker，直接執行 `docker-compose.openwrt.yml`。需 Tier 1 以上。
- **Mode B — OpenWrt 僅作鏡像來源**：路由器只負責 port mirroring，把流量送到外部 sensor 主機（Ubuntu/Pi）。Tier 0 受限裝置走這條。

> 內建 flash **不可**承載 PCAP ring buffer（容量小、寫入磨損）。Mode A 必須掛外接儲存（extroot / USB / SSD）。

---

## 2. Mode A：OpenWrt 主機部署

### 2.1 前置：安裝 Docker

```sh
opkg update
opkg install dockerd docker docker-compose luci-app-dockerman
# 將 Docker 資料目錄移到外接磁碟（見 2.2），再啟動
service dockerd enable
service dockerd start
docker version && docker compose version
```

### 2.2 外接儲存（extroot / block-mount）

PCAP 與佇列要落在實體磁碟。掛載一顆 USB/SSD 到 `/mnt/sensel`：

```sh
opkg install block-mount e2fsprogs kmod-usb-storage kmod-fs-ext4
mkfs.ext4 /dev/sda1
mkdir -p /mnt/sensel
# 寫入 /etc/config/fstab（用 block detect 產生 UUID 設定）
block detect | uci import fstab
uci set fstab.@mount[-1].target='/mnt/sensel'
uci set fstab.@mount[-1].enabled='1'
uci commit fstab
service fstab boot
df -h /mnt/sensel    # 確認已掛載
```

> 進階：把 Docker 的 `data-root` 也指到 `/mnt/sensel/docker`（`/etc/docker/daemon.json`），避免 image 佔滿 flash。

### 2.3 鏡像（mirror）介面設定

sensor 需要一個 **專用監聽埠**，不要參與 LAN/WAN bridge、不配 IP。

設為 unmanaged（`/etc/config/network`）：

```
config interface 'mirror'
    option proto 'none'
    option device 'eth1'
```

把要監看的流量鏡像到該埠：

- **DSA（新版 OpenWrt）**：用 `tc` mirred 從來源埠複製到監聽埠

```sh
opkg install tc-mod-iptables kmod-sched
SRC=lan1; MON=eth1
tc qdisc add dev $SRC handle ffff: ingress
tc filter add dev $SRC parent ffff: matchall action mirred egress mirror dev $MON
tc qdisc add dev $SRC root handle 1: prio
tc filter add dev $SRC parent 1: matchall action mirred egress mirror dev $MON
```

- **swconfig（舊版 switch）**：在 `/etc/config/network` 的 `config switch` 開 `enable_mirror_rx/tx`、`mirror_monitor_port`、`mirror_source_port`。
- **外部 SPAN/TAP**：若交換器已做 SPAN，直接把 SPAN 線接到監聽埠即可，免上面 tc 設定。

確認介面進入 promisc 並有流量：

```sh
ip link set eth1 up promisc on
tcpdump -ni eth1 -c 5
```

### 2.4 取得專案與設定

```sh
git clone <repo-url> /mnt/sensel/sensel-ot-edge-sensor
cd /mnt/sensel/sensel-ot-edge-sensor

cp .env.openwrt.example .env
cp config/sensor.yaml.example config/sensor.yaml
cp config/policy/baseline.example.json config/policy/baseline.json

# 編輯 .env：
#   SENSEL_API_URL / SENSEL_API_KEY / CONTROL_PLANE_MQTT_HOST
#   CAPTURE_INTERFACE=eth1
#   DATA_DIR=/mnt/sensel/data      ← 指向外接磁碟
vi .env
mkdir -p "$DATA_DIR"/{pcap,assets,agent}
```

### 2.5 啟動

```sh
# 確保系統時間正確（事件時間戳依賴）
opkg install ntpd ; service sysntpd enable ; service sysntpd start

docker compose -f docker-compose.openwrt.yml up -d --build
docker compose -f docker-compose.openwrt.yml ps
```

### 2.6 偵測引擎（選用，僅 Tier 2）

自建 OT 規則（OT-001~019）在 Tier 1 即可運作。Snort/Suricata 為重量級 sidecar，**只在 x86 ≥ 4 GB RAM** 開啟：

> ⚠️ **架構限制**：Snort 鏡像 `ciscotalos/snort3:latest` **只有 amd64**，無法在 ARM
> 裝置（如 NanoPi R4S/R5S、RPi）原生執行。**ARM 平台請改用 Suricata**
> （`jasonish/suricata:latest` 為 multi-arch，含 arm64），或維持內建 OT 偵測。

```sh
# Snort（僅 x86_64）
SNORT_INTERFACE=eth1 \
docker compose -f docker-compose.openwrt.yml -f docker-compose.snort.yml up -d

# Suricata（x86_64 或 ARM）
# SURICATA_INTERFACE 必須等於 CAPTURE_INTERFACE（此處 mirror 埠為 eth1）
SURICATA_INTERFACE=eth1 \
docker compose -f docker-compose.openwrt.yml -f docker-compose.suricata.yml up -d
```

引擎細節與 CTI sighting（共用 `SNORT_CTI_SID_MIN/MAX`、各自 `*_SIGHTING_ENABLED`）見 `docker-compose.snort.yml` / `docker-compose.suricata.yml` 標頭。

### 2.7 開機自啟

- Docker 服務：`service dockerd enable`（2.1 已做）。
- 容器：compose 內 `restart: unless-stopped`，dockerd 起來後會自動拉回。
- 進階（不靠 dockerd 自啟時）可加 procd init `/etc/init.d/sensel-edge`：

```sh
#!/bin/sh /etc/rc.common
START=99
start() {
    cd /mnt/sensel/sensel-ot-edge-sensor
    docker compose -f docker-compose.openwrt.yml up -d
}
stop() {
    cd /mnt/sensel/sensel-ot-edge-sensor
    docker compose -f docker-compose.openwrt.yml down
}
```

```sh
chmod +x /etc/init.d/sensel-edge && /etc/init.d/sensel-edge enable
```

---

## 3. Mode B：OpenWrt 僅作鏡像來源

受限路由器（Tier 0）不跑容器，只做 port mirroring，sensor 跑在外部主機（見 `deployment-ubuntu.md` / `deployment-pi4.md`）。

1. 依 2.3 在 OpenWrt 設好鏡像，把監看流量送到一個實體埠。
2. 該埠用網路線接到 sensor 主機的擷取網卡。
3. sensor 主機照 Ubuntu/Pi 指南部署，`CAPTURE_INTERFACE` 設為對應網卡。

OpenWrt 端不需安裝本 repo；只需保留鏡像設定持久化（寫入 `/etc/config/network` 或開機 script）。

---

## 4. 驗證

```sh
# 服務健康
./scripts/health-check.sh

# 擷取確認（看到封包數遞增）
./scripts/capture-test.sh eth1

# 引擎橋接 E2E（若有開 Snort / Suricata）
./scripts/verify-snort-e2e.sh
./scripts/verify-suricata-e2e.sh
```

確認重點：

- `docker logs sensel-packet-sensor` 有 feature/event 輸出，無 capture 權限錯誤。
- Control Plane / SenseL 端可看到此 sensor 的健康與事件（DMS engine 區塊含 Snort/Suricata 狀態與 `rule_version`）。
- 重開機後容器自動回復、PCAP 寫在 `/mnt/sensel`。

---

## 5. 資源與調校建議

| 項目 | 建議 |
|------|------|
| BPF 過濾 | 設 `CAPTURE_BPF_FILTER` 只收 OT 協定（502/102/0x88b8…），大幅省 CPU |
| PCAP | Tier 1 設 `PCAP_MAX_DISK_MB=512`、`PCAP_RETENTION_MINUTES=30`；極限裝置可關閉 |
| 速率 | `CAPTURE_MAX_MBPS` 限制處理量，避免吃滿 CPU |
| 引擎 | Tier 1 只用自建規則；Snort/Suricata 限 Tier 2 |
| 記憶體 | overlay 已設 `deploy.resources.limits`，依實機微調 |

---

## 6. 疑難排解

| 問題 | 檢查 |
|------|------|
| `dockerd` 起不來 / flash 滿 | 把 `data-root` 移到 `/mnt/sensel/docker`；`df -h` |
| 無封包 | 鏡像設定（tc mirred / swconfig）、`promisc`、介面是否被 bridge 佔用 |
| 擷取權限錯誤 | packet-sensor 需 `NET_RAW`/`NET_ADMIN` + `network_mode: host`（overlay 已設） |
| 事件時間錯亂 | 啟用 `sysntpd` 校時 |
| 上傳失敗 | `SENSEL_API_URL`/`API_KEY`、TLS、防火牆 egress、`CONTROL_PLANE_MQTT_HOST` |
| 引擎 OOM | 關閉 Snort/Suricata，或升級到 Tier 2 硬體 |
| PCAP 寫內建 flash | 確認 `.env` 的 `DATA_DIR` 指向外接磁碟且已掛載 |
```
