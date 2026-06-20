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
# ⚠️ SURICATA_INTERFACE 必須等於 packet-sensor 的 CAPTURE_INTERFACE（通常 eth0），
#    否則 Suricata 監看的介面上沒有 OT 流量，永遠不會告警。
SURICATA_INTERFACE=eth0 \
docker compose -f docker-compose.yml -f docker-compose.pi4.yml \
  -f docker-compose.suricata.yml up -d
```

`docker-compose.pi4.yml` 已為 `suricata` 服務設定資源上限（1G / 1.5 CPU），可依實機微調。
引擎為重量級 sidecar，建議僅在 Pi4 8GB + 外接 SSD + 良好散熱下做 Lab/PoC；高流量現場請用 x86。

> Snort 仍可在 x86 sensor 上使用；引擎狀態與規則版本會顯示在 Edge Console「落地狀態」面板。

### 部署前必檢清單（避免常見坑）

實機部署 Suricata 時，以下四點是踩過的雷，務必先確認：

1. **介面要對**：`SURICATA_INTERFACE` 必須是「真的承載 OT 流量」的介面。
   先確認 packet-sensor 抓哪個介面：
   ```bash
   docker inspect sensel-packet-sensor --format '{{range .Config.Env}}{{println .}}{{end}}' | grep CAPTURE_INTERFACE
   ```
   兩者要一致（本專案 lab 為 `eth0`）。overlay 預設已改為 `eth0`。
2. **`/etc/suricata` 必須可寫**：`jasonish/suricata` 啟動時會把 `classification.config`
   等預設檔 seed 進 `/etc/suricata`；若把該目錄掛成唯讀（`:ro`）會 crash-loop
   （`cannot create ... Read-only file system`）。overlay 已改為可寫掛載，勿再加 `:ro`。
3. **packet-sensor 映像要含 EVE 橋接**：Suricata 只負責寫 `eve.json`，真正把 alert 轉成
   SenseL 事件的是 packet-sensor 內的 `SuricataEveSource`
   （`services/packet-sensor/src/detection/external_engine/suricata_source.py`）。
   若現場用的是**舊映像**（例如只 sync 過 edge-agent 而沒重建 packet-sensor），會看到
   Suricata 在跑、`eve.json` 有資料，但 `suricata-events.jsonl` 一直是空的。此時需重建：
   ```bash
   docker compose -f docker-compose.yml -f docker-compose.suricata.yml build packet-sensor
   docker compose ... up -d packet-sensor
   ```
   確認 log 出現：`Suricata source enabled — eve_json=... output=.../suricata-events.jsonl`。
4. **要有 OT 流量才會告警**：Suricata 是被動偵測，沒有對應流量就不會有 alert。lab 環境需
   確認 `sensel-mms-publisher` / `sensel-goose-publisher` 在運行（它們以 host network 把
   MMS/GOOSE 注入 `eth0`）：
   ```bash
   docker compose ... up -d mms-publisher goose-publisher
   ```

### 驗證（端到端）

```bash
# 1) Suricata 引擎啟動、規則載入
docker logs sensel-suricata 2>&1 | grep -E "Engine started|rules successfully loaded"

# 2) packet-sensor 橋接：eve.json → suricata-events.jsonl
docker exec sensel-packet-sensor sh -lc 'tail -1 /app/data/assets/suricata-events.jsonl'

# 3) edge-agent 引擎健康（應為 active=true、last_event_age 很小）
docker exec sensel-edge-agent sh -lc 'cat /app/data/agent-runtime.json' \
  | python3 -c "import sys,json;[print(e) for e in json.load(sys.stdin)['engines'] if e['name']=='suricata']"

# 4) 北向發佈
docker logs sensel-edge-agent 2>&1 | grep "SURICATA_ALERT" | tail -3
```

> 注意：Suricata alert 北向後會經 Aristaconnector 推論層評分；**良性流量**（DNS/LDAP 等，
> `reason=benign_filtered`）會被過濾**不寫入 Portal**，這是預期行為。只有達門檻的事件才會
> 出現在 Portal 的 OT 事件時間軸（與內建 OT-0xx 事件同一處）。

### Suricata 監聽多個介面

Suricata 支援同時監看多個介面（例如 OT 流量在某個 docker bridge `br-xxxx`，IT 流量在
`eth0`）。本專案的 lab publishers 用 **host network 注入 eth0**，所以單一 `eth0` 就能收到
GOOSE/MMS/IT 全部流量，**不需要多介面**。若你的現場 OT 是走容器間的 bridge 網路，才需要多
介面，做法是在 `config/suricata/suricata.yaml` 加入 `af-packet` 區塊並列出多個介面，然後把
overlay command 的 `-i` 拿掉讓 Suricata 從設定檔讀取：

```yaml
# config/suricata/suricata.yaml
af-packet:
  - interface: eth0          # IT 區段
    cluster-id: 98
    cluster-type: cluster_flow
  - interface: br-75a5cad1560a   # OT 容器 bridge（用 `docker network ls` / `ip link` 查名稱）
    cluster-id: 99
    cluster-type: cluster_flow
```

> 找出 OT 流量所在的 bridge：`docker network inspect <network>` 看 container 子網，
> 對應 `ip -o link` 的 `br-<id>`。監看 bridge 需要 Suricata 容器能看到該介面（已用
> `network_mode: host` + `NET_ADMIN/NET_RAW`，可直接指定 `br-*`）。

## 注意事項

- Pi4 僅建議 Lab / PoC；高流量現場請規劃 industrial gateway 或 x86
- 避免在 SD 卡上長期寫入 PCAP；使用 SSD
- 散熱與穩定電源影響持續擷取效能
- Pi4 上的外部 IDS 引擎請用 Suricata（Snort 鏡像無 arm64，見上節）
