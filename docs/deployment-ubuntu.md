# Ubuntu 部署指南（MVP / Lab）

## 需求

- Ubuntu Server 22.04 LTS 或 24.04 LTS（64-bit）
- Docker 24+、Docker Compose v2
- 建議 4 CPU / 8 GB RAM / 64 GB SSD
- 雙網卡（或單網卡 + USB Ethernet 作 mirror）

## 安裝步驟

```bash
# 1. 安裝 Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER

# 2. Clone 專案
git clone <repo-url> sensel-ot-edge-sensor
cd sensel-ot-edge-sensor

# 3. 設定
cp .env.example .env
cp config/sensor.yaml.example config/sensor.yaml
cp config/policy/baseline.example.json config/policy/baseline.json
# 編輯 .env：SENSEL_API_URL、CAPTURE_INTERFACE 等

# 4. Mirror 介面（實體 SPAN 連線後）
sudo ip link set eth1 promisc on
# 或執行 deploy/ubuntu/setup.sh

# 5. 啟動
docker compose build
docker compose up -d

# 6. 驗證
./scripts/health-check.sh
./scripts/capture-test.sh eth1
```

## 單網卡 Lab 模式

若僅有一張網卡，可將 `CAPTURE_INTERFACE` 設為與管理相同介面，並用 `tcpdump` 驗證本機流量（不建議生產環境）。

## 與 EdgeX 整合

Sprint 1 已合併 EdgeX 4.0 compose（`edgex/docker-compose.edgex.yml`）。`make up` 會一併啟動：

- Core：keeper、metadata、data
- Device：modbus、mqtt（訂閱 `local-mqtt`）
- 可選 UI：`make up-ui` → http://127.0.0.1:4000

設備/profile 設定見 `config/edgex/`。

### Modbus lab 驗證（S1-02）

```bash
make up
# 等待 EdgeX 與 device-modbus 啟動（約 1–2 分鐘）
make verify-modbus
```

成功時會看到 `relay-01` 在 core-data 的 event 讀數。現場部署請改 `config/edgex/devices/modbus-relay.yaml` 的 `Address`/`Port`，並停用 `modbus-simulator`。

## 疑難排解

| 問題 | 檢查 |
|------|------|
| 無封包 | `CAPTURE_INTERFACE`、promisc、SPAN 設定 |
| 權限錯誤 | packet-sensor 需 `NET_RAW` / host network |
| SenseL 連線失敗 | TLS、API key、防火牆 egress |
