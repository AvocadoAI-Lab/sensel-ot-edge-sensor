<<<<<<< Updated upstream
# IEC 61850 Lab

## 快速驗證（無 Docker）

```bash
make verify-61850
# 或
python3 scripts/61850-selftest.py
```

## Live lab

```bash
make up-lab-61850
export CAPTURE_INTERFACE=eth0
export CAPTURE_BPF_FILTER='(ether proto 0x88b8) or (tcp port 102)'
make build && make up-lab-61850
make verify-61850
```

Pi4 上 `mms-publisher` 會在 `eth0` 週期性送 TCP/102 MMS write probe；`packet-sensor` 擷取後寫入 `data/assets/iec61850-mms-summary.json`。
amd64 開發機若要用完整 MMS server，可加 `--profile lab-mms-amd64` 啟用 `61850-sim-mms`。

## pcap replay

```bash
python3 lab/61850/generate_sample_pcap.py
./scripts/61850-pcap-replay.sh eth0
```

## 元件

| 路徑 | 說明 |
|------|------|
| `goose-publisher/` | Scapy GOOSE 發送器（host network，ARM OK） |
| `mms-publisher/` | Scapy MMS TCP/102 探測（host network，ARM OK，取代 amd64 61850-sim） |
| `pcap/goose_sample.pcap` | 樣本 GOOSE 封包 |
| `docker-compose.lab-61850.yml` | GOOSE + MMS publishers；EdgeX **僅 mqtt-feature**（modbus/phase2 預設關閉） |
| `config/edgex/lab-61850/` | `device-mqtt` 專用 devices/profiles |
| `scripts/apply-lab-61850-edgex.sh` | 清除 metadata 殘留設備、重啟 device-mqtt |
=======
# IEC 61850 Lab

## 快速驗證（無 Docker）

```bash
make verify-61850
# 或
python3 scripts/61850-selftest.py
```

## Live lab

```bash
make up-lab-61850
export CAPTURE_INTERFACE=eth0
export CAPTURE_BPF_FILTER='(ether proto 0x88b8) or (tcp port 102)'
make build && make up-lab-61850
make verify-61850
```

Pi4 上 `mms-publisher` 會在 `eth0` 週期性送 TCP/102 MMS write probe；`packet-sensor` 擷取後寫入 `data/assets/iec61850-mms-summary.json`。
amd64 開發機若要用完整 MMS server，可加 `--profile lab-mms-amd64` 啟用 `61850-sim-mms`。

## pcap replay

```bash
python3 lab/61850/generate_sample_pcap.py
./scripts/61850-pcap-replay.sh eth0
```

## 元件

| 路徑 | 說明 |
|------|------|
| `goose-publisher/` | Scapy GOOSE 發送器（host network，ARM OK） |
| `mms-publisher/` | Scapy MMS TCP/102 探測（host network，ARM OK，取代 amd64 61850-sim） |
| `pcap/goose_sample.pcap` | 樣本 GOOSE 封包 |
| `docker-compose.lab-61850.yml` | GOOSE + MMS publishers；EdgeX **僅 mqtt-feature**（modbus/phase2 預設關閉） |
| `config/edgex/lab-61850/` | `device-mqtt` 專用 devices/profiles |
| `scripts/apply-lab-61850-edgex.sh` | 清除 metadata 殘留設備、重啟 device-mqtt |
>>>>>>> Stashed changes
