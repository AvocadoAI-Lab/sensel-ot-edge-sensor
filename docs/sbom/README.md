# SenseL OT Edge Sensor — SBOM

產生時間：2026-06-13 01:55 （UTC+8）  
產生工具：[syft](https://github.com/anchore/syft) v1.45.1  
格式：CycloneDX JSON（每個映像一份）+ 對應的 `.txt` 表格  

> 完整 SBOM 是對**已建置 / 已拉取的容器映像**掃描而得，涵蓋 OS 套件層與所有 transitive 相依，而非僅 `requirements.txt` 的直接相依。

## 合併版 SBOM（建議上傳用）

[`sbom-sensel-ot-edge-sensor-merged.cdx.json`](sbom-sensel-ot-edge-sensor-merged.cdx.json) —
把 16 個映像合併成單一 CycloneDX 1.6 BOM，適合上傳到 Dependency-Track 等平台。

- 16 個映像以 `container` 元件呈現，並透過 `dependencies` 連到各自的套件。
- 套件依 purl（或 name+version+type）**去重**；每個套件用 `sensel:source-image` property 記錄它出現在哪些映像（provenance）。
- 為控制檔案大小，合併版**省略 `file` 類元件**（個別檔案雜湊），保留 `library` / `application` / `operating-system` / `container`。
- 內容：container 16、application 12、operating-system 5、library 503（去重後）。

如需含 `file` 層的完整資料，請用下方各映像的單獨 SBOM。

## 映像總覽

| 映像 | 來源 | 作業系統基底 | 套件(library) | 應用(app) | 檔案(file) | 總元件 | SBOM 檔 |
|---|---|---|--:|--:|--:|--:|---|
| `sensel-ot-edge-sensor-edge-console:latest` | 自建 | debian 12 | 192 | 15 | 4130 | 4338 | [`sbom-service-edge-console.cdx.json`](sbom-service-edge-console.cdx.json) |
| `sensel-ot-edge-sensor-packet-sensor:latest` | 自建 | debian 12 | 163 | 15 | 4953 | 5132 | [`sbom-service-packet-sensor.cdx.json`](sbom-service-packet-sensor.cdx.json) |
| `sensel-ot-edge-sensor-sensel-edge-agent:latest` | 自建 | debian 12 | 141 | 15 | 3319 | 3476 | [`sbom-service-sensel-edge-agent.cdx.json`](sbom-service-sensel-edge-agent.cdx.json) |
| `sensel-ot-edge-sensor-vpn-client:latest` | 自建 | debian 12 | 125 | 0 | 3972 | 4098 | [`sbom-service-vpn-client.cdx.json`](sbom-service-vpn-client.cdx.json) |
| `postgres:16.3-alpine3.20` | 第三方 | alpine 3.20.2 | 49 | 1 | 569 | 620 | [`sbom-thirdparty-postgres.cdx.json`](sbom-thirdparty-postgres.cdx.json) |
| `eclipse-mosquitto:2.0.21` | 第三方 | alpine 3.21.3 | 18 | 0 | 581 | 600 | [`sbom-thirdparty-mosquitto.cdx.json`](sbom-thirdparty-mosquitto.cdx.json) |
| `iotechsys/modbus-sim:1.1.0` | 第三方 | alpine 3.16.6 | 72 | 1 | 4915 | 4989 | [`sbom-thirdparty-modbus-sim.cdx.json`](sbom-thirdparty-modbus-sim.cdx.json) |
| `edgexfoundry/core-keeper:4.0.0` | 第三方 | alpine 3.20.6 | 117 | 0 | 79 | 197 | [`sbom-thirdparty-edgex-core-keeper.cdx.json`](sbom-thirdparty-edgex-core-keeper.cdx.json) |
| `edgexfoundry/core-metadata:4.0.0` | 第三方 | alpine 3.20.6 | 117 | 0 | 79 | 197 | [`sbom-thirdparty-edgex-core-metadata.cdx.json`](sbom-thirdparty-edgex-core-metadata.cdx.json) |
| `edgexfoundry/core-data:4.0.0` | 第三方 | alpine 3.20.6 | 117 | 0 | 79 | 197 | [`sbom-thirdparty-edgex-core-data.cdx.json`](sbom-thirdparty-edgex-core-data.cdx.json) |
| `edgexfoundry/core-common-config-bootstrapper:4.0.0` | 第三方 | alpine 3.20.6 | 55 | 0 | 79 | 135 | [`sbom-thirdparty-edgex-core-common-config-bootstrapper.cdx.json`](sbom-thirdparty-edgex-core-common-config-bootstrapper.cdx.json) |
| `edgexfoundry/device-modbus:4.0.0` | 第三方 | alpine 3.20.6 | 120 | 0 | 79 | 200 | [`sbom-thirdparty-edgex-device-modbus.cdx.json`](sbom-thirdparty-edgex-device-modbus.cdx.json) |
| `edgexfoundry/device-mqtt:4.0.0` | 第三方 | alpine 3.20.6 | 118 | 0 | 79 | 198 | [`sbom-thirdparty-edgex-device-mqtt.cdx.json`](sbom-thirdparty-edgex-device-mqtt.cdx.json) |
| `edgexfoundry/device-opc-ua:4.0.0 (phase2)` | 第三方 | alpine 3.20.6 | 124 | 0 | 90 | 215 | [`sbom-thirdparty-edgex-device-opc-ua.cdx.json`](sbom-thirdparty-edgex-device-opc-ua.cdx.json) |
| `edgexfoundry/device-s7:4.0.0 (phase2)` | 第三方 | alpine 3.20.6 | 119 | 0 | 79 | 199 | [`sbom-thirdparty-edgex-device-s7.cdx.json`](sbom-thirdparty-edgex-device-s7.cdx.json) |
| `edgexfoundry/edgex-ui:4.0.0 (lab-ui)` | 第三方 | alpine 3.20.6 | 116 | 0 | 79 | 196 | [`sbom-thirdparty-edgex-ui.cdx.json`](sbom-thirdparty-edgex-ui.cdx.json) |

全部 16 個映像，library 類元件合計約 **1763** 個（不同映像間有重複）。

## 自建服務的 Python 套件（含解析後實際版本）

### edge-console

| 套件 | 版本 |
|---|---|
| annotated-doc | 0.0.4 |
| annotated-types | 0.7.0 |
| anyio | 4.13.0 |
| autocommand | 2.2.2 |
| backports-tarfile | 1.2.0 |
| certifi | 2026.5.20 |
| click | 8.4.1 |
| fastapi | 0.136.3 |
| h11 | 0.16.0 |
| httpcore | 1.0.9 |
| httptools | 0.8.0 |
| httpx | 0.28.1 |
| idna | 3.18 |
| importlib-metadata | 8.0.0 |
| inflect | 7.3.1 |
| jaraco-collections | 5.1.0 |
| jaraco-context | 5.3.0 |
| jaraco-functools | 4.0.1 |
| jaraco-text | 3.12.1 |
| more-itertools | 10.3.0 |
| packaging | 24.2 |
| pip | 24.0 |
| platformdirs | 4.2.2 |
| pydantic | 2.13.4 |
| pydantic-core | 2.46.4 |
| python-dotenv | 1.2.2 |
| pyyaml | 6.0.3 |
| setuptools | 79.0.1 |
| starlette | 1.3.1 |
| tomli | 2.0.1 |
| typeguard | 4.3.0 |
| typing-extensions | 4.12.2 |
| typing-extensions | 4.15.0 |
| typing-inspection | 0.4.2 |
| uvicorn | 0.49.0 |
| uvloop | 0.22.1 |
| watchfiles | 1.2.0 |
| websockets | 16.0 |
| wheel | 0.45.1 |
| zipp | 3.19.2 |

### packet-sensor

| 套件 | 版本 |
|---|---|
| aiosqlite | 0.22.1 |
| annotated-types | 0.7.0 |
| anyio | 4.13.0 |
| autocommand | 2.2.2 |
| backports-tarfile | 1.2.0 |
| certifi | 2026.5.20 |
| h11 | 0.16.0 |
| httpcore | 1.0.9 |
| httpx | 0.28.1 |
| idna | 3.18 |
| importlib-metadata | 8.0.0 |
| inflect | 7.3.1 |
| jaraco-collections | 5.1.0 |
| jaraco-context | 5.3.0 |
| jaraco-functools | 4.0.1 |
| jaraco-text | 3.12.1 |
| more-itertools | 10.3.0 |
| packaging | 24.2 |
| paho-mqtt | 2.1.0 |
| pip | 24.0 |
| platformdirs | 4.2.2 |
| pydantic | 2.13.4 |
| pydantic-core | 2.46.4 |
| pydantic-settings | 2.14.1 |
| python-dotenv | 1.2.2 |
| pyyaml | 6.0.3 |
| scapy | 2.7.0 |
| setuptools | 79.0.1 |
| tomli | 2.0.1 |
| typeguard | 4.3.0 |
| typing-extensions | 4.12.2 |
| typing-extensions | 4.15.0 |
| typing-inspection | 0.4.2 |
| wheel | 0.45.1 |
| zipp | 3.19.2 |

### sensel-edge-agent

| 套件 | 版本 |
|---|---|
| aiosqlite | 0.22.1 |
| annotated-types | 0.7.0 |
| anyio | 4.13.0 |
| autocommand | 2.2.2 |
| backports-tarfile | 1.2.0 |
| certifi | 2026.5.20 |
| h11 | 0.16.0 |
| httpcore | 1.0.9 |
| httpx | 0.28.1 |
| idna | 3.18 |
| importlib-metadata | 8.0.0 |
| inflect | 7.3.1 |
| jaraco-collections | 5.1.0 |
| jaraco-context | 5.3.0 |
| jaraco-functools | 4.0.1 |
| jaraco-text | 3.12.1 |
| more-itertools | 10.3.0 |
| packaging | 24.2 |
| paho-mqtt | 2.1.0 |
| pip | 24.0 |
| platformdirs | 4.2.2 |
| psutil | 7.2.2 |
| pydantic | 2.13.4 |
| pydantic-core | 2.46.4 |
| pydantic-settings | 2.14.1 |
| python-dotenv | 1.2.2 |
| pyyaml | 6.0.3 |
| setuptools | 79.0.1 |
| tomli | 2.0.1 |
| typeguard | 4.3.0 |
| typing-extensions | 4.12.2 |
| typing-extensions | 4.15.0 |
| typing-inspection | 0.4.2 |
| wheel | 0.45.1 |
| zipp | 3.19.2 |

### vpn-client

（無 pypi 套件）

## 重新產生方式

```bash
# 自建映像
docker compose build
syft sensel-ot-edge-sensor-edge-console:latest -o cyclonedx-json=docs/sbom/sbom-service-edge-console.cdx.json
# 第三方映像（syft 會自行拉取）
syft postgres:16.3-alpine3.20 -o cyclonedx-json=docs/sbom/sbom-thirdparty-postgres.cdx.json
```

## 後續：漏洞掃描

已完成 grype v0.114.0 掃描，詳見 **[VULNERABILITY-REPORT.md](VULNERABILITY-REPORT.md)**。

```bash
grype sbom:docs/sbom/sbom-sensel-ot-edge-sensor-merged.cdx.json -o table
grype sbom:docs/sbom/sbom-service-packet-sensor.cdx.json -o json > docs/sbom/vuln-packet-sensor.json
```
