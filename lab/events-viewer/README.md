# Lab Events Viewer (Pi4 / local)

Pi lab 用輕量 Web UI 查詢 OT 安全事件，不需 SenseL 平台。

## URL

```text
http://<host>:8080
```

Pi4 範例：`http://192.168.1.123:8080`

## 資料來源

| 分頁/API | 檔案 | 說明 |
|----------|------|------|
| 本地 | `data/assets/security-events.jsonl` | packet-sensor 偵測寫入 |
| 已上傳 | `data/assets/uploaded-events.jsonl` | mock-sensel 收到 Edge Agent POST 後持久化 |
| Summaries | `iec61850-*-summary.json` | GOOSE/MMS 60s 窗口統計 |

## API

- `GET /api/health`
- `GET /api/events/local?limit=50&rule_id=OT-016`
- `GET /api/events/uploaded?limit=50`
- `GET /api/summaries`

## 啟動

隨 Pi lab stack 一併啟動（`docker-compose.pi-lab.yml`）：

```bash
docker compose -f docker-compose.yml -f docker-compose.pi4.yml \
  -f docker-compose.pi-lab.yml -f docker-compose.lab-61850.yml up -d --build
```

或本機 lab（無 61850）：

```bash
docker compose -f docker-compose.yml -f docker-compose.pi-lab.yml up -d events-viewer mock-sensel
```

## 安全注意

Lab 用途綁定 `8080` 於 LAN；正式部署應加 auth / 僅 management VLAN。
