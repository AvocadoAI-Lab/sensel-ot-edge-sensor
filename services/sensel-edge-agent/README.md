# SenseL Edge Agent

邊緣與 SenseL 平台的通訊代理。

## 職責

| 模組 | 職責 |
|------|------|
| `api/` | 註冊、事件、遙測、健康 API 客戶端 |
| `policy/` | 遠端政策同步（FR-10） |
| `health/` | Pi 資源、擷取統計、服務狀態 |
| `upload/` | 離線緩衝與重試上傳（NFR-3） |

## API 端點

- `POST /api/v1/edge-sensors/register`
- `POST /api/v1/ot/security-events`
- `POST /api/v1/ot/telemetry`
- `POST /api/v1/edge-sensors/health`

## 執行

```bash
python -m src.main
```
