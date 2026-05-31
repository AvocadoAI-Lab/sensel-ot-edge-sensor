# OT Lab 一鍵部署 Runbook（OT-B4）

三節點 lab 拓撲：

| 節點 | IP | 角色 | SSH |
|------|-----|------|-----|
| Pi 4 | 192.168.1.123 | EdgeX + packet sensor + SenseL agent | `edgex` / `edgex` |
| Mac CP | 192.168.1.203 | EMQX + Layer A/B/C dataplane | `avocado.ai` / `avocado@@` |
| VM SenseL | 192.168.1.108 | Portal + OT ingest API | `ubuntu` / `avocado@@` |

共用 secret：`OT_SECURITY_INGEST_SECRET=sensel-ot-ingest-lab-2026`

## 前置

```bash
brew install sshpass   # macOS
export SSHPASS='avocado@@'
export OT_REGISTRATION_TOKEN='<Avocado AI 企業邀請碼>'   # Pi 綁 tenant 用
```

三個 repo 需在同一父目錄：

```
~/guacamole-ai
~/Aristaconnector-Control-Plane
~/sensel-ot-edge-sensor
```

## 一鍵部署（全部）

```bash
cd sensel-ot-edge-sensor
chmod +x scripts/deploy-ot-lab.sh
./scripts/deploy-ot-lab.sh
```

順序：**108 SenseL → 203 Layer A/C → Pi edge → E2E 驗證**

## 分段部署

```bash
./scripts/deploy-ot-lab.sh --108-only   # SenseL + alembic
./scripts/deploy-ot-lab.sh --203-only   # EMQX + Layer B/C（含 OT-B3 profile）
./scripts/deploy-ot-lab.sh --pi-only    # Pi full stack
./scripts/deploy-ot-lab.sh --verify     # 只跑 Layer C E2E
```

## 手動部署（各 repo）

### 108 — SenseL / Portal

```bash
cd guacamole-ai
export DEPLOY_SSH_HOST=192.168.1.108 DEPLOY_SSH_USER=ubuntu SSHPASS='avocado@@'
export DEPLOY_REMOTE_REPO_DIR=/home/ubuntu/guacamole-ai
export DEPLOY_COMPOSE_SERVICES="postgres redis api"
./scripts/deploy_docker_compose.sh
ssh ubuntu@192.168.1.108 'cd /home/ubuntu/guacamole-ai && docker compose exec -T api alembic upgrade head'
```

### 203 — Control Plane Layer A + C

```bash
cd Aristaconnector-Control-Plane
export SSHPASS='avocado@@'
export CONTROL_PLANE_BASE_URL=http://192.168.1.108:8081
export OT_SECURITY_INGEST_SECRET=sensel-ot-ingest-lab-2026
./scripts/deploy-layerA-remote.sh avocado.ai@192.168.1.203
```

OT-B3 關鍵 env（`docker-compose.layerc.yml`）：

- `LAYERC_OT_ANALYZE_PROFILE=1`
- `LAYERC_BRIDGE_MODE=live`
- `AGENT_MODE=rule`
- OT episode → `evidenceops=false`，不走 Wazuh

### Pi — Edge Sensor

```bash
cd sensel-ot-edge-sensor
export SSHPASS='edgex'   # Pi 預設密碼
export OT_REGISTRATION_TOKEN='<invite-code>'   # 或於 Edge Console UI 設定
./scripts/deploy-pi-full.sh edgex@192.168.1.123
```

**Edge Console（推薦）：** `http://192.168.1.123:8090` — 設定精靈填寫企業邀請碼並註冊。

## E2E 驗證

### Layer C analyze（OT profile）

```bash
cd Aristaconnector-Control-Plane
PYTHONPATH=. python3 scripts/e2e-ot-layerc-analyze.py --layerc-url http://192.168.1.203:8001
```

預期輸出：

```json
{
  "ok": true,
  "status": "ok",
  "evidenceops": false,
  "c2_mode": "ot_security_profile"
}
```

### 端到端資料流

1. Pi 產生 OT 規則事件 → MQTT `192.168.1.203:1883`
2. mqtt-bridge → Redpanda → Layer B episode
3. layerc-bridge → `/analyze`（OT profile）→ writeback → 108 ingest
4. Portal「工控安全防護」可見事件、Layer C reasoning、感測器列表

### 健康檢查

```bash
curl -s http://192.168.1.108:8081/api/health
curl -s http://192.168.1.203:8001/health
curl -s http://192.168.1.123:8080   # Pi events viewer (lab profile only)
```

## Production Pi 部署（E3）

現場交付請使用 **production profile**（不含 mock-sensel / events-viewer）：

```bash
./scripts/deploy-pi-full.sh --profile production edgex@192.168.1.123
```

- Edge Console：`http://<pi-ip>:8090`（建議設定 `EDGE_CONSOLE_PASSWORD`）
- 註冊後驗證：`EDGE_CONSOLE_URL=... INVITE_CODE=... SENSEL_API_KEY=... ./scripts/verify-pi-onboarding.sh`
- Production 預設 `MQTT_REQUIRE_TENANT=true`：未完成 Portal 註冊前不會以 `default` tenant 北向 MQTT

進階設定（BPF / 擷取介面）可在 Edge Console「進階」分頁修改，寫入 `data/agent/capture.env` 後重啟 packet-sensor。

## 常見問題

| 症狀 | 處理 |
|------|------|
| Layer C 422 / Wazuh 錯誤 | 確認 `LAYERC_OT_ANALYZE_PROFILE=1`，重建 `layerc-api` + `layerc-bridge` |
| 事件 tenant=default | Pi 設 `OT_REGISTRATION_TOKEN` 後重 deploy |
| 重複事件 | Sprint B upsert 已處理；bridge + writeback 雙 POST 會 dedup |
| 203 docker 找不到 | SSH 後加 PATH：`export PATH="/Applications/Docker.app/Contents/Resources/bin:$PATH"` |

## Git 分支對照

| Repo | Branch | Sprint |
|------|--------|--------|
| guacamole-ai | `SenseL-Guardian` | A + B（Portal、ingest、sensor） |
| Aristaconnector-Control-Plane | `ot` | B3（Layer C OT profile） |
| sensel-ot-edge-sensor | `main` | Edge MVP + Pi deploy |
