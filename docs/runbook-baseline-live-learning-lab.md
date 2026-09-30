# Baseline Live Learning — Lab Runbook（P4）

對應 PRD：[guacamole-ai/docs/PRD_OT_BASELINE_LIVE_LEARNING.md](../../guacamole-ai/docs/PRD_OT_BASELINE_LIVE_LEARNING.md) §13 驗收標準。

## Lab 拓撲

| 節點 | IP | 角色 |
|------|-----|------|
| SenseL CP | 192.168.1.108 | Portal + session/profile BFF + ingest |
| Layer A/C | 192.168.1.203 | EMQX + mqtt-bridge + Layer B/C + CTA aggregator |
| Pi Edge | 192.168.1.124 | packet-sensor + edge-agent + Edge Console |

常數：

- Tenant：`company-a9ae1234648ee138`
- Workspace ID：`6`（Avocado AI 企業工作區）
- MQTT operational：`sensel/{tenant}/cmd/{sensor_id}/operational`
- MQTT baseline profile：`sensel/{tenant}/baseline/{profile_id}`
- Observe tick 上行：`ot-edge/{tenant}/{site}/{sensor}/baseline/observe/v1`

## 前置

```bash
brew install sshpass
cd sensel-ot-edge-sensor
cp .env.lab.example .env.lab   # 填 PORTAL_EMAIL / PORTAL_PASSWORD
export SSHPASS='avocado@@'
export OT_REGISTRATION_TOKEN='<企業邀請碼>'
export TENANT_ID='company-a9ae1234648ee138'
```

三 repo 同層目錄：`guacamole-ai`、`Aristaconnector-Control-Plane`、`sensel-ot-edge-sensor`。

### 必要 env（108 / 203 / Pi）

| 主機 | 變數 | 說明 |
|------|------|------|
| 108 | `MQTT_ENABLED=true` | operational + baseline profile publish |
| 108 | `alembic upgrade head` | migration 090/091 sessions + profiles |
| 203 | mqtt-bridge topic map | `baseline/observe/v1` → Kafka |
| 203 | `run_baseline_observe_ingest.py` | 108 internal ingest 常駐 |
| Pi | `POLICY_SYNC_MQTT_ENABLED=true` | 訂閱 operational + baseline + detection policy |
| Pi | `BASELINE_PROFILE_MQTT_ENABLED=true` | 訂閱 `sensel/{tenant}/baseline/+` |
| Pi | `OBSERVE_TICK_ENABLED=true` | 60s 北向 tick |

一鍵部署（含 migration）：

```bash
./scripts/deploy-ot-lab.sh --cta    # 108 + 203 + Pi .124 + CTA verify
# 或分段
./scripts/deploy-ot-lab.sh --108-only
./scripts/deploy-ot-lab.sh --203-only
PI_TARGET=edgex@192.168.1.124 ./scripts/deploy-ot-lab.sh --pi-only
```

203 上需啟動 baseline observe ingest（Layer A）：

```bash
cd Aristaconnector-Control-Plane
CONTROL_PLANE_BASE_URL=http://192.168.1.108:8081 \
OT_SECURITY_INGEST_SECRET=sensel-ot-ingest-lab-2026 \
python3 scripts/run_baseline_observe_ingest.py
```

---

## 驗收流程（§13 對照）

### 0. 靜態 gate（部署後立即跑）

```bash
./scripts/verify-baseline-live-learning-lab.sh
./scripts/verify-cta-lab.sh
```

預期：CP / Layer C / Portal BFF（sessions、profiles、operational-state）、Edge Console `/api/status`、CTA API 皆 OK。

**Topology E2E（需 `.env.lab` Portal 帳密）：**

```bash
./scripts/verify-baseline-live-learning-lab.sh --expect-topology
```

**EDR match（PRD §11.2 #6，Windows HMI ≥0.9）：**

```bash
./scripts/verify-topology-edr-match-lab.sh --scenario windows-hmi
# 或併入 baseline gate：
./scripts/verify-baseline-live-learning-lab.sh --expect-topology --expect-edr-match --edr-match-scenario windows-hmi
```

**Full gate（detect delta + topology views + EDR，PRD §11.2 一鍵）：**

```bash
./scripts/verify-topology-full-gate-lab.sh
# 已確認 Pi delta 後快速重驗：
./scripts/verify-topology-full-gate-lab.sh --skip-delta-wait
```

**M2 ingest-time（mirror 10.x 無 seed，PRD §4.5.6）：**

```bash
# 1) 在 108 為 agent 003 加上 mirror 次要 IP（雙 homing 模擬）
SSHPASS=avocado@@ ./scripts/lab-setup-m2-mirror-ip.sh

# 2) 嚴格驗收 M2 match
./scripts/verify-topology-m2-ingest-lab.sh --strict --expect-agent-id 003
```

**§11.3 資產門檻 + 完整 gate：**

```bash
./scripts/seed-topology-lab-assets.sh
./scripts/verify-topology-full-gate-lab.sh --skip-delta-wait --seed-assets --expect-m2-ingest \
  --min-topology-assets 10 --min-topology-conduits 5
```

**PRD §11 一鍵完整驗收（topology + M2 + CVE strict + §11.3 門檻）：**

```bash
./scripts/verify-topology-full-gate-lab.sh --prd-11
# 或
./scripts/deploy-ot-lab.sh --verify-topology-prd11
```

簽核文件：[`guacamole-ai/docs/OT_TOPOLOGY_GRAPH_LAB_SIGNOFF.md`](../guacamole-ai/docs/OT_TOPOLOGY_GRAPH_LAB_SIGNOFF.md)

**108 重開機持久化（netplan 10.88 + Wazuh connector + M2/CVE gate）：**

```bash
SSHPASS=avocado@@ ./scripts/verify-lab-108-reboot-persist-lab.sh --reboot
```

預期：`dashboard` 回傳 `zone_asset_counts` + `topology_kpi`；`GET /topology` nodes≥10、edges≥5。  
歷史 tick 若早於 topology 部署，可於 108 執行：

```bash
docker compose exec api bash -c 'cd sensel_control_plane && PYTHONPATH=/app python3 /app/scripts/backfill_topology_from_baseline_ticks.py --tenant-id company-a9ae1234648ee138 --sensor-id ot-edge-001 --limit 30'
```

`baseline-observe-ticks` ingest 回應應含 `topology_ingested: true`（side-ingest）。

### 1. Listen（eth0）→ SSE / tick 每分鐘；無 security events

1. Portal → **工控安全防護 → 感測器** → 點選 Pi 感測器
2. **開始監聽**，interface=`eth0`（或 lab mirror 介面）
3. 觀測 **動態觀測 tick** 列表每 ~60s 增加一筆
4. 可選：`curl -N` SSE  
   `GET /api/v1/smb/workspaces/6/ot-security/sessions/{id}/stream`（Bearer + X-Workspace-Id）
5. 確認 Pi 無新 security event：

```bash
ssh edgex@192.168.1.124 'tail -5 ~/sensel-ot-edge-sensor/data/assets/security-events.jsonl'
# listen 期間不應新增 OT-00x 列
```

6. **CTA baseline**（listen 期間 detect 不應成長）：

```bash
./scripts/verify-baseline-live-learning-lab.sh --cta-snapshot /tmp/cta-listen-before.json
# ... 等待 3–5 分鐘 listen ...
./scripts/verify-baseline-live-learning-lab.sh --cta-compare /tmp/cta-listen-before.json --max-detect-delta 0
```

### 2. Listen → Learning；仍無 events

1. Portal 按 **升級為學習**（或 stop 後 **開始學習**）
2. Edge Console header 應顯示 **學習中**
3. tick 的 `snapshot` 欄位在 learning 時應含 `sensel.baseline/1` 摘要
4. 仍無 `security-events.jsonl` 新增

### 3. Learning ≥5 min → Stop → Profile draft → Approve → Apply → Detect

1. 至少 **5 個 tick**（預設 `min_ticks_required=5`）後按 **正常結束**
2. **Baseline Profiles** 分頁應出現 **draft** profile（learning stop 自動產生）
3. **核准** → **套用 (Detect)**  
   - MQTT：`sensel.baseline.profile.v1` + `operational_mode=detect`
4. 驗證：

```bash
./scripts/verify-baseline-live-learning-lab.sh \
  --expect-mode detect \
  --expect-profile-id '<profile-uuid>'
```

Pi 上確認 artifact：

```bash
ssh edgex@192.168.1.124 'cat ~/sensel-ot-edge-sensor/data/agent/baseline-profile.json | python3 -m json.tool | head -20'
ssh edgex@192.168.1.124 'cat ~/sensel-ot-edge-sensor/data/agent/operational-mode.json | python3 -m json.tool'
```

### 4. Detect 事件含 `baseline_profile_id`

觸發 lab 流量（GOOSE/MMS 模擬或 mirror 異常），確認 Portal 事件或 Layer C episode context：

```bash
./scripts/verify-baseline-live-learning-lab.sh --expect-mode detect --expect-event-metadata
```

事件 metadata 鏈路：edge `context` → mqtt-bridge → Layer B → Layer C ingest → CP `raw_event`。

### 5. 重複 start active session → 409

```bash
./scripts/verify-baseline-live-learning-lab.sh --probe-409 --sensor-id <sensor_id>
```

### 6. Listen/Learning 期間 CTA detect 不增長

見步驟 1 的 `--cta-snapshot` / `--cta-compare`。  
原理：packet-sensor `_emit()` 在 listen/learning 閘掉告警，coverage counter 不 increment，CTA aggregator 的 `detected` 計數不應上升。

### 7. Edge 重啟 → session interrupted

```bash
ssh edgex@192.168.1.124 'cd ~/sensel-ot-edge-sensor && docker compose restart sensel-edge-agent packet-sensor'
```

180s 內 CP `SessionReconciler` 將 session 標為 `interrupted`；不應自動產生 profile；須 **新 session**。

### 8. 3 min 無 tick → interrupted

停止 mirror 流量或斷 MQTT，等待 >180s，確認 session `interrupt_reason=tick_timeout`。

### 9. guacamole 重啟 → reconcile

```bash
ssh ubuntu@192.168.1.108 'cd ~/guacamole-ai && docker compose restart api'
```

30s 內無 orphan `active` session（startup reconcile）。

### 11. Edge Console 模式 badge

- Cloud 下發 learning → `http://192.168.1.124:8090` header **學習中**
- apply detect → **偵測中** + profile 版本（若有）

```bash
curl -s http://192.168.1.124:8090/api/status | python3 -m json.tool | grep -A6 operational_mode
```

---

## CTA 联调要点

| 階段 | CTA `summary.detected` | Edge coverage JSONL |
|------|------------------------|---------------------|
| listen | 不增長 | 不寫入 |
| learning | 不增長 | 不寫入 |
| detect | 可增長 | `coverage-counters.json` 隨 OT 規則命中更新 |

Portal：**工控安全防護 → CTA 覆蓋率** 應與 Layer C API 一致：

```bash
curl -s "http://192.168.1.203:8001/api/cta/coverage?tenant_id=company-a9ae1234648ee138" | python3 -m json.tool
```

詳細 CTA PoC 見 [continuous-trust-assurance-poc.md](continuous-trust-assurance-poc.md) §9.14 與本 runbook §CTA baseline 小節。

---

## 一鍵 verify（deploy-ot-lab 整合）

```bash
./scripts/deploy-ot-lab.sh --verify-baseline-live-learning
./scripts/deploy-ot-lab.sh --baseline-live-learning   # deploy + verify
```

---

## 故障排除

| 症狀 | 處理 |
|------|------|
| observe tick 不到 CP | 203 ingest script、bridge topic、`tenant_id` 綁定 |
| Portal 409 無法 start | 先 stop/abort 現有 session 或 discard interrupted |
| apply 503 | 108 `MQTT_ENABLED` 或 `mqtt_dry_run` |
| detect 無 baseline_profile_id | 確認 P3 edge enrich + bridge canonicalize |
| CTA 在 listen 仍漲 | 查 Pi mode 是否誤為 detect；重啟 packet-sensor reload mode |
| Edge badge 不更新 | `/api/status` 輪詢 30s；查 `operational-mode.json` |

---

## 相關腳本

| 腳本 | 用途 |
|------|------|
| `scripts/verify-baseline-live-learning-lab.sh` | P4 驗收集 |
| `scripts/verify-cta-lab.sh` | CTA API + aggregator |
| `scripts/deploy-ot-lab.sh` | 三節點部署 |
| `Aristaconnector-Control-Plane/scripts/run_baseline_observe_ingest.py` | tick → 108 ingest |
