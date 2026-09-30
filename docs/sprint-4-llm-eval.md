# Sprint 4 — OT LLM Enrich 人工評分（S5-E2）

**目的：** 驗收 203 `gemma2:2b` episode enrich POC — 10 個 lab episode 人工評分 **≥ 8/10 合格**，且無明顯 hallucination。

**前置：**
- 203 `OT_LLM_ENRICH=1`，`ollama pull gemma2:2b`
- Layer C E2E：`PYTHONPATH=. python3 scripts/e2e-ot-layerc-analyze.py --expect-llm`
- Portal 有 live 事件：`./scripts/verify-portal-layerc.sh --expect-llm`

---

## 1. 取得評分樣本

### 方式 A — 從 Portal 匯出（推薦）

```bash
export PORTAL_BEARER_TOKEN='...'   # 或 PORTAL_EMAIL + PORTAL_PASSWORD
export WORKSPACE_ID=6

./scripts/verify-portal-layerc.sh \
  --export-json docs/llm-eval-samples.jsonl \
  --expect-llm
```

`docs/llm-eval-samples.jsonl` 每行一筆事件，含 `episode_id`、`rule_id`、`layerc_summary`。

### 方式 B — Layer C dry-run 單筆

```bash
cd Aristaconnector-Control-Plane
PYTHONPATH=. python3 scripts/e2e-ot-layerc-analyze.py \
  --layerc-url http://192.168.1.203:8001 \
  --expect-llm
```

從輸出或 layerc-api log 擷取 `layerc_ttp_reasoning` JSON。

### 方式 C — 觸發 live episode

1. Pi 產生 OT 規則事件（如 Modbus write → OT-007）
2. 等待 layerc-bridge writeback → 108 ingest
3. Portal **工控安全防護 → 事件** 開啟詳情，複製 Layer C 摘要

---

## 2. 評分維度（每項 1–5 分）

| 維度 | 5 分 | 3 分 | 1 分 |
|------|------|------|------|
| **可讀性** | 繁中流暢、一讀即懂 | 可讀但冗長或術語過多 | 難懂、混雜英文或破碎句 |
| **Grounding** | 摘要與 rule_id / evidence 一致 | 大致相關，細節略缺 | 與事件無關或張冠李戴 |
| **Hallucination** | 無臆測 IP/設備/協定 | 輕微推測但可接受 | 捏造未出現的實體或攻擊步驟 |
| **建議動作** | 可執行、優先序合理 | 泛用建議、略空泛 | 危險或不可行建議 |
| **嚴重度理由** | 與 severity 一致、有依據 | 理由薄弱但方向對 | 與 severity 矛盾 |

**單筆合格：** 可讀性 ≥ 4 且 Hallucination ≥ 4（即無明顯幻覺）。

**批次合格：** 10 筆中 ≥ **8 筆**合格。

---

## 3. 評分表（複製填寫）

評分人：`____________`  
日期：`____________`  
Lab 環境：108 Portal / 203 Layer C / Pi edge  
模型：`gemma2:2b` · `OT_LLM_MAX_TOKENS=512`

| # | episode_id | rule_id | severity | summary_zh（前 40 字） | 可讀 | Ground | Hallu | 動作 | 理由 | 合格? | 備註 |
|---|------------|---------|----------|------------------------|------|--------|-------|------|------|-------|------|
| 1 | | | | | /5 | /5 | /5 | /5 | /5 | Y/N | |
| 2 | | | | | /5 | /5 | /5 | /5 | /5 | Y/N | |
| 3 | | | | | /5 | /5 | /5 | /5 | /5 | Y/N | |
| 4 | | | | | /5 | /5 | /5 | /5 | /5 | Y/N | |
| 5 | | | | | /5 | /5 | /5 | /5 | /5 | Y/N | |
| 6 | | | | | /5 | /5 | /5 | /5 | /5 | Y/N | |
| 7 | | | | | /5 | /5 | /5 | /5 | /5 | Y/N | |
| 8 | | | | | /5 | /5 | /5 | /5 | /5 | Y/N | |
| 9 | | | | | /5 | /5 | /5 | /5 | /5 | Y/N | |
| 10 | | | | | /5 | /5 | /5 | /5 | /5 | Y/N | |

**統計**

| 項目 | 值 |
|------|-----|
| 合格筆數 | ___ / 10 |
| 平均可讀性 | ___ |
| 平均 Hallucination | ___ |
| P95 LLM 延遲（203 log） | ___ s |
| 退出判定 | PASS / FAIL |

---

## 4. 常見問題對照

| 現象 | 可能原因 | 處置 |
|------|----------|------|
| `llm_enriched=false` | Ollama 未跑 / JSON 解析失敗 | `ollama list`；提高 `OT_LLM_MAX_TOKENS` |
| summary 過短 | token 截斷 | 確認 512；精簡 prompt |
| 捏造 IP | prompt grounding 不足 | 檢查 KB citation；降 temperature |
| Portal 無 Layer C | writeback 未達 108 | 查 layerc-bridge log；ingest secret |
| 只有規則路徑 | enrich 未開或 rate limit | `OT_LLM_ENRICH=1`；`OT_LLM_MAX_PER_SENSOR_HOUR` |

---

## 5. 退出簽核

- [ ] 10 episode 評分完成
- [ ] ≥ 8/10 合格
- [ ] `./scripts/verify-portal-layerc.sh --expect-llm` PASS
- [ ] 評分表存檔（本文件或 `docs/llm-eval-results-YYYY-MM-DD.md`）

**Reviewer：** _______________  
**Date：** _______________

---

## 相關文件

- [`sprint-4-ot-intelligence-ui.md`](sprint-4-ot-intelligence-ui.md) — Epic C 驗收
- [`sprint-5-productization.md`](sprint-5-productization.md) — S5-E1 / S5-E2
- [`runbook-ot-lab-deploy.md`](runbook-ot-lab-deploy.md) — lab 部署
