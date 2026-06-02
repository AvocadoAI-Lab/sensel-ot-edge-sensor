# Sprint 5 — 產品化硬化（Lab → Demo Ready）

**前置：** Sprint 4 退出條件基本完成（LLM enrich E2E、AE artifact、Portal 卡片、Edge 篩選）。  
**週期建議：** 2 週。

## 北極星

分析師在 **108 Portal** 開啟 live OT episode，可看到 **Layer C 中文摘要 + 行為分數 + 建議動作**；Edge Console 可作為現場 demo；203 堆疊可 **72h soak** 不重啟。

## Epic E — E2E 與 Demo 路徑

| ID | Story | 產出 | 優先 |
|----|-------|------|------|
| S5-E1 | Live episode Portal 驗收腳本 | `scripts/verify-portal-layerc.sh` | P0 | ✅ |
| S5-E2 | 10 episode LLM 人工評分表 | `docs/sprint-4-llm-eval.md` | P0 | ✅ |
| S5-E3 | F2 告警 email 含 Layer C 摘要 E2E | alert_dispatcher 整合測試 | P1 |

## Epic F — 可靠性

| ID | Story | 產出 | 優先 |
|----|-------|------|------|
| S5-F1 | 203 compose healthcheck + restart policy | layerc-api / layerb-worker | P0 | ✅ |
| S5-F2 | Ollama 存活探測 + enrich fail-closed 指標 | layerc-api `/health` 擴充 | P1 |
| S5-F3 | AE warm-up 完成後 behavior_score 上 Portal | live ingest 驗證 | P1 |

## Epic G — 部署與文件

| ID | Story | 產出 | 優先 |
|----|-------|------|------|
| S5-G1 | `./deploy-ot-lab.sh --sprint4` 納入 108 Portal rebuild | 一鍵三節點 | P0 | ✅ |
| S5-G2 | Sprint 4 env 寫入 `.env.layerc.example` | CP repo | P1 |
| S5-G3 | 72h soak 報告模板更新（含 LLM/AE 指標） | `docs/soak-report-template.md` | P2 |

## Epic H — Sprint 5 預留（選做）

- LSTM / 序列異常（Sprint 4 已預留）
- PCAP 統計 multimodal tool
- Remote GPU Ollama tunnel（escalation 9B）
- Edge Console React rewrite

## 建議時程

| 天 | 工作 |
|----|------|
| D1–2 | S5-E1 live Portal 驗收 + S5-G1 deploy 整合 |
| D3–4 | S5-E2 LLM 人工評分 + S5-F1 healthcheck |
| D5–7 | S5-F3 behavior 端到端 + 72h soak 啟動 |
| D8–10 | 文件、demo script、Sprint 5 退出 review |

## 退出條件

- [ ] `./scripts/deploy-ot-lab.sh --sprint4` 三節點全綠（含 `--expect-llm`）— 腳本就緒；需 `.env.lab` Portal 帳密 + lab 節點在線
- [ ] 108 Portal live OT 事件可見 Layer C 卡片（非 JSON）
- [ ] 10 episode LLM 評分 ≥8/10 可讀、無明顯 hallucination
- [ ] 72h lab soak 無 critical crash（參考 Sprint 3 模板）

## 相關文件

- [`sprint-4-ot-intelligence-ui.md`](sprint-4-ot-intelligence-ui.md)
- [`runbook-ot-lab-deploy.md`](runbook-ot-lab-deploy.md)
- [`sprint-plan.md`](sprint-plan.md)
