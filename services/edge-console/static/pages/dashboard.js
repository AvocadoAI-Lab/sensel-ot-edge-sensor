// 總覽 Dashboard — Edge Readiness, Telemetry Flow, Pipeline, Policy, Baseline, Latest events.
import { $, toast, escapeHtml } from "../core/dom.js";
import { api } from "../core/api.js";
import { fmtTime, relTime, formatRate } from "../core/format.js";
import { gauge, dot, badge, stateBlock, pipeline, copyField, STATE_LABEL, openDrawer } from "../ui/components.js";
import { getReadiness, getBaseline, getEvents } from "../core/dataSource.js";
import { setSensorMeta, updateShield, navigate } from "../core/shell.js";

export const meta = { title: "總覽 Dashboard", sub: "OT Edge Runtime + Security Validation" };

let timer = null;

const BASELINE_UI = {
  not_loaded: { state: "gray", label: "Not Loaded", cta: "建立 Baseline", desc: "尚未建立資產與通訊基線" },
  learning: { state: "blue", label: "Learning", cta: "檢視學習進度", desc: "學習視窗進行中" },
  active: { state: "green", label: "Active", cta: "檢視 Baseline", desc: "基線啟用並監控偏移" },
  drift: { state: "yellow", label: "Drift Detected", cta: "審核偏移", desc: "偵測到基線偏移，待審核" },
};

export function render(root) {
  root.innerHTML = `
    <section class="page">
      <div class="grid-dash-top">
        <div class="card-ot readiness-card" id="readinessCard">${stateBlock("loading")}</div>
        <div class="card-ot" id="policyCard">${stateBlock("loading")}</div>
      </div>

      <div class="card-ot" id="pipelineCard" style="margin-top:1rem">
        <div class="title">Telemetry Pipeline</div>
        <div id="pipelineBody">${stateBlock("loading")}</div>
      </div>

      <div class="title section-title" style="margin-top:1rem">Telemetry Flow</div>
      <div class="grid-5" id="telemetryCards">${stateBlock("loading")}</div>

      <div class="grid-dash-bottom" style="margin-top:1rem">
        <div class="card-ot" id="baselineCard">${stateBlock("loading")}</div>
        <div class="card-ot" id="eventsCard"><div class="title">Latest Security Events</div><div id="latestEvents">${stateBlock("loading")}</div></div>
      </div>

      <div class="actions" style="margin-top:1rem">
        <button type="button" class="btn btn-secondary" id="dashRefresh">重新整理</button>
        <button type="button" class="btn btn-ghost" id="dashRestartAgent">重啟 Edge Agent</button>
      </div>
    </section>`;

  $("#pipelineBody").addEventListener("click", (e) => {
    const btn = e.target.closest(".pipeline-alert");
    if (!btn) return;
    openDrawer(
      `${btn.dataset.pipelineTitle || "節點"} · 診斷`,
      `<p class="hint" style="white-space:pre-wrap">${escapeHtml(btn.dataset.pipelineHint || "無更多資訊")}</p>`,
    );
  });
  $("#dashRefresh").addEventListener("click", () => load().catch((e) => toast(e.message, false)));
  $("#dashRestartAgent").addEventListener("click", async () => {
    try { const r = await api("/api/agent/restart", { method: "POST" }); toast(r.message || "Agent 已重啟"); }
    catch (e) { toast(e.message, false); }
  });

  load().catch((e) => fail(e));
  timer = setInterval(() => { if (!document.hidden) load().catch(() => {}); }, 5000);
}

export function leave() { clearInterval(timer); timer = null; }
export function onVisible() { load().catch(() => {}); }

function fail(e) {
  const c = $("#readinessCard"); if (c) c.innerHTML = stateBlock("error", e.message);
}

async function load() {
  const [readiness, baseline, evts, traffic] = await Promise.all([
    getReadiness(),
    getBaseline(),
    getEvents(5).catch(() => []),
    api("/api/traffic/live").catch(() => ({ metrics: {} })),
  ]);
  const status = readiness.status || {};
  if (status.sensor_id) setSensorMeta(status.sensor_id, status.site_id);

  renderReadiness(readiness);
  renderPolicy(status.metrics?.policy_gauge || {});
  renderPipeline(readiness, status, traffic);
  renderTelemetry(status.metrics?.telemetry || {}, status.metrics || {}, traffic);
  renderBaseline(baseline);
  renderEvents(evts);
  updateShield(baseline.state === "active" ? "green" : baseline.state === "not_loaded" ? "red" : "yellow");
}

function renderReadiness(r) {
  const card = $("#readinessCard");
  if (!card) return;
  const gradeLabel = r.grade === "ready" ? "就緒" : r.grade === "partial" ? "部分就緒" : "需注意";
  const factors = r.factors.map((f) => `
    <div class="readiness-factor">
      <span class="rf-dot">${dot(f.state)}</span>
      <span class="rf-label">${escapeHtml(f.label)}</span>
      <span class="rf-weight mono">${f.weight}%</span>
      <span class="rf-value mono" title="${escapeHtml(f.value)}">${escapeHtml(f.value)}</span>
    </div>`).join("");
  card.innerHTML = `
    <div class="title">Edge Readiness Score</div>
    <div class="readiness-main">
      ${gauge(r.score, gradeLabel)}
      <details class="readiness-details" open>
        <summary>因子明細（${r.factors.filter((f) => f.state === "green").length}/${r.factors.length} 正常）</summary>
        <div class="readiness-factors">${factors}</div>
      </details>
    </div>`;
}

function renderPolicy(gaugeData) {
  const card = $("#policyCard");
  if (!card) return;
  const pct = Number(gaugeData.percent) || 0;
  const have = new Set(gaugeData.factors || []);
  const checklist = [
    { key: "baseline", label: "Baseline 已載入" },
    { key: "registered", label: "感測器已註冊", alt: "configured" },
    { key: "telemetry", label: "Telemetry 即時" },
    { key: "ioc", label: "IoC 指標就緒" },
    { key: "mqtt", label: "北向 MQTT 連線" },
  ];
  const items = checklist.map((c) => {
    const done = have.has(c.key) || (c.alt && have.has(c.alt));
    return `<div class="checklist-item ${done ? "done" : "todo"}"><span class="ck-mark">${done ? "✓" : "○"}</span>${escapeHtml(c.label)}</div>`;
  }).join("");
  card.innerHTML = `
    <div class="title">Policy Status</div>
    ${gauge(pct, gaugeData.label || "—")}
    <details class="policy-checklist">
      <summary>政策檢查清單</summary>
      <div class="checklist">${items}</div>
    </details>`;
}

function renderPipeline(readiness, status, traffic) {
  const fm = Object.fromEntries((readiness.factors || []).map((x) => [x.key, x]));
  const st = (k) => fm[k]?.state || "gray";
  const cards = status.cards || {};
  const nb = status.northbound || {};
  const tm = status.metrics?.telemetry || {};
  const liveState = tm.live ? "green" : "yellow";
  const captureIf = status.metrics?.capture_interface || "";
  const mqttHint = [cards.mqtt?.detail, nb.last_error ? `最後錯誤：${nb.last_error}` : ""].filter(Boolean).join(" · ");
  const nodes = [
    {
      label: "Packet Sensor", state: liveState,
      detail: `${formatRate(tm.instant_rate || traffic.metrics?.instant_rate)} pkt/s`,
      hint: liveState !== "green" ? `未偵測到即時封包${captureIf ? `（介面 ${captureIf}）` : ""}：請確認交換器 mirror/SPAN 與 CAPTURE_INTERFACE 設定。` : "",
    },
    { label: "EdgeX Device Service", state: st("edgex"), hint: fm.edgex?.value || "" },
    { label: "MQTT Bus", state: st("mqtt"), hint: mqttHint },
    { label: "SenseL Control Plane", state: st("registration"), hint: cards.registration?.detail || fm.registration?.value || "" },
    { label: "Security Analytics", state: (status.metrics?.events_24h || 0) > 0 ? "green" : "blue", detail: `${status.metrics?.events_24h || 0} evt/24h` },
  ];
  $("#pipelineBody").innerHTML = pipeline(nodes);
}

function renderTelemetry(t, metrics, traffic) {
  const box = $("#telemetryCards");
  if (!box) return;
  const age = traffic.age_sec;
  const lastRecv = (t.live && typeof age === "number") ? `${age}s 前` : (metrics.last_register_at ? relTime(metrics.last_register_at) : "—");
  const cards = [
    { title: "Realtime Packet Rate", value: `${formatRate(t.instant_rate)}`, sub: "pkt/s", state: t.live ? "green" : "yellow" },
    { title: "24h Event Count", value: `${metrics.events_24h ?? 0}`, sub: "events", state: "green" },
    { title: "Cumulative GOOSE", value: `${t.goose_messages ?? 0}`, sub: "messages", state: (t.goose_messages || 0) > 0 ? "green" : "gray" },
    { title: "IoC Count", value: `${t.ioc_entries ?? 0}`, sub: "indicators", state: (t.ioc_entries || 0) > 0 ? "green" : "gray" },
    { title: "Last Received", value: lastRecv, sub: t.live ? "live" : "stale", state: t.live ? "green" : "red" },
  ];
  box.innerHTML = cards.map((c) => `
    <div class="card-ot metric-card">
      <div class="title">${dot(c.state)}${c.title}</div>
      <div class="value metric-value">${escapeHtml(String(c.value))}</div>
      <div class="sub">${escapeHtml(c.sub)}</div>
    </div>`).join("");
}

function renderBaseline(b) {
  const card = $("#baselineCard");
  if (!card) return;
  const ui = BASELINE_UI[b.state] || BASELINE_UI.not_loaded;
  const progress = b.state === "learning" ? `<div class="baseline-progress"><div class="bar" style="width:${b.learning?.progress_pct || 0}%"></div></div><div class="sub">學習進度 ${b.learning?.progress_pct || 0}%（${b.learning?.window}）</div>` : "";
  const detail = b.state === "drift"
    ? `<div class="sub">${b.drift?.changes || 0} 項變更待審核</div>`
    : `<div class="sub">${b.assets} 資產 · ${b.comm_pairs} comm pairs</div>`;
  card.innerHTML = `
    <div class="title">Baseline</div>
    <div class="baseline-state">${badge(ui.label, ui.state)}</div>
    <div class="sub baseline-desc">${ui.desc}</div>
    ${progress || detail}
    <div class="actions"><button type="button" class="btn btn-sm btn-primary" id="baselineCta">${ui.cta}</button></div>`;
  $("#baselineCta")?.addEventListener("click", () => navigate("policy"));
}

const SEV_STATE = { critical: "red", high: "red", medium: "yellow", low: "blue" };

function renderEvents(events) {
  const box = $("#latestEvents");
  if (!box) return;
  if (!events.length) { box.innerHTML = stateBlock("empty", "近期無安全事件"); return; }
  box.innerHTML = events.slice(0, 5).map((e) => {
    const sev = String(e.severity || "medium").toLowerCase();
    const asset = e.matched_device || e.src_ip || "—";
    return `
      <button type="button" class="latest-event" data-evt>
        <span class="le-sev">${badge(sev, SEV_STATE[sev] || "yellow")}</span>
        <span class="le-rule mono">${escapeHtml(e.rule_id || "")}</span>
        <span class="le-desc">${escapeHtml(e.description || e.event_type || "")}</span>
        <span class="le-asset mono">${escapeHtml(asset)}</span>
        <span class="le-time mono">${fmtTime(e.timestamp)}</span>
      </button>`;
  }).join("");
  box.querySelectorAll("[data-evt]").forEach((el) => el.addEventListener("click", () => navigate("events")));
}
