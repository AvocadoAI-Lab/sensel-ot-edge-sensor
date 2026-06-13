// 系統維運 — Advanced Operations Center.
//
// Orchestrator: page header, tab navigation, shared dirty/draft state, sticky
// action bar, risk-confirmation modal and the 60s rollback flow. Each tab is a
// focused module under ./ops/ that receives the shared `ctx`.

import { $, toast, escapeHtml } from "../core/dom.js";
import { fmtTime } from "../core/format.js";
import { getSystemStatus, updateMqttSettings, updatePacketSensorSettings,
  updateAutoReconnectPolicy, restartAffectedServices, RISK, highestRisk } from "../core/opsApi.js";

import * as overview from "./ops/overview.js";
import * as northbound from "./ops/northbound.js";
import * as packetSensor from "./ops/packetSensor.js";
import * as network from "./ops/network.js";
import * as wifi from "./ops/wifi.js";
import * as security from "./ops/security.js";
import * as diagnostics from "./ops/diagnostics.js";

export const meta = { title: "系統維運", sub: "Advanced Operations Center" };

const TABS = [
  { id: "overview", label: "總覽", mod: overview },
  { id: "northbound", label: "北向連線", mod: northbound },
  { id: "packet", label: "Packet Sensor", mod: packetSensor },
  { id: "network", label: "網路介面", mod: network },
  { id: "wifi", label: "Wi-Fi / 離線重連", mod: wifi },
  { id: "security", label: "安全與稽核", mod: security },
  { id: "diagnostics", label: "診斷工具", mod: diagnostics },
];

const DRAFT_KEY = "sensel.ops.draft";

let activeTab = "overview";
let headerTimer = null;
let ctx = null;

// ---------------------------------------------------------------------------
// Shared context.
// ---------------------------------------------------------------------------
function makeCtx() {
  const changes = new Map(); // key -> { value, label, tab, risk, services, field, apply }
  const subscribers = new Set();

  const notify = () => { subscribers.forEach((fn) => { try { fn(); } catch {} }); renderActionBar(); renderTabBadges(); };

  return {
    system: null,
    changes,
    onChange(fn) { subscribers.add(fn); return () => subscribers.delete(fn); },

    stage(key, meta) {
      changes.set(key, { risk: "low", services: [], ...meta });
      notify();
    },
    unstage(key) { if (changes.delete(key)) notify(); },
    isStaged(key) { return changes.has(key); },
    value(key, fallback) { return changes.has(key) ? changes.get(key).value : fallback; },
    changesForTab(tab) { return [...changes.values()].filter((c) => c.tab === tab); },

    async refreshSystem() {
      try { ctx.system = await getSystemStatus(); } catch { ctx.system = null; }
      renderPageHeader();
      return ctx.system;
    },

    confirm: openRiskModal,
    rollback: runRollback,
    toast,
    switchTab: (id) => setTab(id),
    reloadTab: () => renderTab(activeTab),
  };
}

// ---------------------------------------------------------------------------
// Render entry.
// ---------------------------------------------------------------------------
export function render(root) {
  ctx = makeCtx();
  restoreDraft();
  root.innerHTML = `
    <section class="page ops-center">
      <div class="ops-header" id="opsHeader"></div>
      <div class="ops-tabs" role="tablist" id="opsTabs"></div>
      <div class="ops-tab-body" id="opsTabBody"></div>
      <div class="ops-actionbar hidden" id="opsActionBar"></div>
    </section>`;

  renderPageHeader();
  renderTabNav();
  setTab(activeTab);
  renderActionBar();

  ctx.refreshSystem();
  headerTimer = setInterval(() => ctx.refreshSystem(), 15000);
  window.addEventListener("beforeunload", beforeUnload);
}

export function leave() {
  clearInterval(headerTimer);
  window.removeEventListener("beforeunload", beforeUnload);
}

export function onVisible() { ctx?.refreshSystem(); }

function beforeUnload(e) {
  if (ctx && ctx.changes.size) { e.preventDefault(); e.returnValue = ""; }
}

// ---------------------------------------------------------------------------
// Page header (sensor meta + live status pills).
// ---------------------------------------------------------------------------
function pill(label, state, value) {
  return `<div class="ops-pill ${state}"><span class="status-dot ${state}"></span>
    <span class="ops-pill-label">${escapeHtml(label)}</span>
    <span class="ops-pill-value mono">${escapeHtml(value)}</span></div>`;
}

function renderPageHeader() {
  const host = $("#opsHeader");
  if (!host) return;
  const s = ctx.system;
  const sensor = s?.sensor_id || "ot-edge-001";
  const site = s?.site_id || "factory-lab-001";
  const online = s ? "green" : "gray";
  const agent = !s ? "gray" : s.agent.last_error ? "yellow" : s.agent.registered ? "green" : "yellow";
  const sensor_state = !s ? "gray" : s.capture.ok ? "green" : "yellow";
  const mqtt = !s ? "gray" : s.mqtt.connected ? "green" : "red";
  host.innerHTML = `
    <div class="ops-head-main">
      <div>
        <h2 class="ops-title">系統維運</h2>
        <p class="ops-sub mono">${escapeHtml(sensor)} @ ${escapeHtml(site)}</p>
      </div>
      <div class="ops-head-time mono" id="opsHeadTime">${fmtTime(Date.now())}</div>
    </div>
    <div class="ops-pills">
      ${pill("Edge", online, online === "green" ? "online" : "—")}
      ${pill("Agent", agent, !s ? "—" : s.agent.registered ? "running" : "degraded")}
      ${pill("Packet Sensor", sensor_state, !s ? "—" : s.capture.ok ? "running" : "idle")}
      ${pill("SenseL MQTT", mqtt, !s ? "—" : s.mqtt.connected ? "connected" : "down")}
    </div>`;
}

// ---------------------------------------------------------------------------
// Tabs.
// ---------------------------------------------------------------------------
function renderTabNav() {
  const nav = $("#opsTabs");
  if (!nav) return;
  nav.innerHTML = TABS.map((t) => `
    <button type="button" class="ops-tab" role="tab" data-ops-tab="${t.id}">
      <span class="ops-tab-label">${escapeHtml(t.label)}</span>
      <span class="ops-tab-badge hidden" data-badge="${t.id}">未儲存</span>
    </button>`).join("");
  nav.querySelectorAll("[data-ops-tab]").forEach((b) =>
    b.addEventListener("click", () => setTab(b.dataset.opsTab)));
}

function setTab(id) {
  if (!TABS.some((t) => t.id === id)) id = "overview";
  activeTab = id;
  $("#opsTabs")?.querySelectorAll(".ops-tab").forEach((b) =>
    b.classList.toggle("active", b.dataset.opsTab === id));
  renderTab(id);
}

function renderTab(id) {
  const body = $("#opsTabBody");
  if (!body) return;
  const tab = TABS.find((t) => t.id === id);
  body.innerHTML = "";
  try {
    tab.mod.render(body, ctx);
  } catch (e) {
    body.innerHTML = `<div class="card-state is-error">分頁載入失敗：${escapeHtml(e.message)}</div>`;
  }
  renderTabBadges();
}

function renderTabBadges() {
  TABS.forEach((t) => {
    const badge = document.querySelector(`[data-badge="${t.id}"]`);
    if (!badge) return;
    const n = ctx.changesForTab(t.id).length;
    badge.textContent = n ? `未儲存 ${n}` : "未儲存";
    badge.classList.toggle("hidden", n === 0);
  });
}

// ---------------------------------------------------------------------------
// Sticky action bar.
// ---------------------------------------------------------------------------
function renderActionBar() {
  const bar = $("#opsActionBar");
  if (!bar) return;
  const list = [...ctx.changes.values()];
  if (!list.length) { bar.classList.add("hidden"); bar.innerHTML = ""; return; }
  bar.classList.remove("hidden");
  const risk = highestRisk(list.map((c) => c.risk));
  const r = RISK[risk];
  const services = [...new Set(list.flatMap((c) => c.services))];
  bar.innerHTML = `
    <div class="ops-ab-info">
      <span class="ops-ab-count">${list.length} 項未套用變更</span>
      <span class="risk-chip ${r.cls}">${r.label}</span>
      ${services.length ? `<span class="ops-ab-svc mono">影響：${escapeHtml(services.join(", "))}</span>` : ""}
    </div>
    <div class="ops-ab-actions">
      <button type="button" class="btn btn-ghost btn-sm" id="abReset">捨棄變更</button>
      <button type="button" class="btn btn-ghost btn-sm" id="abDraft">儲存草稿</button>
      <button type="button" class="btn btn-primary btn-sm" id="abApply">套用設定</button>
      ${services.length ? `<button type="button" class="btn btn-secondary btn-sm" id="abApplyRestart">套用並重啟服務</button>` : ""}
    </div>`;
  $("#abReset").onclick = resetChanges;
  $("#abDraft").onclick = saveDraft;
  $("#abApply").onclick = () => applyChanges(false);
  $("#abApplyRestart") && ($("#abApplyRestart").onclick = () => applyChanges(true));
}

function resetChanges() {
  ctx.changes.clear();
  clearDraft();
  renderActionBar(); renderTabBadges();
  renderTab(activeTab);
  toast("已捨棄未套用變更");
}

async function applyChanges(restart) {
  const list = [...ctx.changes.entries()];
  if (!list.length) return;
  const risk = highestRisk(list.map(([, c]) => c.risk));
  const services = [...new Set(list.flatMap(([, c]) => c.services))];
  const diff = list.map(([, c]) => `<li><span class="diff-k">${escapeHtml(c.label)}</span><span class="diff-v mono">${escapeHtml(String(c.value))}</span></li>`).join("");
  const ok = await openRiskModal({
    title: restart ? "套用設定並重啟服務" : "套用設定",
    risk,
    services,
    bodyHtml: `<p class="hint">即將寫入以下變更：</p><ul class="diff-list">${diff}</ul>`,
    confirmLabel: restart ? "套用並重啟" : "確認套用",
  });
  if (!ok) return;

  try {
    // Group config-field changes into a single PUT /api/config.
    const mqttPatch = {}, capturePatch = {};
    let policyPatch = null;
    for (const [, c] of list) {
      if (c.apply === "mqtt") Object.assign(mqttPatch, c.patch || {});
      else if (c.apply === "capture") Object.assign(capturePatch, c.patch || {});
      else if (c.apply === "autoreconnect") policyPatch = { ...(policyPatch || {}), ...(c.patch || {}) };
    }
    if (Object.keys(mqttPatch).length) await updateMqttSettings(mqttPatch);
    if (Object.keys(capturePatch).length) await updatePacketSensorSettings(capturePatch);
    if (policyPatch) updateAutoReconnectPolicy(policyPatch);

    ctx.changes.clear();
    clearDraft();
    renderActionBar(); renderTabBadges();

    if (restart && services.length) {
      toast("設定已套用，重啟服務中…");
      const results = await restartAffectedServices(services);
      const failed = results.filter((r) => !r.ok);
      toast(failed.length ? `部分服務未重啟：${failed.map((f) => f.id).join(", ")}` : "設定已套用，服務已重啟", failed.length === 0);
    } else {
      toast(services.length ? "設定已套用（需重啟相關服務才會生效）" : "設定已套用");
    }
    await ctx.refreshSystem();
    renderTab(activeTab);
  } catch (e) {
    toast(e.message, false);
  }
}

// ---------------------------------------------------------------------------
// Draft persistence.
// ---------------------------------------------------------------------------
function saveDraft() {
  try {
    const obj = {};
    for (const [k, v] of ctx.changes) obj[k] = v;
    localStorage.setItem(DRAFT_KEY, JSON.stringify(obj));
    toast("草稿已儲存");
  } catch { toast("草稿儲存失敗", false); }
}
function restoreDraft() {
  try {
    const raw = localStorage.getItem(DRAFT_KEY);
    if (!raw) return;
    const obj = JSON.parse(raw);
    for (const [k, v] of Object.entries(obj)) ctx.changes.set(k, v);
  } catch { /* ignore */ }
}
function clearDraft() { try { localStorage.removeItem(DRAFT_KEY); } catch {} }

// ---------------------------------------------------------------------------
// Risk confirmation modal (Promise<boolean>).
// ---------------------------------------------------------------------------
function openRiskModal({ title, risk = "low", services = [], bodyHtml = "", confirmLabel = "確認", danger = false }) {
  return new Promise((resolve) => {
    const r = RISK[risk] || RISK.low;
    const overlay = document.createElement("div");
    overlay.className = "ops-modal-overlay";
    overlay.innerHTML = `
      <div class="ops-modal" role="dialog" aria-modal="true">
        <div class="ops-modal-head">
          <h3>${escapeHtml(title)}</h3>
          <span class="risk-chip ${r.cls}">${r.label} · ${escapeHtml(r.note)}</span>
        </div>
        <div class="ops-modal-body">
          ${bodyHtml}
          ${services.length ? `<p class="hint">受影響服務：<span class="mono">${escapeHtml(services.join(", "))}</span></p>` : ""}
        </div>
        <div class="ops-modal-foot">
          <button type="button" class="btn btn-ghost btn-sm" data-act="cancel">取消</button>
          <button type="button" class="btn ${danger || risk === "high" ? "btn-danger" : "btn-primary"} btn-sm" data-act="ok">${escapeHtml(confirmLabel)}</button>
        </div>
      </div>`;
    document.body.appendChild(overlay);
    requestAnimationFrame(() => overlay.classList.add("open"));
    const close = (val) => { overlay.classList.remove("open"); setTimeout(() => overlay.remove(), 180); resolve(val); };
    overlay.addEventListener("click", (e) => {
      if (e.target === overlay || e.target.closest('[data-act="cancel"]')) close(false);
      else if (e.target.closest('[data-act="ok"]')) close(true);
    });
  });
}

// ---------------------------------------------------------------------------
// 60-second rollback flow for high-risk network operations.
//   opts: { title, risk, apply: async fn, verify: async fn -> bool, revert: async fn, seconds }
// ---------------------------------------------------------------------------
async function runRollback({ title, risk = "high", applyFn, revertFn, seconds = 60, detailHtml = "" }) {
  const proceed = await openRiskModal({
    title, risk,
    bodyHtml: `${detailHtml}<p class="hint">套用後將開始 ${seconds} 秒倒數。若你在倒數結束前未確認連線正常，系統會自動還原此變更。</p>`,
    confirmLabel: "套用並開始倒數",
    danger: true,
  });
  if (!proceed) return { applied: false };

  try { await applyFn(); }
  catch (e) { toast(e.message, false); return { applied: false, error: e.message }; }

  return new Promise((resolve) => {
    const overlay = document.createElement("div");
    overlay.className = "ops-modal-overlay open";
    let left = seconds;
    const render = () => {
      overlay.innerHTML = `
        <div class="ops-modal" role="dialog" aria-modal="true">
          <div class="ops-modal-head"><h3>確認連線正常</h3><span class="risk-chip danger">${left}s 後自動還原</span></div>
          <div class="ops-modal-body">
            <p>變更已套用。請確認你仍可正常存取此 Console。</p>
            <p class="hint">若連線中斷，請等待自動還原；恢復後重新整理頁面。</p>
          </div>
          <div class="ops-modal-foot">
            <button type="button" class="btn btn-secondary btn-sm" data-act="revert">立即還原</button>
            <button type="button" class="btn btn-primary btn-sm" data-act="keep">連線正常，保留變更</button>
          </div>
        </div>`;
      overlay.querySelector('[data-act="keep"]').onclick = () => finish(true);
      overlay.querySelector('[data-act="revert"]').onclick = () => finish(false);
    };
    const timer = setInterval(() => { left -= 1; if (left <= 0) finish(false); else render(); }, 1000);
    const finish = async (keep) => {
      clearInterval(timer);
      overlay.remove();
      if (keep) { toast("變更已保留"); resolve({ applied: true, kept: true }); }
      else {
        try { await revertFn(); toast("已自動還原變更"); } catch (e) { toast(`還原失敗：${e.message}`, false); }
        resolve({ applied: true, kept: false });
      }
    };
    document.body.appendChild(overlay);
    render();
  });
}
