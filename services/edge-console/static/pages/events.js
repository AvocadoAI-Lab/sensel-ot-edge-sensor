// 安全事件 — enriched table + Evidence Chain timeline + MITRE ATT&CK for ICS.
import { $, toast, escapeHtml } from "../core/dom.js";
import { fmtTime } from "../core/format.js";
import { dot, badge, stateBlock, copyField, openDrawer } from "../ui/components.js";
import { getEvents, getEventEvidence, getEventsContext } from "../core/dataSource.js";
import { isItMode, setHeader } from "../core/shell.js";

export const meta = { title: "安全事件", sub: "Packet Sensor 偵測 · Evidence Chain · MITRE ICS" };

let cache = [];
let evCtx = {};
let pageIt = false;

const SEV_STATE = { critical: "red", high: "red", medium: "yellow", low: "blue" };

export function render(root) {
  pageIt = isItMode();
  if (pageIt) setHeader("安全事件", "Suricata / Snort IDS · Evidence Chain");
  const it = pageIt;
  const cols = it
    ? `<th>時間</th><th>嚴重度</th><th>來源</th><th>協定</th>
       <th>IDS 規則</th><th>建議動作</th><th>Evidence</th>`
    : `<th>時間</th><th>嚴重度</th><th>資產</th><th>協定</th><th>Baseline 偏移</th>
       <th>Policy</th><th>建議動作</th><th>MITRE ICS</th><th>Evidence</th>`;
  const colSpan = it ? 7 : 9;

  root.innerHTML = `
    <section class="page panel">
      <p class="hint">${it
    ? "來自 Suricata / Snort IDS 與 IoC 比對事件。點列開啟 Evidence Chain。"
    : "來自 packet-sensor 偵測與 Suricata/Snort IDS（security / suricata / snort events）。點列開啟 Evidence Chain。"}</p>
      <div class="event-filters">
        <label>嚴重度
          <select id="eventFilterSeverity">
            <option value="">全部</option><option value="critical">critical</option>
            <option value="high">high</option><option value="medium">medium</option><option value="low">low</option>
          </select>
        </label>
        <label>Rule 前綴<input id="eventFilterRule" placeholder="${it ? "IT-NDR" : "OT-01"}" class="mono" /></label>
        <button type="button" class="btn btn-ghost btn-sm" id="eventFilterClear">清除篩選</button>
        <button type="button" class="btn btn-ghost btn-sm" id="eventsRefresh">重新整理</button>
      </div>
      <div class="table-wrap">
        <table class="events-table">
          <thead><tr>${cols}</tr></thead>
          <tbody id="eventsRows"><tr><td colspan="${colSpan}">${stateBlock("loading")}</td></tr></tbody>
        </table>
      </div>
    </section>`;

  root.dataset.itMode = it ? "1" : "0";
  $("#eventFilterSeverity").addEventListener("change", apply);
  $("#eventFilterRule").addEventListener("input", apply);
  $("#eventFilterClear").addEventListener("click", () => {
    $("#eventFilterSeverity").value = ""; $("#eventFilterRule").value = ""; apply();
  });
  $("#eventsRefresh").addEventListener("click", () => load().catch((e) => toast(e.message, false)));
  load().catch((e) => {
    $("#eventsRows").innerHTML = `<tr><td colspan="${colSpan}">${stateBlock("error", e.message)}</td></tr>`;
  });
}

export function leave() {}

async function load() {
  const [events, ctx] = await Promise.all([getEvents(50), getEventsContext()]);
  cache = events;
  evCtx = ctx;
  apply();
}

function filtered() {
  const sev = ($("#eventFilterSeverity")?.value || "").toLowerCase();
  const rule = ($("#eventFilterRule")?.value || "").toUpperCase();
  return cache.filter((e) => {
    if (sev && String(e.severity || "").toLowerCase() !== sev) return false;
    if (rule && !String(e.rule_id || "").toUpperCase().startsWith(rule)) return false;
    return true;
  });
}

function protoOf(e) {
  const blob = `${e.protocol || ""} ${e.proto || ""} ${e.event_type || ""} ${e.rule_id || ""}`.toUpperCase();
  if (blob.includes("GOOSE")) return "GOOSE";
  if (blob.includes("MMS")) return "MMS";
  if (blob.includes("MODBUS")) return "Modbus";
  if (blob.includes("OPC")) return "OPC UA";
  if (blob.includes("S7")) return "S7";
  if (blob.includes("IOC")) return "IoC";
  if (blob.includes("SURICATA") || blob.includes("ET ")) return "Suricata";
  if (blob.includes("SNORT")) return "Snort";
  return e.protocol || e.proto || "—";
}

function apply() {
  const rows = $("#eventsRows");
  const it = pageIt;
  const colSpan = it ? 7 : 9;
  const list = filtered();
  if (!list.length) {
    rows.innerHTML = `<tr><td colspan="${colSpan}">${stateBlock("empty", "無符合條件的事件")}</td></tr>`;
    return;
  }

  if (it) {
    rows.innerHTML = list.map((e, i) => {
      const sev = String(e.severity || "medium").toLowerCase();
      const ev = getEventEvidence(e, evCtx);
      const asset = e.src_ip || e.matched_device || "—";
      const ruleMatch = ev.matched ? badge("已套用", "green") : `<span class="muted">—</span>`;
      return `<tr class="sev-${sev}" data-idx="${i}">
        <td class="mono">${fmtTime(e.timestamp)}</td>
        <td>${badge(sev, SEV_STATE[sev] || "yellow")}</td>
        <td>${escapeHtml(asset)}<div class="sub mono">${escapeHtml(e.rule_id || "")}</div></td>
        <td><span class="rule-chip">${escapeHtml(protoOf(e))}</span></td>
        <td>${ruleMatch}</td>
        <td><span class="action-pill action-${ev.recommended_action.toLowerCase().replace(/\s+/g, "-")}">${escapeHtml(ev.recommended_action)}</span></td>
        <td><button type="button" class="btn btn-ghost btn-xs" data-evidence="${i}">查看</button></td>
      </tr>`;
    }).join("");
  } else {
    rows.innerHTML = list.map((e, i) => {
      const sev = String(e.severity || "medium").toLowerCase();
      const ev = getEventEvidence(e, evCtx);
      const asset = e.matched_device || e.src_ip || "—";
      const mitre = ev.mitre[0];
      const deviation = sev === "critical" || sev === "high" ? "高偏移" : sev === "medium" ? "中偏移" : "低/無";
      const devState = sev === "critical" || sev === "high" ? "red" : sev === "medium" ? "yellow" : "blue";
      const policyCell = ev.matched ? badge("已套用", "yellow") : `<span class="muted">未套用</span>`;
      return `<tr class="sev-${sev}" data-idx="${i}">
        <td class="mono">${fmtTime(e.timestamp)}</td>
        <td>${badge(sev, SEV_STATE[sev] || "yellow")}</td>
        <td>${escapeHtml(asset)}<div class="sub mono">${escapeHtml(e.rule_id || "")}</div></td>
        <td><span class="rule-chip">${escapeHtml(protoOf(e))}</span></td>
        <td>${badge(deviation, devState)}</td>
        <td>${policyCell}</td>
        <td><span class="action-pill action-${ev.recommended_action.toLowerCase().replace(/\s+/g, "-")}">${escapeHtml(ev.recommended_action)}</span></td>
        <td class="mono mitre-cell" title="${escapeHtml(mitre.tactic)}">${escapeHtml(mitre.id)}</td>
        <td><button type="button" class="btn btn-ghost btn-xs" data-evidence="${i}">查看</button></td>
      </tr>`;
    }).join("");
  }

  rows.querySelectorAll("[data-evidence]").forEach((btn) =>
    btn.addEventListener("click", (e) => { e.stopPropagation(); openEvidence(list[+btn.dataset.evidence], it); }));
  rows.querySelectorAll("tr[data-idx]").forEach((tr) =>
    tr.addEventListener("click", () => openEvidence(list[+tr.dataset.idx], it)));
}

function openEvidence(event, it) {
  if (!event) return;
  const ev = getEventEvidence(event, evCtx);
  const timeline = ev.chain.map((c, i) => `
    <div class="evidence-step">
      <div class="es-marker">${dot(c.state)}${i < ev.chain.length - 1 ? '<span class="es-line"></span>' : ""}</div>
      <div class="es-body"><div class="es-step">${escapeHtml(c.step)}</div><div class="es-detail mono">${escapeHtml(c.detail)}</div></div>
    </div>`).join("");
  const mitre = ev.mitre.map((m) => `
    <div class="mitre-row"><span class="mitre-id">${escapeHtml(m.id)}</span>
      <span class="mitre-tech">${escapeHtml(m.technique)}</span>
      <span class="mitre-tactic mono">${escapeHtml(m.tactic)}</span></div>`).join("");
  const mitreSection = it ? "" : `
    <h4 class="evidence-section">MITRE ATT&CK for ICS <span class="mock-tag">mock</span></h4>
    <div class="mitre-list">${mitre}</div>`;
  const html = `
    <div class="evidence-head">
      <div>${badge(String(event.severity || "medium"), SEV_STATE[String(event.severity || "medium").toLowerCase()] || "yellow")}</div>
      <div class="evidence-rule mono">${escapeHtml(event.rule_id || "")}</div>
    </div>
    <p class="evidence-desc">${escapeHtml(event.description || event.event_type || "")}</p>
    <div class="evidence-kv">
      <div><span class="ek">${it ? "來源" : "資產"}</span>${copyField(event.matched_device || event.src_ip || "—")}</div>
      <div><span class="ek">來源 IP</span>${copyField(event.src_ip || "—")}</div>
      <div><span class="ek">時間</span><span class="mono">${fmtTime(event.timestamp)}</span></div>
      <div><span class="ek">Risk</span><span class="mono">${ev.risk}/100</span></div>
      <div><span class="ek">建議動作</span><span class="action-pill">${escapeHtml(ev.recommended_action)}</span></div>
    </div>
    <h4 class="evidence-section">Evidence Chain</h4>
    <div class="evidence-timeline">${timeline}</div>
    ${mitreSection}`;
  openDrawer("Evidence Chain", html);
}
