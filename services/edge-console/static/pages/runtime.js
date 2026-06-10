// Edge Runtime — EdgeX service health, versions, deps, dependency graph, latency.
import { $, $$, toast, escapeHtml } from "../core/dom.js";
import { api } from "../core/api.js";
import { dot, badge, stateBlock, depGraph, copyField, openDrawer, STATE_LABEL } from "../ui/components.js";
import { getRuntime } from "../core/dataSource.js";
import { navigate } from "../core/shell.js";

const PHASE2_CONTAINERS = ["edgex-device-opc-ua", "edgex-device-s7"];

// Connected services first; offline/missing sink to the bottom.
const STATE_RANK = { green: 0, yellow: 1, blue: 2, red: 3, gray: 4 };
function stateRank(state) { return STATE_RANK[state] ?? 5; }

export const meta = { title: "Edge Runtime", sub: "EdgeX Foundry 4.0 · 服務健康 · 依賴拓撲" };

let timer = null;

export function render(root) {
  root.innerHTML = `
    <section class="page">
      <div class="grid-2">
        <div class="card-ot" id="reachCard">${stateBlock("loading")}</div>
        <div class="card-ot" id="latencyCard">${stateBlock("loading")}</div>
      </div>

      <div class="card-ot" id="runtimeTableCard" style="margin-top:1rem">
        <div class="title">Services</div>
        <div class="table-wrap">
          <table class="runtime-table">
            <thead><tr>
              <th>服務</th><th>Version</th><th>Last Heartbeat</th><th>CPU</th><th>Mem</th>
              <th>Dependency</th><th>Diagnosis</th><th>狀態</th><th>操作</th>
            </tr></thead>
            <tbody id="runtimeRows"><tr><td colspan="9">${stateBlock("loading")}</td></tr></tbody>
          </table>
        </div>
      </div>

      <div class="card-ot" id="graphCard" style="margin-top:1rem">
        <div class="title">Service Dependency Graph</div>
        <div id="graphBody">${stateBlock("loading")}</div>
      </div>

      <div class="actions" style="margin-top:1rem">
        <button type="button" class="btn btn-secondary" id="runtimeRefresh">重新整理</button>
        <a class="btn btn-ghost" id="edgexUiLink" href="#" target="_blank" rel="noopener">開啟 EdgeX UI ↗</a>
      </div>
    </section>`;

  $("#runtimeRefresh").addEventListener("click", () => load().catch((e) => toast(e.message, false)));
  $("#runtimeRows").addEventListener("click", onRowAction);
  load().catch((e) => { $("#reachCard").innerHTML = stateBlock("error", e.message); });
  timer = setInterval(() => { if (!document.hidden) load().catch(() => {}); }, 8000);
}

export function leave() { clearInterval(timer); timer = null; }
export function onVisible() { load().catch(() => {}); }

async function load() {
  const rt = await getRuntime();
  if (!rt.ok) {
    $("#reachCard").innerHTML = `<div class="title">Reachability</div>${stateBlock("error", rt.error || "EdgeX 無法連線")}`;
    $("#runtimeRows").innerHTML = `<tr><td colspan="9">${stateBlock("error", "無法取得服務")}</td></tr>`;
    $("#graphBody").innerHTML = stateBlock("error", "無依賴資料");
    return;
  }
  const bus = rt.message_bus || {};
  const internal = bus.edgex_internal || {};
  $("#reachCard").innerHTML = `
    <div class="title">Reachability</div>
    <div class="value">${dot(rt.reachable ? "green" : "red")}<span>${rt.reachable ? "Core 連線正常" : "Core 無法連線"}</span></div>
    <div class="sub">Message Bus ${copyField(`${internal.host || "—"}:${internal.port || "—"}`)}</div>`;

  const lat = rt.latency || {};
  $("#latencyCard").innerHTML = `
    <div class="title">API Latency</div>
    <div class="latency-row">
      <div class="lat-cell"><span class="lat-k">current</span><span class="lat-v mono">${lat.current_ms ?? "—"} ms</span></div>
      <div class="lat-cell"><span class="lat-k">p50</span><span class="lat-v mono">${lat.p50_ms ?? "—"} ms</span></div>
      <div class="lat-cell"><span class="lat-k">p95</span><span class="lat-v mono">${lat.p95_ms ?? "—"} ms</span></div>
    </div>`;

  const ordered = [...rt.services].sort((a, b) => stateRank(a.state) - stateRank(b.state));
  $("#runtimeRows").innerHTML = ordered.map(rowHtml).join("") ||
    `<tr><td colspan="9">${stateBlock("empty", "尚無服務")}</td></tr>`;

  $("#graphBody").innerHTML = depGraph(rt.graph) + graphLegend();
  const uiLink = $("#edgexUiLink");
  if (uiLink && rt.ui_url) uiLink.href = rt.ui_url;
}

function rowHtml(s) {
  const hb = s.heartbeat || "—";
  const cpu = s.cpu_pct != null ? `${s.cpu_pct}%` : "—";
  const mem = s.mem_mb != null ? `${s.mem_mb} MB` : "—";
  const deps = (s.depends_on || []).map((d) => `<span class="dep-chip">${escapeHtml(d)}</span>`).join(" ") || "<span class='muted'>—</span>";
  const actions = (s.actions || []).map((a) =>
    `<button type="button" class="btn btn-ghost btn-xs" data-action="${a}" data-container="${escapeHtml(s.container || "")}">${a}</button>`
  ).join(" ");
  return `<tr>
    <td>${escapeHtml(s.name)}<div class="sub mono">${copyField(s.container, { max: 22 })}</div></td>
    <td class="mono">${escapeHtml(s.version || "—")}</td>
    <td class="mono">${hb}</td>
    <td class="mono">${cpu}</td>
    <td class="mono">${mem}</td>
    <td>${deps}</td>
    <td><span class="diag-text">${escapeHtml(s.diagnosis || "—")}</span></td>
    <td>${badge(STATE_LABEL[s.state] || s.state, s.state)}</td>
    <td class="runtime-actions">${actions}</td>
  </tr>`;
}

function graphLegend() {
  return `<div class="graph-legend">
    ${["green", "yellow", "red", "blue", "gray"].map((s) => `<span class="lg">${dot(s)}${STATE_LABEL[s]}</span>`).join("")}
  </div>`;
}

async function onRowAction(e) {
  const btn = e.target.closest("[data-action]");
  if (!btn) return;
  const action = btn.dataset.action;
  const container = btn.dataset.container;
  if (action === "Restart") {
    if (!confirm(`確定重啟 ${container}？`)) return;
    try {
      const r = await api(`/api/edgex/actions/restart/${encodeURIComponent(container)}`, { method: "POST" });
      toast(r.message || "已重啟");
      await load();
    } catch (err) { toast(err.message, false); }
    return;
  }
  if (action === "Enable") {
    if (!confirm(`確定啟用 ${container}？`)) return;
    try {
      const r = await api(`/api/edgex/actions/start/${encodeURIComponent(container)}`, { method: "POST" });
      toast(r.message || "已啟用");
      await load();
    } catch (err) { toast(err.message, false); }
    return;
  }
  if (action === "View Logs") {
    const mockText = `（示意）docker logs ${escapeHtml(container)}\n— 即時日誌串接尚未實作（mock）。\n請於 Pi 執行：docker logs -f ${escapeHtml(container)}`;
    openDrawer(`Logs · ${container}`, `<pre class="logs-pre mono">載入中…</pre>`);
    try {
      const r = await api(`/api/edgex/actions/logs/${encodeURIComponent(container)}?tail=300`);
      const logs = (r.logs || "").trim();
      openDrawer(`Logs · ${container}`, `<pre class="logs-pre mono">${logs ? escapeHtml(logs) : mockText}</pre>`);
    } catch {
      openDrawer(`Logs · ${container}`, `<pre class="logs-pre mono">${mockText}</pre>`);
    }
    return;
  }
  if (action === "Configure") {
    navigate("setup");
    return;
  }
  if (action === "Install") {
    if (PHASE2_CONTAINERS.includes(container)) {
      if (!confirm("啟用 Phase 2 服務（OPC UA / S7）？")) return;
      try {
        const r = await api(`/api/edgex/phase2/enable`, { method: "POST" });
        toast(r.message || "Phase 2 已啟動");
        await load();
      } catch (err) { toast(err.message, false); }
    } else {
      toast(`「${container}」請於主機手動部署`, false);
    }
    return;
  }
  toast(`「${action}」尚未支援（${container}）`, false);
}
