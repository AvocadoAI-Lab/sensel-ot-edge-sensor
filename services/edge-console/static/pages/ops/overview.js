// 總覽 Tab — status cards + recent changes.
import { $, escapeHtml, toast } from "../../core/dom.js";
import { fmtTime, relTime } from "../../core/format.js";
import { signalBars } from "../../ui/components.js";
import { getSystemStatus, diagnoseNetwork, getWifiProfiles, getAuditLogs,
  testMqttConnection, testCapture } from "../../core/opsApi.js";

export const id = "overview";
export const label = "總覽";

function card({ key, icon, title, state, metric, sub, actions }) {
  const acts = (actions || []).map((a) =>
    `<button type="button" class="btn btn-ghost btn-sm" data-ov-act="${a.act}" data-ov-arg="${escapeHtml(a.arg || "")}">${escapeHtml(a.label)}</button>`).join("");
  return `
    <div class="ops-card ov-card ${state}" data-card="${key}">
      <div class="ops-card-head">
        <span class="ov-card-icon">${icon}</span>
        <span class="ops-card-title">${escapeHtml(title)}</span>
        <span class="status-dot ${state}"></span>
      </div>
      <div class="ov-card-metric">${metric}</div>
      <div class="ov-card-sub mono">${sub || ""}</div>
      <div class="ops-card-actions">${acts}</div>
    </div>`;
}

export function render(container, ctx) {
  container.innerHTML = `<div class="ops-grid ov-grid" id="ovGrid">
    <div class="card-state is-loading">載入狀態中…</div></div>`;
  load(container, ctx);

  container.addEventListener("click", async (e) => {
    const btn = e.target.closest("[data-ov-act]");
    if (!btn) return;
    const act = btn.dataset.ovAct, arg = btn.dataset.ovArg;
    if (act === "goto") ctx.switchTab(arg);
    else if (act === "test-mqtt") { toast("測試北向連線中…"); const r = await testMqttConnection(); toast(r.ok ? "MQTT 連線正常" : (r.error || "MQTT 未連線"), r.ok); }
    else if (act === "test-capture") { toast("擷取測試中…"); const r = await testCapture(10); toast(`10 秒內 ${r.packets} 封包${r.MOCK ? "（估算）" : ""}`); }
    else if (act === "test-net") { toast("網路診斷中…"); const r = await diagnoseNetwork(); const bad = r.checks.filter((c) => !c.ok); toast(bad.length ? `異常：${bad.map((c) => c.label).join(", ")}` : "網路檢查全數通過", bad.length === 0); }
  });
}

async function load(container, ctx) {
  const grid = $("#ovGrid", container);
  const [sys, net, wifi, audit] = await Promise.all([
    getSystemStatus().catch(() => null),
    diagnoseNetwork().catch(() => null),
    getWifiProfiles().catch(() => null),
    getAuditLogs({ limit: 5 }).catch(() => []),
  ]);
  ctx.system = sys || ctx.system;
  if (!grid) return;
  if (!sys) { grid.innerHTML = `<div class="card-state is-error">無法取得狀態</div>`; return; }

  const agentState = sys.agent.last_error ? "yellow" : sys.agent.registered ? "green" : "yellow";
  const captureState = sys.capture.ok ? "green" : "yellow";
  const mqttState = sys.mqtt.connected ? "green" : "red";
  const tls = sys.raw?.metrics ? null : null;
  const tlsLabel = (sys.mqtt && sys.mqtt.detail) || "";

  const netOk = net ? net.checks.every((c) => c.ok) : false;
  const netState = net ? (netOk ? "green" : net.checks.some((c) => c.ok) ? "yellow" : "red") : "gray";
  const def = net?.default_route;

  const activeWifi = (wifi?.interfaces || []).find((d) => d.connected);
  const wifiState = activeWifi ? "green" : (wifi?.available ? "yellow" : "gray");
  const pinned = (wifi?.pinned || []).length;

  const cards = [
    card({
      key: "agent", icon: "⬡", title: "Edge Agent", state: agentState,
      metric: agentState === "green" ? "running" : "degraded",
      sub: `更新 ${sys.agent.updated_at ? relTime(sys.agent.updated_at) : "—"}${sys.agent.last_error ? ` · ${escapeHtml(sys.agent.last_error)}` : ""}`,
      actions: [{ act: "goto", arg: "diagnostics", label: "查看服務" }],
    }),
    card({
      key: "packet", icon: "◎", title: "Packet Sensor", state: captureState,
      metric: sys.capture.ok ? "running" : "idle",
      sub: `${escapeHtml(sys.capture.detail)} · iface ${escapeHtml(sys.capture.interface || "—")}`,
      actions: [{ act: "goto", arg: "packet", label: "查看設定" }, { act: "test-capture", label: "重新測試" }],
    }),
    card({
      key: "mqtt", icon: "☁", title: "SenseL MQTT", state: mqttState,
      metric: sys.mqtt.connected ? "connected" : "disconnected",
      sub: `${escapeHtml(tlsLabel)} · 最後發布 ${sys.mqtt.last_publish_at ? relTime(sys.mqtt.last_publish_at) : "—"}`,
      actions: [{ act: "goto", arg: "northbound", label: "查看設定" }, { act: "test-mqtt", label: "重新測試" }],
    }),
    card({
      key: "network", icon: "⇄", title: "Network Health", state: netState,
      metric: netOk ? "healthy" : "attention",
      sub: def ? `default ${escapeHtml(def.name)} → ${escapeHtml(def.gateway || "—")}` : "無預設路由",
      actions: [{ act: "goto", arg: "network", label: "查看介面" }, { act: "test-net", label: "重新測試" }],
    }),
    card({
      key: "wifi", icon: "≋", title: "Wi-Fi Backhaul", state: wifiState,
      metric: activeWifi ? escapeHtml(activeWifi.active_ssid || "已連線") : (wifi?.available ? "未連線" : "無無線網卡"),
      sub: activeWifi ? `${signalBars(activeWifi.signal || 0)} ${activeWifi.signal || 0}% · 備援 ${pinned} 個` : `備援 ${pinned} 個`,
      actions: [{ act: "goto", arg: "wifi", label: "查看設定" }],
    }),
    recentChangesCard(audit),
  ];
  grid.innerHTML = cards.join("");
}

function recentChangesCard(audit) {
  const rows = (audit || []).slice(0, 5).map((a) =>
    `<div class="ov-change-row">
      <span class="ov-change-time mono">${fmtTime(a.at)}</span>
      <span class="ov-change-act">${escapeHtml(a.action)}</span>
      <span class="state-badge ${a.result === "ok" ? "green" : "red"}">${a.result}</span>
    </div>`).join("") || `<p class="hint muted">尚無記錄</p>`;
  return `
    <div class="ops-card ov-card ov-card-wide gray">
      <div class="ops-card-head">
        <span class="ov-card-icon">🕑</span>
        <span class="ops-card-title">最近變更</span>
      </div>
      <div class="ov-change-list">${rows}</div>
    </div>`;
}
