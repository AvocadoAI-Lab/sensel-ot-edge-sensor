const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

let wizardStep = 1;

const PAGE_META = {
  dashboard: { title: "總覽", sub: "OT 邊緣感測與安全狀態" },
  edgex: { title: "EdgeX 平台", sub: "服務健康 · Message Bus" },
  devices: { title: "設備與協定", sub: "Modbus · MQTT · 點位遙測" },
  setup: { title: "設定精靈", sub: "感測器身分 · SenseL 註冊" },
  events: { title: "安全事件", sub: "Packet Sensor 本地偵測" },
  traffic: { title: "即時流量", sub: "Mirror 埠鏡像 · Telemetry Flow" },
  settings: { title: "進階設定", sub: "北向、擷取與 Console" },
};

const TAB_IDS = ["dashboard", "edgex", "devices", "setup", "events", "traffic", "settings"];
const DASH_POLL_MS = 5000;
const TRAFFIC_POLL_MS = 3000;
const LAB_TRAFFIC_POLL_MS = 10000;
let currentTab = "dashboard";

const BRAND = {
  lime: "#d8f25a",
  limeFill: "rgba(216, 242, 90, 0.14)",
  grid: "rgba(221, 234, 242, 0.08)",
  muted: "#8fa3b8",
};

async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(opts.headers || {}) },
    credentials: "same-origin",
    ...opts,
  });
  if (res.status === 401) {
    showLogin();
    throw new Error("未登入");
  }
  const text = await res.text();
  let data = {};
  try { data = text ? JSON.parse(text) : {}; } catch { data = { detail: text }; }
  if (!res.ok) throw new Error(data.detail || data.error || res.statusText);
  return data;
}

function toast(msg, ok = true) {
  const el = $("#toast");
  el.textContent = msg;
  el.className = `toast ${ok ? "ok" : "err"}`;
  el.classList.remove("hidden");
  setTimeout(() => el.classList.add("hidden"), 3500);
}

function showLogin() {
  $("#loginView").classList.remove("hidden");
  $("#appView").classList.add("hidden");
}

function showApp() {
  $("#loginView").classList.add("hidden");
  $("#appView").classList.remove("hidden");
}

function updatePageHeader(name) {
  const meta = PAGE_META[name] || PAGE_META.dashboard;
  const titleEl = $("#pageTitle");
  const subEl = $("#pageSubtitle");
  if (titleEl) titleEl.textContent = meta.title;
  if (subEl && !subEl.dataset.sensorBound) subEl.textContent = meta.sub;
}

function setSensorHeaderMeta(sensorId, siteId) {
  const subEl = $("#pageSubtitle");
  if (!subEl) return;
  if (sensorId) {
    subEl.textContent = `${sensorId} @ ${siteId || "—"}`;
    subEl.dataset.sensorBound = "1";
  } else {
    delete subEl.dataset.sensorBound;
    const tab = document.querySelector(".nav-item.active[data-tab]")?.dataset.tab || "dashboard";
    updatePageHeader(tab);
  }
  const avatar = $("#headerAvatar");
  if (avatar && sensorId) {
    const parts = String(sensorId).split(/[-_]/).filter(Boolean);
    const abbr = parts.length >= 2
      ? (parts[0][0] + parts[1][0]).toUpperCase()
      : String(sensorId).slice(0, 2).toUpperCase();
    avatar.textContent = abbr;
    avatar.title = sensorId;
  }
}

function updatePolicyShield(baselineOk) {
  const shield = $("#headerShield");
  if (!shield) return;
  if (baselineOk === true) {
    shield.className = "header-shield ok";
    shield.title = "Baseline 已載入";
  } else if (baselineOk === false) {
    shield.className = "header-shield bad";
    shield.title = "Baseline 未就緒";
  } else {
    shield.className = "header-shield";
    shield.title = "Policy / Baseline";
  }
}

function setTab(name) {
  currentTab = name;
  $$(".nav-item[data-tab]").forEach((t) => t.classList.toggle("active", t.dataset.tab === name));
  TAB_IDS.forEach((id) => {
    const el = $(`#tab-${id}`);
    if (el) el.classList.toggle("hidden", id !== name);
  });
  updatePageHeader(name);
  const headerAdd = $("#headerAddDeviceBtn");
  if (headerAdd) headerAdd.classList.toggle("hidden", name !== "devices");
  if (name === "events") loadEvents();
  if (name === "dashboard") {
    loadStatus();
    startDashboardPoll();
  } else stopDashboardPoll();
  if (name === "edgex") loadEdgexPlatform();
  if (name === "devices") loadDevicesPage();
  if (name === "traffic") startTrafficPoll();
  else stopTrafficPoll();
  if (name === "settings") loadAuditLog();
}

function setWizardStep(n) {
  wizardStep = n;
  [1, 2, 3].forEach((i) => {
    $(`#wizardStep${i}`).classList.toggle("hidden", i !== n);
    const pill = document.querySelector(`.step-pill[data-step="${i}"]`);
    pill.classList.toggle("active", i === n);
    pill.classList.toggle("done", i < n);
  });
  if (n === 3) renderWizardSummary();
}

function renderWizardSummary() {
  const html = `
    <div><strong>Sensor</strong> ${$("#wSensorId").value} @ ${$("#wSiteId").value}</div>
    <div><strong>SenseL</strong> ${$("#wApiUrl").value}</div>
    <div><strong>MQTT</strong> ${$("#wMqttHost").value}:1883</div>
    <div><strong>邀請碼</strong> ${$("#wInvite").value ? "已填寫" : "未填寫"}</div>`;
  $("#wizardSummary").innerHTML = html;
}

function collectWizardConfig(extra = {}) {
  return {
    sensor_id: $("#wSensorId").value.trim(),
    site_id: $("#wSiteId").value.trim(),
    sensel_api_url: $("#wApiUrl").value.trim(),
    sensel_api_key: $("#wApiKey").value.trim(),
    registration_token: $("#wInvite").value.trim(),
    mqtt_host: $("#wMqttHost").value.trim(),
    mqtt_port: parseInt($("#sMqttPort").value || "1883", 10),
    sensel_verify_tls: $("#sVerifyTls").value === "true",
    ...extra,
  };
}

async function loadConfigIntoForm(cfg) {
  $("#wSensorId").value = cfg.sensor_id || "";
  $("#wSiteId").value = cfg.site_id || "";
  $("#wApiUrl").value = cfg.sensel_api_url || "";
  $("#wMqttHost").value = cfg.mqtt_host || "";
  $("#sMqttPort").value = cfg.mqtt_port || 1883;
  $("#sVerifyTls").value = cfg.sensel_verify_tls ? "true" : "false";
  $("#sCaptureInterface").value = cfg.capture_interface || "";
  $("#sCaptureBpf").value = cfg.capture_bpf_filter || "";
  $("#sMqttTenant").value = cfg.last_register_tenant_id || cfg.mqtt_tenant_id || "";
  if (!cfg.sensel_api_key_set) $("#wApiKey").placeholder = "（已儲存，留空不變）";
  if (!cfg.registration_token_set) $("#wInvite").placeholder = "（已儲存，留空不變）";
}

function collectSettingsConfig(extra = {}) {
  return {
    mqtt_port: parseInt($("#sMqttPort").value || "1883", 10),
    sensel_verify_tls: $("#sVerifyTls").value === "true",
    capture_interface: $("#sCaptureInterface").value.trim(),
    capture_bpf_filter: $("#sCaptureBpf").value.trim(),
    ...extra,
  };
}

const POLICY_GAUGE_CIRC = 2 * Math.PI * 48;
const dashRateHistory = [];
const DASH_HISTORY_MAX = 45;
let dashboardTimer = null;

function renderPolicyGauge(policy) {
  if (!policy) return;
  const pct = Math.max(0, Math.min(100, Number(policy.percent) || 0));
  const fill = $("#policyGaugeFill");
  if (fill) {
    fill.setAttribute("stroke-dasharray", `${(POLICY_GAUGE_CIRC * pct) / 100} ${POLICY_GAUGE_CIRC}`);
  }
  setText("#policyGaugePct", `${Math.round(pct)}%`);
  setText("#policyGaugeLabel", policy.label || "—");
  const factors = (policy.factors || []).join(" · ");
  setText("#policyGaugeFactors", factors ? `含：${factors}` : "");
}

function renderDashTelemetryChart() {
  const canvas = $("#dashTelemetryChart");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  const w = Math.max(rect.width, 200);
  const h = 88;
  canvas.width = w * dpr;
  canvas.height = h * dpr;
  ctx.setTransform(1, 0, 0, 1, 0, 0);
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, w, h);
  const data = dashRateHistory;
  if (data.length < 2) {
    ctx.fillStyle = BRAND.muted;
    ctx.font = "11px Poppins, sans-serif";
    ctx.fillText("等待流量…", 8, h / 2);
    return;
  }
  const max = Math.max(...data, 1);
  const pad = 6;
  const innerW = w - pad * 2;
  const innerH = h - pad * 2;
  const step = innerW / Math.max(data.length - 1, 1);
  ctx.beginPath();
  ctx.strokeStyle = BRAND.lime;
  ctx.lineWidth = 2;
  data.forEach((val, i) => {
    const x = pad + i * step;
    const y = pad + innerH - (val / max) * innerH;
    if (i === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.stroke();
}

function applyTelemetryMetrics(telemetry, live) {
  const t = telemetry || {};
  const rate = Number(t.instant_rate) || 0;
  setText("#dashTelemetryRate", formatRate(rate));
  const meta = $("#dashTelemetryMeta");
  if (meta) {
    meta.textContent = live
      ? `${t.unique_ips ?? 0} IP · ${t.unique_macs ?? 0} MAC · GOOSE ${t.goose_messages ?? 0} · IoC ${t.ioc_entries ?? 0}`
      : "Mirror 未連線或資料過期";
  }
  dashRateHistory.push(rate);
  if (dashRateHistory.length > DASH_HISTORY_MAX) dashRateHistory.shift();
  renderDashTelemetryChart();
}

async function loadStatus() {
  const data = await api("/api/status");
  const cards = data.cards || {};
  const cardOrder = ["registration", "mqtt", "capture", "baseline", "sensel"];
  const html = cardOrder
    .filter((key) => cards[key])
    .map((key) => {
      const c = cards[key];
      const dot = c.ok === true ? "ok" : c.ok === false ? "bad" : "unk";
      return `<div class="card card-ot"><div class="title">${c.label}</div>
        <div class="value"><span class="status-dot ${dot}"></span><span class="mono">${c.detail}</span></div></div>`;
    })
    .join("");
  $("#statusCards").innerHTML = html || "<div class='card muted'>尚無狀態</div>";

  const metrics = data.metrics || {};
  renderPolicyGauge(metrics.policy_gauge);
  applyTelemetryMetrics(metrics.telemetry, metrics.telemetry?.live);

  const topRules = metrics.top_rules_24h || [];
  const ruleBox = $("#ruleSummary");
  if (topRules.length) {
    const chips = topRules.map(([rid, n]) => `<span class="rule-chip">${rid} ×${n}</span>`).join(" ");
    const iface = metrics.capture_interface || "—";
    const bpf = metrics.capture_bpf ? metrics.capture_bpf.slice(0, 60) + (metrics.capture_bpf.length > 60 ? "…" : "") : "—";
    ruleBox.innerHTML = `<div class="title">24h 規則活動</div><div class="value">${chips}</div>
      <div class="sub">介面 <span class="mono">${iface}</span> · BPF <span class="mono">${bpf}</span></div>`;
    ruleBox.classList.remove("hidden");
  } else {
    ruleBox.classList.add("hidden");
  }

  if (data.sensor_id) {
    setSensorHeaderMeta(data.sensor_id, data.site_id);
  }
  const baseline = cards.baseline;
  updatePolicyShield(baseline ? baseline.ok : undefined);
}

function stopDashboardPoll() {
  if (dashboardTimer) {
    clearInterval(dashboardTimer);
    dashboardTimer = null;
  }
}

function startDashboardPoll() {
  stopDashboardPoll();
  dashboardTimer = setInterval(() => {
    if (document.hidden || currentTab !== "dashboard") return;
    loadStatus().catch(() => {});
  }, DASH_POLL_MS);
}

let cachedEvents = [];

function renderEvents(events) {
  const rows = $("#eventsRows");
  rows.innerHTML = "";
  if (!events.length) {
    rows.innerHTML = `<tr><td colspan="6" class="hint">無符合條件的事件</td></tr>`;
    return;
  }
  for (const e of events) {
    const tr = document.createElement("tr");
    tr.className = `sev-${(e.severity || "medium").toLowerCase()}`;
    const srcIp = e.src_ip || "";
    const assetHtml = e.matched_device
      ? `<span class="mono">${e.matched_device}</span><div class="sub mono">${srcIp}</div>`
      : `<span class="mono">${srcIp || "—"}</span>`;
    const srcChip =
      e.asset_source === "edgex"
        ? '<span class="source-chip edgex">EdgeX</span>'
        : e.asset_source === "mirror"
          ? '<span class="source-chip mirror">Mirror</span>'
          : "";
    tr.innerHTML = `<td>${e.timestamp || ""}</td><td><span class="rule-chip">${e.rule_id || ""}</span></td>
      <td>${assetHtml} ${srcChip}</td>
      <td>${e.severity || ""}</td><td><span class="purdue-badge">${e.purdue_level || "L2"}</span></td>
      <td>${e.description || e.event_type || ""}</td>`;
    rows.appendChild(tr);
  }
}

function renderDiscovery(discovery) {
  const rows = $("#discoveryRows");
  const summary = $("#discoverySummary");
  if (!rows) return;
  const assets = discovery?.assets || [];
  if (summary) {
    summary.textContent = `EdgeX ${discovery.edgex_device_count ?? 0} 台 · 僅 Mirror 發現 ${discovery.mirror_only_count ?? 0} · 即時 ${discovery.traffic_live ? "是" : "否"}`;
  }
  rows.innerHTML = "";
  if (!assets.length) {
    rows.innerHTML = `<tr><td colspan="5" class="hint">尚無資產（請確認 mirror 有流量）</td></tr>`;
    return;
  }
  for (const a of assets) {
    const tr = document.createElement("tr");
    const src = a.source === "edgex" ? "edgex" : "mirror";
    tr.innerHTML = `<td>${a.label || a.ip}</td>
      <td class="mono">${a.ip || "—"}</td>
      <td><span class="source-chip ${src}">${src === "edgex" ? "EdgeX" : "Mirror"}</span></td>
      <td class="mono">${a.edgex_device || "—"}</td>
      <td class="mono">${a.packets ?? "—"}</td>`;
    rows.appendChild(tr);
  }
}

async function loadAuditLog() {
  const box = $("#auditLogBox");
  if (!box) return;
  try {
    const data = await api("/api/audit/recent?limit=25");
    const lines = (data.entries || [])
      .map((e) => `${e.at}  ${e.action}  ${JSON.stringify(e.detail || {})}`)
      .join("\n");
    box.textContent = lines || "尚無審計記錄";
    box.classList.remove("muted");
  } catch (e) {
    box.textContent = e.message;
  }
}

function filterEvents(events) {
  const sev = ($("#eventFilterSeverity")?.value || "").trim().toLowerCase();
  const rulePrefix = ($("#eventFilterRule")?.value || "").trim().toUpperCase();
  return (events || []).filter((e) => {
    if (sev && String(e.severity || "").toLowerCase() !== sev) return false;
    if (rulePrefix && !String(e.rule_id || "").toUpperCase().startsWith(rulePrefix)) return false;
    return true;
  });
}

function applyEventFilters() {
  renderEvents(filterEvents(cachedEvents));
}

async function loadEvents() {
  const data = await api("/api/events/recent?limit=50");
  cachedEvents = data.events || [];
  applyEventFilters();
}

let trafficTimer = null;
let labTrafficTimer = null;
let labTrafficState = null;
const trafficRateHistory = [];
const TRAFFIC_HISTORY_MAX = 60;

function stopTrafficPoll() {
  if (trafficTimer) {
    clearInterval(trafficTimer);
    trafficTimer = null;
  }
  if (labTrafficTimer) {
    clearInterval(labTrafficTimer);
    labTrafficTimer = null;
  }
}

function startTrafficPoll() {
  stopTrafficPoll();
  const metricsBox = $("#trafficMetrics");
  if (metricsBox && !metricsBox.innerHTML.trim()) {
    metricsBox.innerHTML = '<div class="card card-ot muted"><div class="value">載入中…</div></div>';
  }
  loadTraffic().catch((e) => showTrafficError(e.message || "載入失敗"));
  loadLabTrafficStatus().catch(() => {});
  trafficTimer = setInterval(() => {
    if (document.hidden || currentTab !== "traffic") return;
    loadTraffic().catch(() => {});
  }, TRAFFIC_POLL_MS);
  labTrafficTimer = setInterval(() => {
    if (document.hidden || currentTab !== "traffic") return;
    loadLabTrafficStatus().catch(() => {});
  }, LAB_TRAFFIC_POLL_MS);
}

function labStatusDotClass(running, exists) {
  if (!exists) return "bad";
  return running ? "ok" : "unk";
}

function labStatusLabel(running, exists, status) {
  if (!exists) return "未部署";
  if (running) return "運行中";
  if (status === "exited") return "已停止";
  return status || "—";
}

function renderLabTrafficCard(item, dockerOk) {
  const dot = labStatusDotClass(item.running, item.exists !== false);
  const label = labStatusLabel(item.running, item.exists !== false, item.status);
  const disabled = !dockerOk ? "disabled" : "";
  const toggleAction = item.running ? "stop" : "start";
  const toggleLabel = item.running ? "暫停" : "開始";
  const restartBtn =
    item.id === "capture"
      ? `<button type="button" class="btn btn-sm btn-ghost" data-lab-action="restart" data-lab-target="capture" ${disabled}>重啟</button>`
      : "";
  return `
    <div class="lab-card" data-lab-card="${item.id}">
      <div class="lab-card-title">${item.label || item.id}</div>
      <div class="lab-card-status">
        <span class="status-dot ${dot}"></span>
        <span>${label}</span>
      </div>
      <div class="lab-card-sub mono">${item.summary || item.interface || item.bpf_filter || "—"}</div>
      <div class="lab-card-actions">
        <button type="button" class="btn btn-sm" data-lab-action="${toggleAction}" data-lab-target="${item.id}" ${disabled}>${toggleLabel}</button>
        ${restartBtn}
      </div>
    </div>`;
}

function renderLabTrafficPanel(data) {
  const panel = $("#labTrafficPanel");
  if (!panel) return;
  if (!data?.enabled) {
    panel.classList.add("hidden");
    return;
  }
  panel.classList.remove("hidden");
  const dockerOk = data.docker_control_enabled === true;
  const msg = $("#labTrafficMsg");
  if (msg) {
    msg.textContent = dockerOk
      ? ""
      : "Docker 控制已停用或無 socket；請在 Pi 上設定 EDGE_CONSOLE_DOCKER_RESTART=1";
  }
  const cards = $("#labTrafficCards");
  if (cards) {
    const pub = (data.publishers || []).map((p) => renderLabTrafficCard(p, dockerOk)).join("");
    const cap = data.capture ? renderLabTrafficCard({ ...data.capture, id: "capture" }, dockerOk) : "";
    cards.innerHTML = pub + cap;
  }
  const presets = $("#labTrafficPresets");
  if (presets) {
    const disabled = !dockerOk ? "disabled" : "";
    presets.innerHTML = (data.presets || [])
      .map(
        (p) =>
          `<button type="button" class="btn btn-sm btn-ghost" data-lab-preset="${p.id}" ${disabled}>${p.label}</button>`
      )
      .join("");
  }
}

async function loadLabTrafficStatus() {
  let data;
  try {
    data = await api("/api/lab/traffic/status");
  } catch {
    return;
  }
  labTrafficState = data;
  renderLabTrafficPanel(data);
}

async function labTrafficAction(action, target) {
  const body = { action, targets: [target] };
  const res = await api("/api/lab/traffic/actions", { method: "POST", body: JSON.stringify(body) });
  toast(res.ok ? "已套用" : "部分失敗", !!res.ok);
  await Promise.all([loadLabTrafficStatus(), loadTraffic()]);
}

async function labTrafficPreset(presetId) {
  const res = await api("/api/lab/traffic/actions", {
    method: "POST",
    body: JSON.stringify({ preset: presetId }),
  });
  toast(res.ok ? "快捷已套用" : "部分失敗", !!res.ok);
  await Promise.all([loadLabTrafficStatus(), loadTraffic()]);
}

document.addEventListener("visibilitychange", () => {
  if (document.hidden) return;
  if (currentTab === "dashboard") loadStatus().catch(() => {});
  if (currentTab === "traffic") loadTraffic().catch(() => {});
});

function formatRate(n) {
  const v = Number(n) || 0;
  if (v >= 1000) return `${(v / 1000).toFixed(1)}k`;
  return v.toFixed(v >= 10 ? 0 : 1);
}

function protoClass(proto) {
  const p = String(proto || "").toUpperCase();
  if (p.includes("GOOSE")) return "proto-goose";
  if (p.includes("MMS")) return "proto-mms";
  return "";
}

function renderTrafficChart() {
  const canvas = $("#trafficRateChart");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  const w = Math.max(rect.width, 300);
  const h = 120;
  canvas.width = w * dpr;
  canvas.height = h * dpr;
  ctx.setTransform(1, 0, 0, 1, 0, 0);
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, w, h);

  const data = trafficRateHistory;
  if (data.length < 2) {
    ctx.fillStyle = BRAND.muted;
    ctx.font = "12px Poppins, sans-serif";
    ctx.fillText("等待流量資料…", 12, h / 2);
    return;
  }

  const max = Math.max(...data, 1);
  const pad = 8;
  const innerW = w - pad * 2;
  const innerH = h - pad * 2;
  const step = innerW / Math.max(data.length - 1, 1);

  ctx.strokeStyle = BRAND.grid;
  ctx.lineWidth = 1;
  for (let i = 0; i <= 3; i++) {
    const y = pad + (innerH * i) / 3;
    ctx.beginPath();
    ctx.moveTo(pad, y);
    ctx.lineTo(w - pad, y);
    ctx.stroke();
  }

  ctx.beginPath();
  ctx.strokeStyle = BRAND.lime;
  ctx.lineWidth = 2;
  ctx.shadowColor = BRAND.lime;
  ctx.shadowBlur = 8;
  data.forEach((val, i) => {
    const x = pad + i * step;
    const y = pad + innerH - (val / max) * innerH;
    if (i === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.stroke();
  ctx.shadowBlur = 0;

  ctx.lineTo(pad + (data.length - 1) * step, pad + innerH);
  ctx.lineTo(pad, pad + innerH);
  ctx.closePath();
  ctx.fillStyle = BRAND.limeFill;
  ctx.fill();

  ctx.fillStyle = BRAND.muted;
  ctx.font = "11px IBM Plex Mono, monospace";
  ctx.fillText(`${formatRate(max)} pkt/s`, pad, 14);
  ctx.fillText(`${formatRate(data[data.length - 1])} now`, w - pad - 70, 14);
}

function renderTrafficTopList(el, items, keyName) {
  if (!el) return;
  if (!items.length) {
    el.innerHTML = '<span class="muted">尚無資料</span>';
    el.classList.add("muted");
    return;
  }
  el.classList.remove("muted");
  el.innerHTML = items
    .map(
      (item) =>
        `<div class="row"><span class="mono">${item[keyName] || "—"}</span><span>${item.count}</span></div>`
    )
    .join("");
}

function renderTrafficRecent(packets) {
  const rows = $("#trafficRecentRows");
  if (!rows) return;
  rows.innerHTML = "";
  if (!packets.length) {
    rows.innerHTML = `<tr><td colspan="6" class="hint">尚無封包（請確認 mirror 介面有流量）</td></tr>`;
    return;
  }
  for (const p of packets.slice(0, 30)) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td class="mono">${p.at || ""}</td>
      <td><span class="rule-chip ${protoClass(p.proto)}">${p.proto || "—"}</span></td>
      <td class="mono">${p.src_mac || "—"}</td>
      <td class="mono">${p.src_ip || "—"}</td>
      <td class="mono">${p.dst_ip || "—"}</td>
      <td class="mono">${p.size || 0} B</td>`;
    rows.appendChild(tr);
  }
}

function setText(id, text) {
  const el = $(id);
  if (el) el.textContent = text;
}

function showTrafficError(msg) {
  const box = $("#trafficMetrics");
  if (box) {
    box.innerHTML = `<div class="card card-ot traffic-alert bad"><div class="title">無法載入流量</div><div class="value">${msg}</div><div class="sub">請強制重新整理（Ctrl+Shift+R）或確認 packet-sensor 容器運行中</div></div>`;
  }
}

function formatDockerStatus(docker) {
  const st = docker?.status || "—";
  const dot = docker?.running === true ? "ok" : docker?.running === false ? "bad" : "unk";
  return `<span class="status-dot ${dot}"></span><span class="mono">${st}</span>`;
}

function formatApiStatus(api) {
  if (!api) return '<span class="muted">—</span>';
  if (api.ok) return `<span class="status-dot ok"></span><span class="mono">${api.latency_ms ?? "—"} ms</span>`;
  return `<span class="status-dot bad"></span><span class="mono" title="${api.error || ""}">fail</span>`;
}

async function loadEdgexPlatform() {
  const data = await api("/api/edgex/platform");
  const dot = $("#edgexReachDot");
  const label = $("#edgexReachLabel");
  if (dot) dot.className = `status-dot ${data.reachable ? "ok" : "bad"}`;
  if (label) {
    label.textContent = data.reachable
      ? "Core 連線正常"
      : "Core 無法連線（請確認 EdgeX 堆疊）";
  }

  const bus = data.message_bus || {};
  const internal = bus.edgex_internal || {};
  const local = bus.local_features || {};
  $("#edgexBusCard").innerHTML = `
    <div class="title">Message Bus</div>
    <div class="value">
      EdgeX 內部 <span class="mono">${internal.host || "—"}:${internal.port || "—"}</span>
      · 特徵匯流 <span class="mono">${local.host || "—"}:${local.port || "—"}</span>
    </div>
    <div class="sub">${local.note || ""} · metadata ${data.metadata_url || ""}</div>`;

  const rows = $("#edgexServicesRows");
  rows.innerHTML = "";
  for (const s of data.services || []) {
    const tr = document.createElement("tr");
    const canRestart =
      s.container &&
      [
        "edgex-device-modbus",
        "edgex-device-mqtt",
        "edgex-device-opc-ua",
        "edgex-device-s7",
      ].includes(s.container) &&
      s.docker?.running !== null;
    const restartBtn = canRestart
      ? `<button type="button" class="btn btn-ghost btn-sm edgex-restart-btn" data-container="${s.container}">重啟</button>`
      : '<span class="muted">—</span>';
    const apiCell = formatApiStatus(s.api);
    tr.innerHTML = `<td>${s.label}</td>
      <td class="mono">${s.container}</td>
      <td class="mono">${s.port ?? "—"}</td>
      <td>${formatDockerStatus(s.docker)}</td>
      <td>${apiCell}</td>
      <td>${restartBtn}</td>`;
    rows.appendChild(tr);
  }

  const uiLink = $("#edgexUiLink");
  if (uiLink && data.ui_url) {
    uiLink.href = data.ui_url;
  }
}

async function restartEdgexService(container) {
  if (!confirm(`確定重啟 ${container}？`)) return;
  try {
    const r = await api(`/api/edgex/actions/restart/${encodeURIComponent(container)}`, { method: "POST" });
    toast(r.message || "已重啟");
    await loadEdgexPlatform();
  } catch (e) {
    toast(e.message, false);
  }
}

function renderProtocolMatrix(protocols) {
  const box = $("#protocolMatrix");
  if (!box) return;
  box.innerHTML = (protocols || [])
    .map((p) => {
      const cls = p.enabled ? "on" : "off";
      const title = p.reason || "";
      const click = p.phase === 2 ? `data-protocol="${p.id}"` : "";
      const extra = p.phase === 2 ? " clickable" : "";
      return `<span class="protocol-chip ${cls}${extra}" ${click} title="${title}">${p.label}<span class="phase">P${p.phase}</span></span>`;
    })
    .join("");
  box.querySelectorAll(".protocol-chip.clickable").forEach((chip) => {
    chip.addEventListener("click", () => {
      const pid = chip.dataset.protocol;
      if (pid === "opcua" || pid === "s7") openDeviceWizard(pid);
    });
  });
}

const WIZARD_DEFAULTS = {
  modbus: { host: "modbus-simulator", port: 1502 },
  mqtt: { host: "local-mqtt", port: 1883 },
  opcua: { host: "192.168.1.50", port: 4840 },
  s7: { host: "192.168.1.60", port: 102 },
};

function syncWizardFields() {
  const proto = $("#dwProtocol")?.value || "modbus";
  const defs = WIZARD_DEFAULTS[proto] || {};
  if ($("#dwHost") && !$("#dwHost").dataset.touched) $("#dwHost").value = defs.host || "";
  if ($("#dwPort") && !$("#dwPort").dataset.touched) $("#dwPort").value = defs.port ?? "";
  const isS7 = proto === "s7";
  const isOpc = proto === "opcua";
  $("#dwRackLabel")?.classList.toggle("hidden", !isS7);
  $("#dwSlotLabel")?.classList.toggle("hidden", !isS7);
  $("#dwEndpointLabel")?.classList.toggle("hidden", !isOpc);
}

function openDeviceWizard(protocol) {
  const w = $("#deviceWizard");
  const bar = $("#devicesToolbar");
  if (w) w.classList.remove("hidden");
  bar?.scrollIntoView({ behavior: "smooth", block: "nearest" });
  if ($("#dwProtocol")) {
    $("#dwProtocol").value = protocol || "modbus";
    delete $("#dwHost")?.dataset.touched;
    delete $("#dwPort")?.dataset.touched;
    syncWizardFields();
  }
}

async function loadPhase2Banner() {
  const banner = $("#phase2Banner");
  const text = $("#phase2StatusText");
  try {
    const st = await api("/api/edgex/phase2/status");
    if (banner) banner.classList.remove("hidden");
    const lines = (st.services || [])
      .map((s) => `${s.container}: ${s.status}`)
      .join(" · ");
    if (text) {
      text.textContent = st.enabled
        ? `已啟用 · ${lines}`
        : `未啟用 · ${st.compose_hint || ""}`;
    }
  } catch {
    if (banner) banner.classList.add("hidden");
  }
}

async function saveDeviceWizard() {
  const proto = $("#dwProtocol").value;
  const body = {
    protocol: proto,
    name: $("#dwName").value.trim(),
    host: $("#dwHost").value.trim(),
    port: parseInt($("#dwPort").value || "0", 10),
    interval: $("#dwInterval").value.trim() || "10s",
  };
  if (proto === "s7") {
    body.rack = parseInt($("#dwRack").value || "0", 10);
    body.slot = parseInt($("#dwSlot").value || "1", 10);
  }
  if (proto === "opcua" && $("#dwEndpoint").value.trim()) {
    body.endpoint = $("#dwEndpoint").value.trim();
  }
  const r = await api("/api/edgex/config/devices", { method: "POST", body: JSON.stringify(body) });
  $("#dwResult").textContent = JSON.stringify(r, null, 2);
  toast(`設備 ${r.name} 已寫入 ${r.file}`);
  await loadDevicesPage();
}

async function probeDeviceWizard() {
  const proto = $("#dwProtocol").value;
  const host = $("#dwHost").value.trim();
  const port = parseInt($("#dwPort").value || "0", 10);
  const r = await api("/api/edgex/diagnostics/connect", {
    method: "POST",
    body: JSON.stringify({ protocol: proto, host, port }),
  });
  $("#dwResult").textContent = JSON.stringify(r, null, 2);
  toast(r.ok ? "連線成功" : r.error || "連線失敗", r.ok);
}

async function runDiagSuite() {
  const box = $("#diagResults");
  const body = $("#diagResultsBody");
  box?.classList.remove("hidden");
  if (body) body.innerHTML = "診斷中…";
  const r = await api("/api/edgex/diagnostics/suite");
  const lines = (r.checks || []).map(
    (c) =>
      `<div class="row"><span>${c.protocol} ${c.host || ""}:${c.port || ""}</span><span class="${c.ok ? "ok" : "bad"}">${c.ok ? "OK" : c.error || "fail"}</span></div>`
  );
  const p2 = r.phase2?.enabled ? "Phase2 ON" : "Phase2 OFF";
  if (body) {
    body.innerHTML = lines.join("") + `<div class="sub" style="margin-top:0.5rem">${p2}</div>`;
    body.classList.remove("muted");
  }
}

function renderDevicesTable(devices) {
  const rows = $("#devicesRows");
  rows.innerHTML = "";
  if (!devices.length) {
    rows.innerHTML = `<tr><td colspan="6" class="hint">尚無設備（請確認 EdgeX metadata 或 config/edgex/devices）</td></tr>`;
    return;
  }
  for (const d of devices) {
    const tr = document.createElement("tr");
    tr.className = "device-row";
    tr.dataset.device = d.name;
    const up = String(d.operatingState || "").toUpperCase() === "UP";
    const stDot = up ? "ok" : "bad";
    tr.innerHTML = `<td class="mono">${d.name}</td>
      <td>${d.protocol || "—"}</td>
      <td class="mono">${d.profileName || "—"}</td>
      <td class="mono">${d.endpoint || "—"}</td>
      <td><span class="status-dot ${stDot}"></span>${d.operatingState || "—"}</td>
      <td class="mono">${d.last_event_at || "—"}</td>`;
    tr.addEventListener("click", () => selectDevice(d.name, tr));
    rows.appendChild(tr);
  }
}

let selectedDeviceName = null;

async function selectDevice(name, rowEl) {
  selectedDeviceName = name;
  $$("tr.device-row").forEach((r) => r.classList.toggle("selected", r === rowEl));
  const panel = $("#deviceDetail");
  const nameEl = $("#deviceDetailName");
  const readingsEl = $("#deviceReadings");
  if (panel) panel.classList.remove("hidden");
  if (nameEl) nameEl.textContent = name;
  if (readingsEl) readingsEl.innerHTML = '<span class="muted">載入點位中…</span>';
  try {
    const data = await api(`/api/edgex/devices/${encodeURIComponent(name)}/readings?limit=15`);
    if (!data.ok) {
      readingsEl.innerHTML = `<span class="muted">${data.error || "無法載入"}</span>`;
      return;
    }
    const readings = data.readings || [];
    if (!readings.length) {
      readingsEl.innerHTML = '<span class="muted">尚無 readings（請確認 autoEvents / MQTT 流量）</span>';
      return;
    }
    readingsEl.classList.remove("muted");
    readingsEl.innerHTML = readings
      .slice(0, 20)
      .map(
        (r) =>
          `<div class="reading-row"><span class="mono">${r.resourceName}</span><span>${r.value} <span class="muted">${r.valueType || ""}</span></span></div>`
      )
      .join("");
  } catch (e) {
    readingsEl.innerHTML = `<span class="muted">${e.message}</span>`;
  }
}

async function loadDevicesPage() {
  const [proto, dev, discovery] = await Promise.all([
    api("/api/edgex/protocols"),
    api("/api/edgex/devices"),
    api("/api/edgex/discovery"),
  ]);
  await loadPhase2Banner();
  renderProtocolMatrix(proto.protocols);
  renderDiscovery(discovery);
  const summary = $("#devicesSummary");
  if (summary) {
    const src = dev.source === "metadata" ? "EdgeX metadata" : dev.source === "config" ? "本地 config" : "—";
    summary.textContent = `${dev.online ?? 0} / ${dev.count ?? 0} UP · 來源 ${src}`;
    if (dev.metadata_error) summary.textContent += ` · ${dev.metadata_error}`;
  }
  renderDevicesTable(dev.devices || []);
  if (selectedDeviceName) {
    const row = document.querySelector(`tr.device-row[data-device="${selectedDeviceName}"]`);
    if (row) selectDevice(selectedDeviceName, row);
  }
}

async function loadTraffic() {
  const panel = $("#tab-traffic");
  if (!panel) {
    showTrafficError("頁面版本過舊，請強制重新整理瀏覽器（Ctrl+Shift+R）");
    return;
  }

  let data;
  try {
    data = await api("/api/traffic/live");
  } catch (e) {
    showTrafficError(e.message || "API 請求失敗");
    return;
  }

  const dot = $("#trafficLiveDot");
  const label = $("#trafficLiveLabel");
  const live = data.live === true;
  if (dot) dot.className = `status-dot ${live ? "ok" : data.stale ? "bad" : "unk"}`;
  if (label) {
    if (live) label.textContent = `即時 · ${data.age_sec ?? 0}s 前更新`;
    else label.textContent = data.message || "資料過期或未連線";
  }

  setText("#trafficIface", data.capture_interface || "—");
  setText("#trafficBackend", data.capture_backend || "—");
  const bpf = data.capture_bpf || "";
  setText("#trafficBpf", bpf.length > 72 ? `${bpf.slice(0, 72)}…` : bpf || "—");

  const m = data.metrics || {};
  trafficRateHistory.push(Number(m.instant_rate) || 0);
  if (trafficRateHistory.length > TRAFFIC_HISTORY_MAX) trafficRateHistory.shift();
  renderTrafficChart();

  const idle = m.idle_sec != null ? `${m.idle_sec}s` : "—";
  const metricsHtml = [
    ["即時速率", `<span class="traffic-rate-big">${formatRate(m.instant_rate)}</span><span class="sub"> pkt/s</span>`, ""],
    ["平均速率", `${formatRate(m.packet_rate)} pkt/s`, `累計 ${m.total_packets ?? 0}`],
    ["視窗封包", `${m.window_packets ?? 0}`, `IPv4 ${m.ipv4_packets ?? 0} · IPv6 ${m.ipv6_packets ?? 0}`],
    ["IEC 61850", `GOOSE ${m.goose_messages ?? 0}`, `MMS 寫 ${m.mms_writes ?? 0} · 連線 ${m.mms_sessions ?? 0}`],
    ["資產指紋", `${m.unique_macs ?? 0} MAC`, `${m.unique_ips ?? 0} IP · 閒置 ${idle}`],
    ["執行時間", `${Math.round(m.elapsed_sec ?? 0)}s`, `IoC 條目 ${m.ioc_entries ?? 0}`],
  ]
    .map(
      ([title, value, sub]) =>
        `<div class="card card-ot"><div class="title">${title}</div><div class="value">${value}</div>${
          sub ? `<div class="sub">${sub}</div>` : ""
        }</div>`
    )
    .join("");
  const metricsBox = $("#trafficMetrics");
  if (metricsBox) {
    const alert = !live
      ? `<div class="card card-ot traffic-alert warn" style="grid-column:1/-1"><div class="value">${data.message || "等待 Packet Sensor 寫入 capture-live.json"}</div></div>`
      : "";
    metricsBox.innerHTML = alert + metricsHtml;
  }

  renderTrafficTopList($("#trafficTopMacs"), data.top_macs || [], "mac");
  renderTrafficTopList($("#trafficTopIps"), data.top_ips || [], "ip");
  renderTrafficRecent(data.recent_packets || []);
}

$("#labTrafficPanel")?.addEventListener("click", async (ev) => {
  const presetBtn = ev.target.closest("[data-lab-preset]");
  if (presetBtn && !presetBtn.disabled) {
    try {
      await labTrafficPreset(presetBtn.getAttribute("data-lab-preset"));
    } catch (e) {
      toast(e.message || "操作失敗", false);
    }
    return;
  }
  const actionBtn = ev.target.closest("[data-lab-action]");
  if (!actionBtn || actionBtn.disabled) return;
  const action = actionBtn.getAttribute("data-lab-action");
  const target = actionBtn.getAttribute("data-lab-target");
  if (!action || !target) return;
  try {
    await labTrafficAction(action, target);
  } catch (e) {
    toast(e.message || "操作失敗", false);
  }
});

async function boot() {
  const auth = await fetch("/api/auth/status").then((r) => r.json());
  if (auth.password_required && !auth.authenticated) {
    showLogin();
    return;
  }
  showApp();
  const cfg = await api("/api/config");
  await loadConfigIntoForm(cfg);
  if (!cfg.configured) setTab("setup");
  else {
    setTab("dashboard");
    await loadStatus();
  }
}

$("#loginBtn")?.addEventListener("click", async () => {
  try {
    await api("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ password: $("#loginPassword").value }),
    });
    await boot();
  } catch (e) {
    toast(e.message, false);
  }
});

$("#logoutBtn")?.addEventListener("click", async () => {
  await api("/api/auth/logout", { method: "POST" });
  showLogin();
});

$$(".nav-item[data-tab]").forEach((btn) => {
  btn.addEventListener("click", () => setTab(btn.dataset.tab));
});

$("#sidebarToggle")?.addEventListener("click", () => {
  $("#appView")?.classList.toggle("sidebar-collapsed");
});

$("#refreshEdgexBtn")?.addEventListener("click", () =>
  loadEdgexPlatform().catch((e) => toast(e.message, false))
);
$("#refreshDevicesBtn")?.addEventListener("click", () =>
  loadDevicesPage().catch((e) => toast(e.message, false))
);

document.addEventListener("click", (ev) => {
  const btn = ev.target.closest(".edgex-restart-btn");
  if (btn?.dataset.container) restartEdgexService(btn.dataset.container);
});

function toggleDeviceWizard() {
  const wiz = $("#deviceWizard");
  if (!wiz) return;
  if (wiz.classList.contains("hidden")) {
    openDeviceWizard($("#dwProtocol")?.value);
  } else {
    wiz.classList.add("hidden");
  }
}

$("#toggleWizardBtn")?.addEventListener("click", toggleDeviceWizard);
$("#headerAddDeviceBtn")?.addEventListener("click", () => {
  setTab("devices");
  toggleDeviceWizard();
});

$("#dwProtocol")?.addEventListener("change", () => {
  delete $("#dwHost")?.dataset.touched;
  delete $("#dwPort")?.dataset.touched;
  syncWizardFields();
});
$("#dwHost")?.addEventListener("input", () => {
  if ($("#dwHost")) $("#dwHost").dataset.touched = "1";
});
$("#dwPort")?.addEventListener("input", () => {
  if ($("#dwPort")) $("#dwPort").dataset.touched = "1";
});

$("#dwSaveBtn")?.addEventListener("click", () =>
  saveDeviceWizard().catch((e) => toast(e.message, false))
);
$("#dwProbeBtn")?.addEventListener("click", () =>
  probeDeviceWizard().catch((e) => toast(e.message, false))
);
$("#diagSuiteBtn")?.addEventListener("click", () =>
  runDiagSuite().catch((e) => toast(e.message, false))
);
$("#enablePhase2Btn")?.addEventListener("click", async () => {
  try {
    const r = await api("/api/edgex/phase2/enable", { method: "POST" });
    toast(r.message || "Phase 2 已啟用");
    await loadDevicesPage();
    await loadEdgexPlatform();
  } catch (e) {
    toast(e.message, false);
  }
});

$("#refreshAuditBtn")?.addEventListener("click", () =>
  loadAuditLog().catch((e) => toast(e.message, false))
);

$("#deleteDeviceBtn")?.addEventListener("click", async () => {
  if (!selectedDeviceName || !confirm(`刪除 config 設備 ${selectedDeviceName}？`)) return;
  try {
    await api(`/api/edgex/config/devices/${encodeURIComponent(selectedDeviceName)}`, { method: "DELETE" });
    toast("已刪除");
    selectedDeviceName = null;
    $("#deviceDetail")?.classList.add("hidden");
    await loadDevicesPage();
  } catch (e) {
    toast(e.message, false);
  }
});

$$("[data-next]").forEach((btn) => {
  btn.addEventListener("click", () => setWizardStep(parseInt(btn.dataset.next, 10)));
});

$("#pingSenselBtn")?.addEventListener("click", async () => {
  try {
    await api("/api/config", { method: "PUT", body: JSON.stringify(collectWizardConfig()) });
    const r = await api("/api/sensel/ping", { method: "POST" });
    toast(r.ok ? "SenseL 連線正常" : (r.error || "連線失敗"), r.ok);
  } catch (e) {
    toast(e.message, false);
  }
});

$("#saveAndRegisterBtn")?.addEventListener("click", async () => {
  try {
    await api("/api/config", { method: "PUT", body: JSON.stringify(collectWizardConfig()) });
    const r = await api("/api/register/test", { method: "POST", body: JSON.stringify({ save_first: true }) });
    $("#registerResult").textContent = JSON.stringify(r, null, 2);
    toast(r.ok ? `註冊成功 · tenant ${r.tenant_id}` : (r.error || "註冊失敗"), !!r.ok);
    if (r.ok) {
      setTab("dashboard");
      await loadStatus();
    }
  } catch (e) {
    toast(e.message, false);
  }
});

$("#saveSettingsBtn")?.addEventListener("click", async () => {
  try {
    await api("/api/config", {
      method: "PUT",
      body: JSON.stringify(collectSettingsConfig()),
    });
    const pw1 = $("#sNewPassword").value;
    const pw2 = $("#sNewPassword2").value;
    if (pw1 || pw2) {
      if (pw1 !== pw2) throw new Error("兩次密碼不一致");
      const current = prompt("請輸入目前 Console 密碼以確認變更");
      if (!current) throw new Error("已取消");
      await api("/api/auth/password", {
        method: "PUT",
        body: JSON.stringify({ current_password: current, new_password: pw1 }),
      });
      $("#sNewPassword").value = "";
      $("#sNewPassword2").value = "";
    }
    toast("設定已儲存");
  } catch (e) {
    toast(e.message, false);
  }
});

$("#reloadCaptureBtn")?.addEventListener("click", async () => {
  try {
    const r = await api("/api/capture/reload", { method: "POST" });
    toast(r.message || "Packet Sensor 已重啟");
  } catch (e) {
    toast(e.message, false);
  }
});

$("#refreshStatusBtn")?.addEventListener("click", () => loadStatus().catch((e) => toast(e.message, false)));
$("#eventFilterSeverity")?.addEventListener("change", applyEventFilters);
$("#eventFilterRule")?.addEventListener("input", applyEventFilters);
$("#eventFilterClear")?.addEventListener("click", () => {
  if ($("#eventFilterSeverity")) $("#eventFilterSeverity").value = "";
  if ($("#eventFilterRule")) $("#eventFilterRule").value = "";
  applyEventFilters();
});
$("#restartAgentBtn")?.addEventListener("click", async () => {
  try {
    const r = await api("/api/agent/restart", { method: "POST" });
    toast(r.message || "Agent 已重啟");
  } catch (e) {
    toast(e.message, false);
  }
});

boot().catch(() => showLogin());
