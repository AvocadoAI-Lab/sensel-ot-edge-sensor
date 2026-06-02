const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

let wizardStep = 1;

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

function setTab(name) {
  $$(".tab[data-tab]").forEach((t) => t.classList.toggle("active", t.dataset.tab === name));
  ["dashboard", "setup", "events", "traffic", "settings"].forEach((id) => {
    $(`#tab-${id}`).classList.toggle("hidden", id !== name);
  });
  if (name === "events") loadEvents();
  if (name === "dashboard") loadStatus();
  if (name === "traffic") startTrafficPoll();
  else stopTrafficPoll();
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
    document.querySelector(".brand p").textContent =
      `OT 邊緣 · ${data.sensor_id} @ ${data.site_id || "—"}`;
  }
}

let cachedEvents = [];

function renderEvents(events) {
  const rows = $("#eventsRows");
  rows.innerHTML = "";
  if (!events.length) {
    rows.innerHTML = `<tr><td colspan="5" class="hint">無符合條件的事件</td></tr>`;
    return;
  }
  for (const e of events) {
    const tr = document.createElement("tr");
    tr.className = `sev-${(e.severity || "medium").toLowerCase()}`;
    tr.innerHTML = `<td>${e.timestamp || ""}</td><td><span class="rule-chip">${e.rule_id || ""}</span></td>
      <td>${e.severity || ""}</td><td><span class="purdue-badge">${e.purdue_level || "L2"}</span></td>
      <td>${e.description || e.event_type || ""}</td>`;
    rows.appendChild(tr);
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
const trafficRateHistory = [];
const TRAFFIC_HISTORY_MAX = 60;

function stopTrafficPoll() {
  if (trafficTimer) {
    clearInterval(trafficTimer);
    trafficTimer = null;
  }
}

function startTrafficPoll() {
  stopTrafficPoll();
  const metricsBox = $("#trafficMetrics");
  if (metricsBox && !metricsBox.innerHTML.trim()) {
    metricsBox.innerHTML = '<div class="card card-ot muted"><div class="value">載入中…</div></div>';
  }
  loadTraffic().catch((e) => showTrafficError(e.message || "載入失敗"));
  trafficTimer = setInterval(() => {
    loadTraffic().catch(() => {});
  }, 1000);
}

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
    ctx.fillStyle = "#8b9cb3";
    ctx.font = "12px Inter, sans-serif";
    ctx.fillText("等待流量資料…", 12, h / 2);
    return;
  }

  const max = Math.max(...data, 1);
  const pad = 8;
  const innerW = w - pad * 2;
  const innerH = h - pad * 2;
  const step = innerW / Math.max(data.length - 1, 1);

  ctx.strokeStyle = "rgba(42, 53, 68, 0.8)";
  ctx.lineWidth = 1;
  for (let i = 0; i <= 3; i++) {
    const y = pad + (innerH * i) / 3;
    ctx.beginPath();
    ctx.moveTo(pad, y);
    ctx.lineTo(w - pad, y);
    ctx.stroke();
  }

  ctx.beginPath();
  ctx.strokeStyle = "#14b8a6";
  ctx.lineWidth = 2;
  data.forEach((val, i) => {
    const x = pad + i * step;
    const y = pad + innerH - (val / max) * innerH;
    if (i === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.stroke();

  ctx.lineTo(pad + (data.length - 1) * step, pad + innerH);
  ctx.lineTo(pad, pad + innerH);
  ctx.closePath();
  ctx.fillStyle = "rgba(20, 184, 166, 0.12)";
  ctx.fill();

  ctx.fillStyle = "#8b9cb3";
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

$$(".tab[data-tab]").forEach((btn) => {
  btn.addEventListener("click", () => setTab(btn.dataset.tab));
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
