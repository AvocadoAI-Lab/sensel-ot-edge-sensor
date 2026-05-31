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
  ["dashboard", "setup", "events", "settings"].forEach((id) => {
    $(`#tab-${id}`).classList.toggle("hidden", id !== name);
  });
  if (name === "events") loadEvents();
  if (name === "dashboard") loadStatus();
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
  if (!cfg.sensel_api_key_set) $("#wApiKey").placeholder = "（已儲存，留空不變）";
  if (!cfg.registration_token_set) $("#wInvite").placeholder = "（已儲存，留空不變）";
}

async function loadStatus() {
  const data = await api("/api/status");
  const cards = data.cards || {};
  const html = Object.entries(cards).map(([key, c]) => {
    const dot = c.ok === true ? "ok" : c.ok === false ? "bad" : "unk";
    return `<div class="card"><div class="title">${c.label}</div>
      <div class="value"><span class="status-dot ${dot}"></span>${c.detail}</div></div>`;
  }).join("");
  $("#statusCards").innerHTML = html || "<div class='card muted'>尚無狀態</div>";
}

async function loadEvents() {
  const data = await api("/api/events/recent?limit=50");
  const rows = $("#eventsRows");
  rows.innerHTML = "";
  for (const e of data.events || []) {
    const tr = document.createElement("tr");
    tr.className = `sev-${(e.severity || "medium").toLowerCase()}`;
    tr.innerHTML = `<td>${e.timestamp || ""}</td><td><code>${e.rule_id || ""}</code></td>
      <td>${e.severity || ""}</td><td>${e.description || e.event_type || ""}</td>`;
    rows.appendChild(tr);
  }
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
      body: JSON.stringify(collectWizardConfig()),
    });
    toast("設定已儲存");
  } catch (e) {
    toast(e.message, false);
  }
});

$("#refreshStatusBtn")?.addEventListener("click", () => loadStatus().catch((e) => toast(e.message, false)));
$("#restartAgentBtn")?.addEventListener("click", async () => {
  try {
    const r = await api("/api/agent/restart", { method: "POST" });
    toast(r.message || "Agent 已重啟");
  } catch (e) {
    toast(e.message, false);
  }
});

boot().catch(() => showLogin());
