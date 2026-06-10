// 系統維運 — northbound, capture, network interfaces, Wi-Fi, console, audit.
import { $, $$, toast, escapeHtml } from "../core/dom.js";
import { api } from "../core/api.js";
import { fmtTime } from "../core/format.js";
import { signalBars, stateBlock } from "../ui/components.js";

export const meta = { title: "系統維運", sub: "北向 · 擷取 · 網路 · Console" };

let cachedInterfaces = [];
let netAdminEnabled = false;

export function render(root) {
  root.innerHTML = `
    <section class="page panel">
      <p class="hint">修改後請儲存，並重啟 Edge Agent / Packet Sensor 使設定生效。</p>

      <p class="settings-section-title">SenseL 北向</p>
      <div class="grid-2">
        <label>MQTT Port<input id="sMqttPort" type="number" value="1883" /></label>
        <label>TLS 驗證 SenseL<select id="sVerifyTls"><option value="false">關閉 (Lab)</option><option value="true">開啟</option></select></label>
        <label>MQTT Tenant（唯讀）<input id="sMqttTenant" readonly placeholder="註冊後自動填入" /></label>
      </div>

      <p class="settings-section-title">擷取 (Packet Sensor)</p>
      <div class="grid-2">
        <label>擷取介面 (CAPTURE_INTERFACE)<input id="sCaptureInterface" placeholder="eth0" list="ifaceOptions" /><datalist id="ifaceOptions"></datalist></label>
        <label class="col-span-2">BPF Filter<input id="sCaptureBpf" placeholder="(ether proto 0x88b8) or (tcp port 102)" /></label>
      </div>

      <p class="settings-section-title">網路介面</p>
      <p class="hint">主機實體網卡連線狀態。<span class="net-dot status-dot green"></span>已取得 IP&nbsp;&nbsp;<span class="net-dot status-dot yellow"></span>已連線無 IP&nbsp;&nbsp;<span class="net-dot status-dot red"></span>未連線</p>
      <div class="net-toolbar">
        <span id="netIfacesSummary" class="mono muted">載入中…</span>
        <label class="net-show-virtual"><input type="checkbox" id="netShowVirtual" /> 顯示虛擬介面</label>
        <button type="button" class="btn btn-ghost btn-sm" id="refreshNetIfacesBtn">重新整理</button>
      </div>
      <div id="netIfacesList" class="net-iface-list"></div>
      <p id="netIfacesError" class="hint muted hidden"></p>

      <div id="wifiPanel" class="wifi-panel hidden">
        <p class="settings-section-title">Wi-Fi 無線網路</p>
        <p class="hint">透過主機 NetworkManager 掃描並連線。密碼只送往本機，不會記錄。</p>
        <div class="net-toolbar">
          <label class="net-show-virtual"><input type="checkbox" id="wifiRadioToggle" /> 開啟 Wi-Fi 無線電</label>
          <span id="wifiStatus" class="mono muted">—</span>
          <button type="button" class="btn btn-ghost btn-sm" id="wifiScanBtn">掃描</button>
        </div>
        <div id="wifiList" class="net-iface-list"></div>
        <p id="wifiError" class="hint muted hidden"></p>
      </div>

      <p class="settings-section-title">Console</p>
      <div class="grid-2">
        <label>新密碼<input id="sNewPassword" type="password" autocomplete="new-password" /></label>
        <label>確認新密碼<input id="sNewPassword2" type="password" autocomplete="new-password" /></label>
      </div>

      <p class="settings-section-title">安全審計</p>
      <p class="hint">登入、改密、設備變更、容器重啟等操作寫入 <span class="mono">data/agent/console-audit.jsonl</span></p>
      <div id="auditLogBox" class="card mono muted" style="font-size:0.8rem;max-height:160px;overflow:auto">載入中…</div>
      <button type="button" class="btn btn-ghost btn-sm" id="refreshAuditBtn" style="margin-top:0.5rem">重新整理審計</button>

      <div class="actions">
        <button type="button" class="btn btn-primary" id="saveSettingsBtn">儲存設定</button>
        <button type="button" class="btn btn-secondary" id="reloadCaptureBtn">重啟 Packet Sensor</button>
      </div>
    </section>`;

  wire();
  loadConfig().catch(() => {});
  loadAuditLog().catch(() => {});
  loadNetInterfaces().catch((e) => toast(e.message, false));
  loadWifi().catch(() => {});
}

export function leave() {}

function wire() {
  $("#refreshNetIfacesBtn").addEventListener("click", () => loadNetInterfaces().catch((e) => toast(e.message, false)));
  $("#netShowVirtual").addEventListener("change", renderNetInterfaces);
  $("#wifiScanBtn").addEventListener("click", () => loadWifi(true).catch((e) => toast(e.message, false)));
  $("#wifiRadioToggle").addEventListener("change", (e) => setWifiRadio(e.target.checked));
  $("#refreshAuditBtn").addEventListener("click", () => loadAuditLog().catch((e) => toast(e.message, false)));
  $("#saveSettingsBtn").addEventListener("click", saveSettings);
  $("#reloadCaptureBtn").addEventListener("click", async () => {
    try { const r = await api("/api/capture/reload", { method: "POST" }); toast(r.message || "Packet Sensor 已重啟"); }
    catch (e) { toast(e.message, false); }
  });
}

async function loadConfig() {
  const cfg = await api("/api/config");
  $("#sMqttPort").value = cfg.mqtt_port || 1883;
  $("#sVerifyTls").value = cfg.sensel_verify_tls ? "true" : "false";
  $("#sCaptureInterface").value = cfg.capture_interface || "";
  $("#sCaptureBpf").value = cfg.capture_bpf_filter || "";
  $("#sMqttTenant").value = cfg.last_register_tenant_id || cfg.mqtt_tenant_id || "";
}

async function saveSettings() {
  try {
    await api("/api/config", { method: "PUT", body: JSON.stringify({
      mqtt_port: parseInt($("#sMqttPort").value || "1883", 10),
      sensel_verify_tls: $("#sVerifyTls").value === "true",
      capture_interface: $("#sCaptureInterface").value.trim(),
      capture_bpf_filter: $("#sCaptureBpf").value.trim(),
    }) });
    const pw1 = $("#sNewPassword").value, pw2 = $("#sNewPassword2").value;
    if (pw1 || pw2) {
      if (pw1 !== pw2) throw new Error("兩次密碼不一致");
      const current = prompt("請輸入目前 Console 密碼以確認變更");
      if (!current) throw new Error("已取消");
      await api("/api/auth/password", { method: "PUT", body: JSON.stringify({ current_password: current, new_password: pw1 }) });
      $("#sNewPassword").value = ""; $("#sNewPassword2").value = "";
    }
    toast("設定已儲存");
  } catch (e) { toast(e.message, false); }
}

async function loadAuditLog() {
  const box = $("#auditLogBox");
  if (!box) return;
  try {
    const data = await api("/api/audit/recent?limit=25");
    const lines = (data.entries || []).map((e) => `${fmtTime(e.at)}  ${e.action}  ${JSON.stringify(e.detail || {})}`).join("\n");
    box.textContent = lines || "尚無審計記錄";
    box.classList.remove("muted");
  } catch (e) { box.textContent = e.message; }
}

// ---- Network interfaces (ported) -------------------------------------------
function ipSummary(iface) {
  const parts = [];
  if (iface.ipv4) parts.push(iface.ipv4);
  if ((iface.ipv6 || []).length) parts.push(iface.ipv6[0]);
  return parts.length ? parts.join(" · ") : "無 IP";
}

function netIfaceControls(iface) {
  if (!iface.can_toggle) return `<div class="net-kv"><span class="net-k">控制</span><span class="net-v muted">${escapeHtml(iface.toggle_block_reason || "不可操作")}</span></div>`;
  const isUp = iface.link_up;
  return `<div class="net-kv"><span class="net-k">控制</span><span class="net-v net-iface-actions">
    <button type="button" class="btn btn-ghost btn-sm" data-net-action="up" ${isUp ? "disabled" : ""}>啟用</button>
    <button type="button" class="btn btn-ghost btn-sm" data-net-action="down" ${isUp ? "" : "disabled"}>停用</button></span></div>`;
}

function renderNetInterfaces() {
  const list = $("#netIfacesList");
  if (!list) return;
  const showVirtual = $("#netShowVirtual")?.checked;
  const items = cachedInterfaces.filter((i) => showVirtual || !i.virtual);
  list.innerHTML = "";
  if (!items.length) { list.innerHTML = `<p class="hint muted">無可顯示的網路介面</p>`; return; }
  for (const iface of items) {
    const row = document.createElement("div");
    row.className = "net-iface card-ot";
    const kindLabel = iface.kind === "wireless" ? "無線" : "有線";
    const speed = iface.speed_mbps ? `${iface.speed_mbps} Mbps` : "—";
    const ipv6Lines = (iface.ipv6 || []).map((a) => `<div class="mono">${escapeHtml(a)}</div>`).join("") || '<span class="muted">—</span>';
    row.innerHTML = `
      <button type="button" class="net-iface-head">
        <span class="status-dot ${iface.dot}"></span>
        <span class="net-iface-name mono">${escapeHtml(iface.name)}</span>
        <span class="net-kind-chip ${iface.kind}">${kindLabel}</span>
        ${iface.virtual ? '<span class="net-kind-chip virtual">虛擬</span>' : ""}
        <span class="net-iface-ip mono">${escapeHtml(ipSummary(iface))}</span>
        <span class="net-iface-state">${escapeHtml(iface.state_label)}</span>
        <span class="net-iface-caret" aria-hidden="true">▾</span>
      </button>
      <div class="net-iface-detail hidden">
        <div class="net-kv"><span class="net-k">狀態</span><span class="net-v">${escapeHtml(iface.state_label)}（operstate=${escapeHtml(iface.operstate || "—")} · carrier=${iface.carrier ?? "—"}）</span></div>
        <div class="net-kv"><span class="net-k">類型</span><span class="net-v">${kindLabel}${iface.virtual ? " · 虛擬" : ""}${iface.default_route ? " · 預設路由" : ""}</span></div>
        <div class="net-kv"><span class="net-k">MAC</span><span class="net-v mono">${escapeHtml(iface.mac || "—")}</span></div>
        <div class="net-kv"><span class="net-k">IPv4</span><span class="net-v mono">${escapeHtml(iface.ipv4 || "—")}</span></div>
        <div class="net-kv"><span class="net-k">IPv6</span><span class="net-v">${ipv6Lines}</span></div>
        <div class="net-kv"><span class="net-k">速率</span><span class="net-v mono">${speed}</span></div>
        <div class="net-kv"><span class="net-k">MTU</span><span class="net-v mono">${iface.mtu || "—"}</span></div>
        ${netAdminEnabled ? netIfaceControls(iface) : ""}
      </div>`;
    const head = row.querySelector(".net-iface-head");
    const detail = row.querySelector(".net-iface-detail");
    head.addEventListener("click", () => { detail.classList.toggle("hidden"); row.classList.toggle("expanded"); });
    row.querySelector('[data-net-action="up"]')?.addEventListener("click", () => toggleInterface(iface.name, true));
    row.querySelector('[data-net-action="down"]')?.addEventListener("click", () => toggleInterface(iface.name, false));
    list.appendChild(row);
  }
}

function populateIfaceDatalist() {
  const dl = $("#ifaceOptions");
  if (!dl) return;
  dl.innerHTML = cachedInterfaces.filter((i) => !i.virtual)
    .map((i) => `<option value="${escapeHtml(i.name)}">${i.kind === "wireless" ? "無線" : "有線"} · ${escapeHtml(ipSummary(i))}</option>`).join("");
}

async function toggleInterface(name, up) {
  if (!up && !window.confirm(`確定要停用介面 ${name}？可能中斷該介面上的連線。`)) return;
  try {
    const r = await api(`/api/network/interfaces/${encodeURIComponent(name)}/state`, { method: "POST", body: JSON.stringify({ up }) });
    toast(r.message || `${name} 已更新`);
    await loadNetInterfaces();
  } catch (e) { toast(e.message, false); }
}

async function loadNetInterfaces() {
  const summary = $("#netIfacesSummary"), errEl = $("#netIfacesError");
  try {
    const data = await api("/api/network/interfaces");
    cachedInterfaces = data.interfaces || [];
    netAdminEnabled = data.net_admin_enabled === true;
    if (!data.ok) {
      if (errEl) { errEl.textContent = data.error || "無法取得網卡資訊"; errEl.classList.remove("hidden"); }
      if (summary) summary.textContent = "—";
    } else {
      if (errEl) errEl.classList.add("hidden");
      const s = data.summary || {};
      const srcNote = data.source === "console-local" ? "（來源：Console 本機）" : "";
      if (summary) summary.textContent = `實體介面 ${s.total ?? 0} · 🟢 ${s.up_ip ?? 0} · 🟠 ${s.up_no_ip ?? 0} · 🔴 ${s.down ?? 0} ${srcNote}`;
    }
    renderNetInterfaces();
    populateIfaceDatalist();
  } catch (e) {
    if (errEl) { errEl.textContent = e.message; errEl.classList.remove("hidden"); }
  }
}

// ---- Wi-Fi -----------------------------------------------------------------
// Per-interface: each wireless card can connect to its own network. One card is
// the "primary uplink" (owns the default route); the rest are never-default.
function renderWifiNetworks(listEl, networks, activeSsid, iface) {
  if (!listEl) return;
  listEl.innerHTML = "";
  if (!networks.length) { listEl.innerHTML = '<p class="hint muted">無可用網路（請開啟無線電後掃描）</p>'; return; }
  networks.forEach((nw) => {
    const row = document.createElement("div");
    row.className = "net-iface wifi-row" + (nw.in_use ? " expanded" : "");
    const lock = nw.open ? "" : "🔒";
    const active = nw.in_use || nw.ssid === activeSsid;
    row.innerHTML = `<div class="net-iface-head">
      <span class="net-iface-name">${lock} ${escapeHtml(nw.ssid)}${active ? ' <span class="net-kind-chip">已連線</span>' : ""}</span>
      <span class="net-iface-ip mono">${escapeHtml(nw.band)} · ${escapeHtml(nw.security)}</span>
      <span class="net-iface-state mono">${signalBars(nw.signal)} ${nw.signal}%</span></div>`;
    row.querySelector(".net-iface-head").addEventListener("click", () => connectWifi(nw, iface));
    listEl.appendChild(row);
  });
}

function renderWifiInterfaces(data) {
  const list = $("#wifiList");
  if (!list) return;
  list.innerHTML = "";
  const ifaces = data.interfaces || [];
  if (!ifaces.length) { list.innerHTML = '<p class="hint muted">未偵測到無線網卡</p>'; return; }
  const multi = ifaces.length > 1;
  ifaces.forEach((dev) => {
    const block = document.createElement("div");
    block.className = "wifi-iface";
    const connLabel = dev.connected ? `已連線：${escapeHtml(dev.active_ssid || "—")}` : "未連線";
    const primaryOpt = multi
      ? `<label class="wifi-primary-opt${dev.connected ? "" : " disabled"}" title="設為對外上網（持有預設路由）的網卡">
           <input type="radio" name="wifiPrimary" value="${escapeHtml(dev.device)}" ${dev.is_primary ? "checked" : ""} ${dev.connected ? "" : "disabled"} /> 主要上行
         </label>`
      : "";
    block.innerHTML = `
      <div class="wifi-iface-head">
        <span class="net-iface-name mono">${escapeHtml(dev.device)}</span>
        <span class="wifi-iface-conn mono muted">${connLabel}</span>
        ${primaryOpt}
      </div>
      <div class="net-iface-list wifi-net-list"></div>`;
    renderWifiNetworks(block.querySelector(".wifi-net-list"), dev.networks || [], dev.active_ssid, dev.device);
    block.querySelector('input[name="wifiPrimary"]')?.addEventListener("change", (e) => {
      if (e.target.checked) setWifiPrimary(dev.device);
    });
    list.appendChild(block);
  });
}

async function connectWifi(nw, iface) {
  if (nw.in_use) {
    if (!window.confirm(`中斷與 ${nw.ssid} 的連線？`)) return;
    try { const r = await api("/api/network/wifi/disconnect", { method: "POST", body: JSON.stringify({ iface }) }); toast(r.message || "已斷線"); await loadWifi(); await loadNetInterfaces(); }
    catch (e) { toast(e.message, false); }
    return;
  }
  let password = null;
  if (!nw.open) { password = window.prompt(`輸入 ${nw.ssid} 的 Wi-Fi 密碼：`); if (password === null) return; }
  toast(`連線中：${nw.ssid}（${iface || "wlan"}）…`);
  try {
    const r = await api("/api/network/wifi/connect", { method: "POST", body: JSON.stringify({ ssid: nw.ssid, password, iface }) });
    toast(r.message || `已連線到 ${nw.ssid}`);
    await loadWifi(); await loadNetInterfaces();
  } catch (e) { toast(e.message, false); }
}

async function loadWifi(rescan = false) {
  const panel = $("#wifiPanel"), statusEl = $("#wifiStatus"), errEl = $("#wifiError"), toggle = $("#wifiRadioToggle");
  if (!panel) return;
  try {
    const data = await api(`/api/network/wifi${rescan ? "?rescan=true" : ""}`);
    if (!data.available) { panel.classList.add("hidden"); return; }
    panel.classList.remove("hidden");
    if (errEl) errEl.classList.add("hidden");
    if (toggle) toggle.checked = data.radio_on === true;
    if (statusEl) {
      const n = (data.interfaces || []).length;
      statusEl.textContent = data.radio_on ? `無線電開啟 · ${n} 張無線網卡` : "無線電關閉";
    }
    renderWifiInterfaces(data);
  } catch (e) { if (errEl) { errEl.textContent = e.message; errEl.classList.remove("hidden"); } }
}

async function setWifiPrimary(iface) {
  try { const r = await api("/api/network/wifi/primary", { method: "POST", body: JSON.stringify({ iface }) }); toast(r.message || "已設定主要上行"); await loadWifi(); await loadNetInterfaces(); }
  catch (e) { toast(e.message, false); await loadWifi(); }
}

async function setWifiRadio(on) {
  try { const r = await api("/api/network/wifi/radio", { method: "POST", body: JSON.stringify({ on }) }); toast(r.message || "已更新"); await loadWifi(); }
  catch (e) { toast(e.message, false); await loadWifi(); }
}
