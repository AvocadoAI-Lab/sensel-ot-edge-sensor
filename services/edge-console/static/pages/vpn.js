// VPN 連線 — OpenVPN client: profiles, connect/disconnect/view/diagnose, and a
// prominent banner showing the internal IP acquired over the tunnel.
import { $, $$, toast, escapeHtml } from "../core/dom.js";
import { api } from "../core/api.js";
import { fmtTime } from "../core/format.js";
import { openDrawer } from "../ui/components.js";

export const meta = { title: "VPN 連線", sub: "OpenVPN · 內網存取" };

let pollTimer = null;
let lastStatus = null;

const STATE_META = {
  connected: { dot: "green", label: "已連線" },
  connecting: { dot: "yellow", label: "連線中…" },
  reconnecting: { dot: "yellow", label: "重新連線中…" },
  disconnected: { dot: "red", label: "未連線" },
  error: { dot: "red", label: "連線錯誤" },
  stale: { dot: "red", label: "狀態過期（vpn-client 未回應）" },
  unknown: { dot: "gray", label: "尚未取得狀態" },
};

export function render(root) {
  root.innerHTML = `
    <section class="page panel">
      <p class="hint">上傳 <span class="mono">.ovpn</span> 設定檔後即可連線。憑證/密碼只儲存在本機並遮蔽顯示，不會寫入審計記錄。連線採分流模式（保留伺服器推送的內網路由，但不接管預設閘道），避免遠端管理連線中斷。</p>

      <div id="vpnDisabled" class="card-state is-degraded hidden">
        <span class="card-state-icon">▲</span>
        <span>VPN 控制未啟用。請設定 <span class="mono">EDGE_CONSOLE_VPN_ADMIN=true</span> 並重啟 Console。</span>
      </div>

      <div id="vpnBanner" class="vpn-banner"></div>

      <p class="settings-section-title">VPN 設定檔</p>
      <div class="net-toolbar">
        <span id="vpnProfilesSummary" class="mono muted">載入中…</span>
        <label class="net-show-virtual" title="勾選後隧道斷線會自動重連；取消勾選則中斷後維持斷線，需手動再連線。">
          <input type="checkbox" id="vpnAutoReconnect" checked /> 斷線自動重連
        </label>
        <button type="button" class="btn btn-ghost btn-sm" id="vpnRefreshBtn">重新整理</button>
      </div>
      <div id="vpnProfileList" class="net-iface-list"></div>
      <p id="vpnProfilesError" class="hint muted hidden"></p>

      <p class="settings-section-title">上傳設定檔</p>
      <div class="net-toolbar">
        <input type="file" id="vpnFileInput" accept=".ovpn,.conf,text/plain" />
        <label class="net-show-virtual">名稱 <input id="vpnUploadName" placeholder="自動由檔名帶入" style="width:12rem" /></label>
        <button type="button" class="btn btn-primary btn-sm" id="vpnUploadBtn">上傳</button>
      </div>
      <p class="hint muted">支援 client 模式、內嵌憑證的 <span class="mono">.ovpn</span>。檔案大小上限 512KB。</p>
    </section>`;

  wire();
  refresh().catch((e) => toast(e.message, false));
  startPolling();
}

export function leave() { stopPolling(); }
export function onVisible() { refresh().catch(() => {}); }

function startPolling() {
  stopPolling();
  pollTimer = setInterval(() => loadStatus().catch(() => {}), 4000);
}
function stopPolling() {
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
}

function wire() {
  $("#vpnRefreshBtn").addEventListener("click", () => refresh().catch((e) => toast(e.message, false)));
  $("#vpnAutoReconnect").addEventListener("change", onAutoReconnectToggle);
  $("#vpnUploadBtn").addEventListener("click", uploadProfile);
  $("#vpnFileInput").addEventListener("change", (e) => {
    const f = e.target.files?.[0];
    if (f && !$("#vpnUploadName").value.trim()) {
      $("#vpnUploadName").value = f.name.replace(/\.(ovpn|conf|txt)$/i, "").replace(/[^A-Za-z0-9._-]/g, "-").slice(0, 64);
    }
  });
}

async function refresh() {
  await loadProfiles();
  await loadStatus();
}

// ---- Status banner ---------------------------------------------------------
function fmtBytes(n) {
  if (n == null) return "—";
  const u = ["B", "KB", "MB", "GB"]; let i = 0; let v = Number(n);
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(i ? 1 : 0)} ${u[i]}`;
}

function renderBanner(status) {
  const banner = $("#vpnBanner");
  if (!banner) return;
  const sd = status?.status_data || {};
  const state = status?.state || "unknown";
  const m = STATE_META[state] || STATE_META.unknown;
  const connected = state === "connected";
  const ip = sd.assigned_ip;

  const rows = [];
  if (sd.profile) rows.push(["設定檔", escapeHtml(sd.profile)]);
  if (sd.server) rows.push(["VPN 伺服器", escapeHtml(sd.server)]);
  if (sd.tun_device) rows.push(["隧道介面", escapeHtml(sd.tun_device)]);
  if (sd.since) rows.push(["連線時間", fmtTime(sd.since)]);
  if (sd.bytes_in != null || sd.bytes_out != null) rows.push(["流量", `↓ ${fmtBytes(sd.bytes_in)} · ↑ ${fmtBytes(sd.bytes_out)}`]);
  if (status?.desired_connect) rows.push(["斷線自動重連", status.desired_auto_reconnect === false ? "停用（中斷後維持斷線）" : "啟用"]);
  if (sd.last_error && !connected) rows.push(["最後錯誤", escapeHtml(sd.last_error)]);

  banner.className = `vpn-banner ${connected ? "is-connected" : state === "connecting" || state === "reconnecting" ? "is-pending" : "is-off"}`;
  banner.innerHTML = `
    <div class="vpn-banner-main">
      <div class="vpn-banner-state"><span class="status-dot ${m.dot}"></span>${escapeHtml(m.label)}</div>
      <div class="vpn-banner-ip">
        <span class="vpn-ip-label">內網 IP</span>
        <span class="vpn-ip-value mono">${connected && ip ? escapeHtml(ip) : "—"}</span>
      </div>
      <div class="vpn-banner-actions">
        <button type="button" class="btn btn-ghost btn-sm" id="vpnDiagBtn">診斷 MQTT</button>
        ${status?.desired_connect ? `<button type="button" class="btn btn-secondary btn-sm" id="vpnDisconnectBtn">中斷連線</button>` : ""}
      </div>
    </div>
    ${rows.length ? `<div class="vpn-banner-detail">${rows.map(([k, v]) => `<div class="net-kv"><span class="net-k">${k}</span><span class="net-v mono">${v}</span></div>`).join("")}</div>` : ""}`;

  $("#vpnDisconnectBtn")?.addEventListener("click", disconnectVpn);
  $("#vpnDiagBtn")?.addEventListener("click", () => diagnose());
}

async function loadStatus() {
  const status = await api("/api/vpn/status");
  lastStatus = status;
  syncAutoReconnect(status);
  renderBanner(status);
  highlightActiveProfile(status);
}

function syncAutoReconnect(status) {
  const cb = $("#vpnAutoReconnect");
  // Don't yank the checkbox out from under the operator mid-toggle.
  if (!cb || cb.dataset.busy === "1" || cb === document.activeElement) return;
  if (typeof status?.desired_auto_reconnect === "boolean") cb.checked = status.desired_auto_reconnect;
}

async function onAutoReconnectToggle(e) {
  const cb = e.target;
  const on = cb.checked;
  cb.dataset.busy = "1";
  try {
    const r = await api("/api/vpn/auto-reconnect", { method: "POST", body: JSON.stringify({ on }) });
    toast(r.message || (on ? "已啟用自動重連" : "已停用自動重連"));
  } catch (err) {
    cb.checked = !on; // revert on failure
    toast(err.message, false);
  } finally {
    delete cb.dataset.busy;
  }
}

// ---- Profiles --------------------------------------------------------------
function highlightActiveProfile(status) {
  const active = status?.desired_connect ? status?.desired_profile : null;
  $$("#vpnProfileList .vpn-profile").forEach((row) => {
    row.classList.toggle("active", row.dataset.profile === active);
  });
}

function renderProfiles(data) {
  const list = $("#vpnProfileList");
  if (!list) return;
  const profiles = data.profiles || [];
  list.innerHTML = "";
  if (!profiles.length) {
    list.innerHTML = `<p class="hint muted">尚無設定檔，請於下方上傳 .ovpn</p>`;
    return;
  }
  for (const p of profiles) {
    const row = document.createElement("div");
    row.className = "net-iface card-ot vpn-profile";
    row.dataset.profile = p.name;
    const meta = [p.remote ? escapeHtml(p.remote) : "—", p.needs_auth ? "需帳密" : "憑證認證"].join(" · ");
    row.innerHTML = `
      <div class="net-iface-head vpn-profile-head">
        <span class="net-iface-name">${escapeHtml(p.name)}</span>
        <span class="net-iface-ip mono">${meta}</span>
        <span class="net-iface-state vpn-profile-actions">
          <button type="button" class="btn btn-primary btn-sm" data-vpn="connect">連線</button>
          <button type="button" class="btn btn-ghost btn-sm" data-vpn="view">檢視</button>
          <button type="button" class="btn btn-ghost btn-sm" data-vpn="delete">刪除</button>
        </span>
      </div>`;
    row.querySelector('[data-vpn="connect"]').addEventListener("click", () => connectVpn(p));
    row.querySelector('[data-vpn="view"]').addEventListener("click", () => viewProfile(p.name));
    row.querySelector('[data-vpn="delete"]').addEventListener("click", () => deleteProfile(p.name));
    list.appendChild(row);
  }
  highlightActiveProfile(lastStatus);
}

async function loadProfiles() {
  const summary = $("#vpnProfilesSummary"), errEl = $("#vpnProfilesError"), disabled = $("#vpnDisabled");
  try {
    const data = await api("/api/vpn/profiles");
    if (disabled) disabled.classList.toggle("hidden", data.admin !== false);
    if (errEl) errEl.classList.add("hidden");
    if (summary) summary.textContent = `${(data.profiles || []).length} 個設定檔`;
    renderProfiles(data);
  } catch (e) {
    if (errEl) { errEl.textContent = e.message; errEl.classList.remove("hidden"); }
  }
}

async function uploadProfile() {
  const input = $("#vpnFileInput");
  const file = input.files?.[0];
  if (!file) { toast("請先選擇 .ovpn 檔案", false); return; }
  let name = $("#vpnUploadName").value.trim();
  if (!name) name = file.name.replace(/\.(ovpn|conf|txt)$/i, "");
  name = name.replace(/[^A-Za-z0-9._-]/g, "-").slice(0, 64);
  if (!name) { toast("名稱無效", false); return; }
  try {
    const body = await file.text();
    const r = await api(`/api/vpn/profiles?name=${encodeURIComponent(name)}`, {
      method: "POST",
      headers: { "Content-Type": "text/plain" },
      body,
    });
    toast(r.message || "已上傳");
    (r.warnings || []).forEach((w) => toast(w, false));
    input.value = ""; $("#vpnUploadName").value = "";
    await loadProfiles();
  } catch (e) { toast(e.message, false); }
}

async function connectVpn(profile) {
  let username = null, password = null;
  if (profile.needs_auth && !profile.has_auth_file) {
    username = window.prompt(`「${profile.name}」需要帳號：`);
    if (username === null) return;
    password = window.prompt(`「${profile.name}」的密碼：`);
    if (password === null) return;
  }
  const autoReconnect = $("#vpnAutoReconnect")?.checked !== false;
  toast(`要求連線：${profile.name}…`);
  try {
    const r = await api("/api/vpn/connect", { method: "POST", body: JSON.stringify({ profile: profile.name, username, password, auto_reconnect: autoReconnect }) });
    toast(r.message || "已要求連線");
    await loadStatus();
  } catch (e) { toast(e.message, false); }
}

async function disconnectVpn() {
  if (!window.confirm("確定要中斷 VPN 連線？")) return;
  try {
    const r = await api("/api/vpn/disconnect", { method: "POST" });
    toast(r.message || "已要求中斷");
    await loadStatus();
  } catch (e) { toast(e.message, false); }
}

async function deleteProfile(name) {
  if (!window.confirm(`確定刪除設定檔「${name}」？`)) return;
  try {
    const r = await api(`/api/vpn/profiles/${encodeURIComponent(name)}`, { method: "DELETE" });
    toast(r.message || "已刪除");
    await loadProfiles();
  } catch (e) { toast(e.message, false); }
}

async function viewProfile(name) {
  try {
    const r = await api(`/api/vpn/profiles/${encodeURIComponent(name)}/view`);
    const warns = (r.warnings || []).map((w) => `<p class="hint">⚠ ${escapeHtml(w)}</p>`).join("");
    openDrawer(`設定檔：${name}`, `
      <div class="net-kv"><span class="net-k">伺服器</span><span class="net-v mono">${escapeHtml(r.remote || "—")}</span></div>
      <div class="net-kv"><span class="net-k">認證</span><span class="net-v">${r.needs_auth ? "帳號 / 密碼" : "憑證"}</span></div>
      ${warns}
      <pre class="mono vpn-view-pre">${escapeHtml(r.content || "")}</pre>`);
  } catch (e) { toast(e.message, false); }
}

async function diagnose(host = "192.168.1.203", port = 1883) {
  toast(`診斷中：${host}:${port}…`);
  try {
    const r = await api(`/api/vpn/diagnose?host=${encodeURIComponent(host)}&port=${port}`, { method: "POST" });
    const p = r.probe || {};
    const tcp = p.tcp_target || {};
    const tunRows = (p.tun_interfaces || []).map((t) => `<div class="net-kv"><span class="net-k">${escapeHtml(t.name)}</span><span class="net-v mono">${escapeHtml(t.ipv4 || "無 IP")}</span></div>`).join("") || `<p class="hint muted">未偵測到 tun 介面</p>`;
    const ok = r.reachable;
    openDrawer(`VPN 診斷 — ${host}:${port}`, `
      <div class="card-state ${ok ? "is-empty" : "is-error"}" style="margin-bottom:0.75rem">
        <span class="card-state-icon">${ok ? "✓" : "⚠"}</span>
        <span>${escapeHtml(r.summary || "")}</span>
      </div>
      <p class="settings-section-title">隧道介面</p>
      ${tunRows}
      <p class="settings-section-title">目標連線（MQTT）</p>
      <div class="net-kv"><span class="net-k">目標</span><span class="net-v mono">${escapeHtml(host)}:${port}</span></div>
      <div class="net-kv"><span class="net-k">解析 IP</span><span class="net-v mono">${escapeHtml(tcp.ip || "—")}</span></div>
      <div class="net-kv"><span class="net-k">TCP 連線</span><span class="net-v">${tcp.ok ? "✓ 成功" : `✗ 失敗（${escapeHtml(tcp.error || "未知")}）`}</span></div>`);
  } catch (e) { toast(e.message, false); }
}
