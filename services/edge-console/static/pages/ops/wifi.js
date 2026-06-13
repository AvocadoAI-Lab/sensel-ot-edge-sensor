// Wi-Fi / 離線重連 Tab — current connection, priority manager, auto-reconnect.
import { $, $$, escapeHtml, toast } from "../../core/dom.js";
import { signalBars } from "../../ui/components.js";
import { getWifiProfiles, connectWifi, disconnectWifi, setWifiRadio, setWifiPrimary,
  updateWifiPriority, getAutoReconnectPolicy } from "../../core/opsApi.js";

export const id = "wifi";
export const label = "Wi-Fi / 離線重連";

let data = null;

export function render(container, ctx) {
  container.innerHTML = `<div class="card-state is-loading">載入 Wi-Fi…</div>`;
  load(container, ctx);
}

async function load(container, ctx, rescan = false) {
  try { data = await getWifiProfiles(rescan); }
  catch (e) { container.innerHTML = `<div class="card-state is-error">${escapeHtml(e.message)}</div>`; return; }

  if (!data.available) {
    container.innerHTML = `<div class="card-state is-empty">未偵測到無線網卡</div>`;
    return;
  }
  const policy = getAutoReconnectPolicy();
  const ifaces = data.interfaces || [];
  const active = ifaces.find((d) => d.connected);

  container.innerHTML = `
    <div class="ops-grid wifi-grid">
      <div class="ops-card wifi-current ${active ? "green" : "gray"}">
        <div class="ops-card-head"><span class="ops-card-title">目前連線</span>
          <label class="net-show-virtual"><input type="checkbox" id="wifiRadio" ${data.radio_on ? "checked" : ""}/> 無線電</label>
        </div>
        ${active ? `
          <div class="wifi-cur-ssid">${escapeHtml(active.active_ssid || "—")}</div>
          <div class="wifi-cur-meta mono">${signalBars(active.signal || 0)} ${active.signal || 0}% · ${escapeHtml(active.device)}</div>
        ` : `<p class="hint muted">未連線</p>`}
        <div class="ops-form-actions"><button type="button" class="btn btn-ghost btn-sm" id="wifiScan">掃描網路</button></div>
      </div>

      <div class="ops-card wifi-policy">
        <div class="ops-card-head"><span class="ops-card-title">自動重連策略</span><span class="mock-tag">本機設定</span></div>
        <div class="ops-form">
          <label class="ops-field">重試間隔（秒）<input id="arInterval" type="number" min="5" value="${policy.retry_interval_sec}"/></label>
          <label class="ops-field">最大重試次數（0=無限）<input id="arMax" type="number" min="0" value="${policy.max_retry}"/></label>
          <label class="ops-field ops-field-toggle"><input id="arFallback" type="checkbox" ${policy.fallback_next ? "checked" : ""}/> 失敗時切換下一個網路</label>
          <label class="ops-field ops-field-toggle"><input id="arKeep" type="checkbox" ${policy.keep_last ? "checked" : ""}/> 保留最後成功的網路</label>
        </div>
        <div class="ops-form-actions"><button type="button" class="btn btn-ghost btn-sm" id="wifiFailover">測試 Failover</button></div>
      </div>

      <div class="ops-card wifi-nets">
        <div class="ops-card-head"><span class="ops-card-title">可用網路</span></div>
        <div id="wifiNetList" class="wifi-net-list"></div>
      </div>

      <div class="ops-card wifi-priority">
        <div class="ops-card-head"><span class="ops-card-title">離線重連優先順序</span></div>
        <p class="ops-helper">沒網路時依序自動重連，已釘選的網路不會被清除。</p>
        <div id="wifiPinned" class="wifi-fb-list"></div>
        <p class="ops-helper" id="wifiKnownLabel">其他已記住的網路</p>
        <div id="wifiKnown" class="wifi-fb-list"></div>
      </div>
    </div>`;

  $("#wifiRadio", container).addEventListener("change", async (e) => {
    try { await setWifiRadio(e.target.checked); await load(container, ctx); } catch (err) { toast(err.message, false); }
  });
  $("#wifiScan", container).addEventListener("click", () => { toast("掃描中…"); load(container, ctx, true); });
  $("#wifiFailover", container).addEventListener("click", () => toast("已模擬 failover：將依優先順序嘗試下一個網路"));
  wirePolicy(container, ctx);
  renderNetworks(container, ctx, ifaces);
  renderPriority(container, ctx);
}

function wirePolicy(container, ctx) {
  const base = getAutoReconnectPolicy();
  const stage = () => {
    const patch = {
      retry_interval_sec: parseInt($("#arInterval", container).value, 10) || 30,
      max_retry: parseInt($("#arMax", container).value, 10) || 0,
      fallback_next: $("#arFallback", container).checked,
      keep_last: $("#arKeep", container).checked,
    };
    const changed = JSON.stringify(patch) !== JSON.stringify({
      retry_interval_sec: base.retry_interval_sec, max_retry: base.max_retry,
      fallback_next: base.fallback_next, keep_last: base.keep_last,
    });
    if (!changed) ctx.unstage("wifi.policy");
    else ctx.stage("wifi.policy", { value: `間隔 ${patch.retry_interval_sec}s`, label: "自動重連策略", tab: "wifi", risk: "low", services: [], apply: "autoreconnect", patch });
  };
  ["arInterval", "arMax", "arFallback", "arKeep"].forEach((idn) =>
    $(`#${idn}`, container).addEventListener("change", stage));
}

function renderNetworks(container, ctx, ifaces) {
  const host = $("#wifiNetList", container);
  if (!host) return;
  const multi = ifaces.length > 1;
  host.innerHTML = "";
  ifaces.forEach((dev) => {
    const wrap = document.createElement("div");
    wrap.className = "wifi-iface";
    const conn = dev.connected ? `已連線：${escapeHtml(dev.active_ssid || "—")}` : "未連線";
    const primary = multi ? `<label class="wifi-primary-opt${dev.connected ? "" : " disabled"}">
      <input type="radio" name="wifiPrimary" value="${escapeHtml(dev.device)}" ${dev.is_primary ? "checked" : ""} ${dev.connected ? "" : "disabled"}/> 主要上行</label>` : "";
    wrap.innerHTML = `<div class="wifi-iface-head"><span class="net-iface-name mono">${escapeHtml(dev.device)}</span>
      <span class="wifi-iface-conn mono muted">${conn}</span>${primary}</div>
      <div class="wifi-net-rows"></div>`;
    const rows = wrap.querySelector(".wifi-net-rows");
    const nets = dev.networks || [];
    if (!nets.length) rows.innerHTML = `<p class="hint muted">無可用網路（開啟無線電後掃描）</p>`;
    nets.forEach((nw) => {
      const row = document.createElement("div");
      row.className = "wifi-row";
      const lock = nw.open ? "" : "🔒";
      const active = nw.in_use || nw.ssid === dev.active_ssid;
      row.innerHTML = `<span class="net-iface-name">${lock} ${escapeHtml(nw.ssid)}${active ? ' <span class="net-kind-chip">已連線</span>' : ""}</span>
        <span class="net-iface-ip mono">${escapeHtml(nw.band)} · ${escapeHtml(nw.security)}</span>
        <span class="net-iface-state mono">${signalBars(nw.signal)} ${nw.signal}%</span>`;
      row.addEventListener("click", () => doConnect(nw, dev.device, container, ctx));
      rows.appendChild(row);
    });
    wrap.querySelector('input[name="wifiPrimary"]')?.addEventListener("change", async (e) => {
      if (!e.target.checked) return;
      try { await setWifiPrimary(dev.device); toast("已設定主要上行"); await load(container, ctx); }
      catch (err) { toast(err.message, false); }
    });
    host.appendChild(wrap);
  });
}

async function doConnect(nw, iface, container, ctx) {
  if (nw.in_use) {
    if (!window.confirm(`中斷與 ${nw.ssid} 的連線？`)) return;
    try { await disconnectWifi(iface); toast("已斷線"); await load(container, ctx); } catch (e) { toast(e.message, false); }
    return;
  }
  let password = null;
  if (!nw.open) { password = window.prompt(`輸入 ${nw.ssid} 的 Wi-Fi 密碼：`); if (password === null) return; }
  toast(`連線中：${nw.ssid}…`);
  try { const r = await connectWifi(nw.ssid, password, iface); toast(r.message || `已連線到 ${nw.ssid}`); await load(container, ctx); }
  catch (e) { toast(e.message, false); }
}

function renderPriority(container, ctx) {
  const pinnedEl = $("#wifiPinned", container), knownEl = $("#wifiKnown", container), knownLabel = $("#wifiKnownLabel", container);
  const pinned = data.pinned || [], known = data.known || [];
  const order = pinned.map((p) => p.ssid);
  const unpinned = known.filter((k) => !order.includes(k.ssid));

  pinnedEl.innerHTML = pinned.length ? pinned.map((p, i) => `
    <div class="wifi-fb-row">
      <span class="wifi-fb-ord mono">${i + 1}</span>
      <span class="wifi-fb-ssid">${escapeHtml(p.ssid)}</span>
      <span class="wifi-fb-actions">
        <button type="button" class="btn btn-ghost btn-sm" data-mv="up" data-ssid="${escapeHtml(p.ssid)}" ${i === 0 ? "disabled" : ""}>▲</button>
        <button type="button" class="btn btn-ghost btn-sm" data-mv="down" data-ssid="${escapeHtml(p.ssid)}" ${i === pinned.length - 1 ? "disabled" : ""}>▼</button>
        <button type="button" class="btn btn-ghost btn-sm" data-mv="pin-top" data-ssid="${escapeHtml(p.ssid)}" title="置頂">⤒</button>
        <button type="button" class="btn btn-ghost btn-sm" data-mv="unpin" data-ssid="${escapeHtml(p.ssid)}" title="移除">✕</button>
      </span>
    </div>`).join("") : `<p class="hint muted">尚未釘選備援網路</p>`;

  knownEl.innerHTML = unpinned.length ? unpinned.map((k) => `
    <div class="wifi-fb-row wifi-fb-other">
      <span class="wifi-fb-ssid muted">${escapeHtml(k.ssid)}</span>
      <button type="button" class="btn btn-ghost btn-sm" data-mv="pin" data-ssid="${escapeHtml(k.ssid)}">📌 釘選</button>
    </div>`).join("") : `<p class="hint muted">無其他已記住的網路</p>`;
  knownLabel.classList.toggle("hidden", !unpinned.length);

  $$("button[data-mv]", container).forEach((btn) => btn.addEventListener("click", async () => {
    const ssid = btn.dataset.ssid, mv = btn.dataset.mv;
    const next = order.slice();
    const idx = next.indexOf(ssid);
    if (mv === "pin") { if (idx === -1) next.push(ssid); }
    else if (mv === "unpin") { if (idx !== -1) next.splice(idx, 1); }
    else if (mv === "pin-top") { if (idx !== -1) { next.splice(idx, 1); } next.unshift(ssid); }
    else if (mv === "up" && idx > 0) [next[idx - 1], next[idx]] = [next[idx], next[idx - 1]];
    else if (mv === "down" && idx !== -1 && idx < next.length - 1) [next[idx + 1], next[idx]] = [next[idx], next[idx + 1]];
    try { await updateWifiPriority(next); toast("已更新離線重連順序"); await load(container, ctx); }
    catch (e) { toast(e.message, false); await load(container, ctx); }
  }));
}
