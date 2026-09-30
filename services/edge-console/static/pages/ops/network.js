// 網路介面 Tab — interface cards, diagnose, high-risk rollback.
import { $, $$, escapeHtml, toast } from "../../core/dom.js";
import { fmtTime } from "../../core/format.js";
import { getNetworkInterfaces, setInterfaceState, diagnoseNetwork } from "../../core/opsApi.js";

export const id = "network";
export const label = "網路介面";

let cache = [];
let netAdmin = false;
let showVirtual = false;

export function render(container, ctx) {
  container.innerHTML = `
    <div class="net-toolbar">
      <span id="netSummary" class="mono muted">載入中…</span>
      <label class="net-show-virtual"><input type="checkbox" id="netShowVirtual" ${showVirtual ? "checked" : ""}/> 顯示虛擬介面</label>
      <button type="button" class="btn btn-ghost btn-sm" id="netRefresh">重新整理</button>
      <button type="button" class="btn btn-secondary btn-sm" id="netDiagnose">網路診斷</button>
    </div>
    <div id="netDiagResult" class="net-diag hidden"></div>
    <div id="netCards" class="ops-grid net-card-grid"></div>
    <p id="netErr" class="hint muted hidden"></p>`;

  $("#netShowVirtual", container).addEventListener("change", (e) => { showVirtual = e.target.checked; renderCards(container, ctx); });
  $("#netRefresh", container).addEventListener("click", () => load(container, ctx));
  $("#netDiagnose", container).addEventListener("click", () => runDiagnose(container));
  load(container, ctx);
}

async function load(container, ctx) {
  const errEl = $("#netErr", container), sum = $("#netSummary", container);
  try {
    const data = await getNetworkInterfaces();
    cache = data.interfaces || [];
    netAdmin = data.net_admin_enabled === true;
    if (!data.ok) {
      errEl.textContent = data.error || "無法取得網卡資訊"; errEl.classList.remove("hidden");
      sum.textContent = "—";
    } else {
      errEl.classList.add("hidden");
      const s = data.summary || {};
      const src = data.source === "console-local" ? "（來源：Console 本機）" : "";
      sum.textContent = `實體介面 ${s.total ?? 0} · 🟢 ${s.up_ip ?? 0} · 🟠 ${s.up_no_ip ?? 0} · 🔴 ${s.down ?? 0} ${src}`;
    }
    renderCards(container, ctx);
  } catch (e) {
    errEl.textContent = e.message; errEl.classList.remove("hidden");
  }
}

function roleBadge(iface, captureIface) {
  if (captureIface && iface.name === captureIface) return { label: "封包監聽", cls: "role-capture" };
  if (iface.default_route) return { label: "上行網路", cls: "role-uplink" };
  if (iface.ipv4) return { label: "管理網路", cls: "role-mgmt" };
  return { label: "未指定", cls: "role-none" };
}

function renderCards(container, ctx) {
  const host = $("#netCards", container);
  if (!host) return;
  const captureIface = ctx.system?.capture?.interface || "";
  const items = cache.filter((i) => showVirtual || !i.virtual);
  if (!items.length) { host.innerHTML = `<p class="hint muted">無可顯示的網路介面</p>`; return; }

  host.innerHTML = items.map((iface) => {
    const role = roleBadge(iface, captureIface);
    const isMgmt = role.cls === "role-mgmt" || iface.default_route;
    const ipv6 = (iface.ipv6 || [])[0] || "—";
    const kindLabel = iface.kind === "wireless" ? "無線" : "有線";
    const speed = iface.speed_mbps ? `${iface.speed_mbps} Mbps` : "—";
    const canDown = netAdmin && iface.can_toggle && iface.link_up;
    const canUp = netAdmin && iface.can_toggle && !iface.link_up;
    return `
      <div class="ops-card net-card ${iface.dot}">
        <div class="ops-card-head">
          <span class="status-dot ${iface.dot}"></span>
          <span class="net-card-name mono">${escapeHtml(iface.name)}</span>
          <span class="role-badge ${role.cls}">${role.label}</span>
          ${iface.virtual ? `<span class="net-kind-chip virtual">虛擬</span>` : ""}
        </div>
        <div class="net-card-kv"><span>狀態</span><span>${escapeHtml(iface.state_label || "—")} · ${kindLabel}</span></div>
        <div class="net-card-kv"><span>operstate / carrier</span><span class="mono">${escapeHtml(iface.operstate || "—")} / ${iface.carrier ?? "—"}</span></div>
        <div class="net-card-kv"><span>MAC</span><span class="mono">${escapeHtml(iface.mac || "—")}</span></div>
        <div class="net-card-kv"><span>IPv4</span><span class="mono">${escapeHtml(iface.ipv4 || "—")}</span></div>
        <div class="net-card-kv"><span>IPv6</span><span class="mono">${escapeHtml(ipv6)}</span></div>
        <div class="net-card-kv"><span>速率 / MTU</span><span class="mono">${speed} / ${iface.mtu || "—"}</span></div>
        <div class="net-card-kv"><span>預設路由</span><span>${iface.default_route ? "✔ 使用此介面" : "—"}</span></div>
        ${isMgmt ? `<div class="net-risk-warn">⚠ 管理連線，停用可能造成失聯</div>` : ""}
        ${netAdmin ? `<div class="ops-card-actions">
          <button type="button" class="btn btn-ghost btn-sm" data-net-up="${escapeHtml(iface.name)}" ${canUp ? "" : "disabled"}>啟用</button>
          <button type="button" class="btn btn-danger btn-sm" data-net-down="${escapeHtml(iface.name)}" ${canDown ? "" : "disabled"}>停用</button>
        </div>` : `<div class="ops-card-actions"><span class="hint muted">${escapeHtml(iface.toggle_block_reason || "唯讀（未啟用 NET_ADMIN）")}</span></div>`}
      </div>`;
  }).join("");

  $$("[data-net-up]", host).forEach((b) => b.addEventListener("click", () => enable(b.dataset.netUp, container, ctx)));
  $$("[data-net-down]", host).forEach((b) => b.addEventListener("click", () => disable(b.dataset.netDown, container, ctx)));
}

async function enable(name, container, ctx) {
  try { const r = await setInterfaceState(name, true); toast(r.message || `${name} 已啟用`); await load(container, ctx); }
  catch (e) { toast(e.message, false); }
}

async function disable(name, container, ctx) {
  const iface = cache.find((i) => i.name === name);
  const highRisk = iface && (iface.default_route || (iface.ipv4 && !iface.virtual));
  if (highRisk) {
    await ctx.rollback({
      title: `停用管理介面 ${name}`,
      risk: "high",
      detailHtml: `<p>介面 <span class="mono">${escapeHtml(name)}</span> ${iface.default_route ? "持有預設路由" : "具有 IP 位址"}，停用可能造成 Edge 失聯。</p>`,
      applyFn: async () => { await setInterfaceState(name, false); },
      revertFn: async () => { await setInterfaceState(name, true); },
      seconds: 60,
    });
    await load(container, ctx);
    return;
  }
  const ok = await ctx.confirm({ title: `停用介面 ${name}`, risk: "medium", bodyHtml: `<p>確定要停用 ${escapeHtml(name)}？</p>`, confirmLabel: "停用", danger: true });
  if (!ok) return;
  try { const r = await setInterfaceState(name, false); toast(r.message || `${name} 已停用`); await load(container, ctx); }
  catch (e) { toast(e.message, false); }
}

async function runDiagnose(container) {
  const box = $("#netDiagResult", container);
  box.classList.remove("hidden");
  box.innerHTML = `<p class="hint">診斷中…</p>`;
  const r = await diagnoseNetwork();
  box.innerHTML = `
    <div class="net-diag-grid">
      ${r.checks.map((c) => `
        <div class="net-diag-row">
          <span class="status-dot ${c.ok ? "green" : "red"}"></span>
          <span class="net-diag-label">${escapeHtml(c.label)}${c.mock ? ' <span class="mock-tag">估算</span>' : ""}</span>
          <span class="net-diag-detail mono muted">${escapeHtml(c.detail)}</span>
        </div>`).join("")}
    </div>
    <div class="net-diag-foot mono muted">診斷時間：${fmtTime(r.at)}</div>`;
}
