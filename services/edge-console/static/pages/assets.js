// 資產與協定 — Protocol Coverage, OT Asset Inventory, EdgeX device management.
import { $, $$, toast, escapeHtml } from "../core/dom.js";
import { api } from "../core/api.js";
import { fmtTime } from "../core/format.js";
import { dot, badge, stateBlock, copyField, openDrawer } from "../ui/components.js";
import { getProtocolCoverage, getAssets } from "../core/dataSource.js";

const ID_SOURCE = {
  manual: { label: "手動", cls: "src-manual" },
  probe: { label: "探測", cls: "src-probe" },
  oui: { label: "OUI", cls: "src-oui" },
  mock: { label: "示意", cls: "src-mock" },
};
let _probeEnabled = false;

export const meta = { title: "資產與協定", sub: "OT Asset Inventory · Protocol Coverage" };

const COVERAGE_STATE = { enabled: "綠 啟用", disabled: "停用", missing: "未安裝", };
const RISK_LABEL = { red: "高", yellow: "中", green: "低" };

const WIZARD_DEFAULTS = {
  modbus: { host: "modbus-simulator", port: 1502 },
  mqtt: { host: "local-mqtt", port: 1883 },
  opcua: { host: "192.168.1.50", port: 4840 },
  s7: { host: "192.168.1.60", port: 102 },
};
let selectedDeviceName = null;

export function render(root) {
  root.innerHTML = `
    <section class="page">
      <p class="hint">IEC 61850 GOOSE · Modbus TCP · OPC UA · Siemens S7 · MQTT。GOOSE/MMS 由 Packet Sensor 被動擷取，其餘由 EdgeX 管理。</p>

      <div class="card-ot" id="coverageCard">
        <div class="title">Protocol Coverage</div>
        <div id="coverageBody">${stateBlock("loading")}</div>
      </div>

      <div class="card-ot" id="inventoryCard" style="margin-top:1rem">
        <div class="title">OT Asset Inventory <span id="inventorySummary" class="count-badge"></span></div>
        <div class="table-wrap">
          <table class="asset-table">
            <thead><tr>
              <th>資產</th><th>IP</th><th>MAC</th><th>Vendor</th><th>Model</th><th>Firmware</th><th>來源</th>
              <th>Protocol</th><th>Purdue</th><th>Zone</th><th>Last Seen</th><th>Risk</th><th>識別</th>
            </tr></thead>
            <tbody id="assetRows"><tr><td colspan="13">${stateBlock("loading")}</td></tr></tbody>
          </table>
        </div>
      </div>

      <div id="phase2Banner" class="card-ot phase2-banner hidden" style="margin-top:1rem">
        <div class="title">Phase 2 · OPC UA &amp; S7</div>
        <div class="sub" id="phase2StatusText">檢查中…</div>
        <div class="actions" style="margin-top:0.65rem">
          <button type="button" class="btn btn-primary btn-sm" id="enablePhase2Btn">啟用 Phase 2 服務</button>
        </div>
      </div>

      <div class="devices-toolbar" style="margin-top:1rem">
        <span id="devicesSummary" class="mono">載入中…</span>
        <div class="devices-toolbar-actions">
          <button type="button" class="btn btn-primary" id="toggleWizardBtn">＋ 新增設備</button>
          <button type="button" class="btn btn-secondary btn-sm" id="diagSuiteBtn">連線診斷</button>
          <button type="button" class="btn btn-ghost btn-sm" id="refreshDevicesBtn">重新整理</button>
        </div>
      </div>

      <div id="deviceWizard" class="card-ot device-wizard hidden" style="margin-top:0.75rem">
        <div class="title">新增 / 更新設備</div>
        <div class="grid-2">
          <label>協定
            <select id="dwProtocol">
              <option value="modbus">Modbus TCP</option>
              <option value="mqtt">MQTT</option>
              <option value="opcua">OPC UA</option>
              <option value="s7">S7 / ISO-on-TCP</option>
            </select>
          </label>
          <label>設備名稱<input id="dwName" placeholder="plc-opcua-01" class="mono" /></label>
          <label>Host / 位址<input id="dwHost" placeholder="192.168.1.50" class="mono" /></label>
          <label>Port<input id="dwPort" type="number" placeholder="4840" class="mono" /></label>
          <label id="dwRackLabel" class="hidden">Rack<input id="dwRack" type="number" value="0" class="mono" /></label>
          <label id="dwSlotLabel" class="hidden">Slot<input id="dwSlot" type="number" value="1" class="mono" /></label>
          <label id="dwEndpointLabel" class="hidden col-span-2">OPC UA Endpoint（可選）<input id="dwEndpoint" placeholder="opc.tcp://192.168.1.50:4840" class="mono" /></label>
          <label>輪詢間隔<input id="dwInterval" value="10s" class="mono" /></label>
        </div>
        <div class="actions">
          <button type="button" class="btn btn-ghost btn-sm" id="dwProbeBtn">測試連線</button>
          <button type="button" class="btn btn-primary btn-sm" id="dwSaveBtn">儲存並重載驅動</button>
        </div>
        <pre id="dwResult" class="mono muted" style="margin:0.5rem 0 0;font-size:0.8rem;white-space:pre-wrap"></pre>
      </div>

      <div id="diagResults" class="card-ot hidden" style="margin-top:0.75rem">
        <div class="title">連線診斷</div>
        <div id="diagResultsBody" class="traffic-list muted"></div>
      </div>

      <div class="card-ot" style="margin-top:0.75rem">
        <div class="title">EdgeX 已納管設備</div>
        <div class="table-wrap" style="margin-top:0.5rem">
          <table>
            <thead><tr><th>設備</th><th>協定</th><th>Profile</th><th>端點</th><th>狀態</th><th>最後遙測</th></tr></thead>
            <tbody id="devicesRows"></tbody>
          </table>
        </div>
      </div>

      <div id="deviceDetail" class="card-ot device-detail hidden" style="margin-top:0.75rem">
        <div class="title">設備詳情 · <span id="deviceDetailName" class="mono"></span></div>
        <div id="deviceReadings" class="traffic-list muted">選擇設備以載入點位</div>
        <div class="actions"><button type="button" class="btn btn-ghost btn-sm" id="deleteDeviceBtn">刪除 config 設備</button></div>
      </div>
    </section>`;

  wireDevices();
  loadCoverage().catch((e) => { $("#coverageBody").innerHTML = stateBlock("error", e.message); });
  loadInventory().catch((e) => { $("#assetRows").innerHTML = `<tr><td colspan="13">${stateBlock("error", e.message)}</td></tr>`; });
  loadDevicesPage().catch((e) => toast(e.message, false));

  if (assetsAddRequested) { assetsAddRequested = false; openDeviceWizard($("#dwProtocol")?.value); }
}

export function leave() {}

// header "+新增設備" may fire before render; remember it.
let assetsAddRequested = false;
window.addEventListener("edge:assets:add-device", () => {
  const w = document.querySelector("#deviceWizard");
  if (w) openDeviceWizard(document.querySelector("#dwProtocol")?.value);
  else assetsAddRequested = true;
});

async function loadCoverage() {
  const { protocols } = await getProtocolCoverage();
  $("#coverageBody").innerHTML = `<div class="coverage-grid">${protocols.map((p) => `
    <div class="coverage-item ${p.state}">
      <div class="cov-head">${dot(p.state)}<span class="cov-label">${escapeHtml(p.label)}</span></div>
      <div class="cov-status">${escapeHtml(statusText(p))}</div>
      <div class="cov-traffic ${p.traffic ? "on" : ""}">${p.traffic ? "● traffic detected" : "○ no traffic"}</div>
    </div>`).join("")}</div>`;
}

function statusText(p) {
  const m = { enabled: "Enabled", disabled: "Disabled", missing: "Missing" };
  return m[p.status] || p.status;
}

let _assetsCache = [];

async function loadInventory() {
  const { assets, summary, active_probe_enabled } = await getAssets();
  _assetsCache = assets;
  _probeEnabled = active_probe_enabled === true;
  $("#inventorySummary").textContent = `${summary.total} 資產 · EdgeX ${summary.edgex} · Mirror ${summary.mirror_only}`;
  const rows = $("#assetRows");
  if (!assets.length) { rows.innerHTML = `<tr><td colspan="13">${stateBlock("empty", "尚無資產（請確認 mirror 有流量）")}</td></tr>`; return; }
  rows.innerHTML = assets.map((a) => {
    const src = ID_SOURCE[a.identity_source] || ID_SOURCE.mock;
    return `
    <tr>
      <td>${escapeHtml(a.label || a.ip)}</td>
      <td>${copyField(a.ip, { max: 18 })}</td>
      <td>${copyField(a.mac || "—", { max: 18 })}</td>
      <td>${escapeHtml(a.vendor)}</td>
      <td class="mono">${escapeHtml(a.model)}</td>
      <td class="mono">${escapeHtml(a.firmware)}</td>
      <td><span class="src-tag ${src.cls}">${src.label}</span></td>
      <td>${escapeHtml(a.protocol)}</td>
      <td><span class="purdue-badge">${escapeHtml(a.purdue)}</span></td>
      <td>${escapeHtml(a.zone)}</td>
      <td class="mono">${a.last_seen ? fmtTime(a.last_seen) : "—"}</td>
      <td>${riskBadge(a.risk)}</td>
      <td class="asset-id-actions">
        <button type="button" class="btn btn-ghost btn-xs" data-edit-ip="${escapeHtml(a.ip)}">編輯</button>
        ${_probeEnabled ? `<button type="button" class="btn btn-ghost btn-xs" data-probe-ip="${escapeHtml(a.ip)}">探測</button>` : ""}
      </td>
    </tr>`;
  }).join("");
  $$("[data-edit-ip]").forEach((b) => b.addEventListener("click", () => openIdentityEditor(b.dataset.editIp)));
  $$("[data-probe-ip]").forEach((b) => b.addEventListener("click", () => probeAsset(b.dataset.probeIp, b)));
}

function openIdentityEditor(ip) {
  const a = _assetsCache.find((x) => x.ip === ip) || { ip };
  openDrawer(`編輯資產識別 · ${ip}`, `
    <div class="id-editor">
      <label>Vendor<input id="idVendor" class="mono" value="${escapeHtml(a.identity_source === "manual" ? a.vendor : "")}" placeholder="${escapeHtml(a.vendor || "")}"></label>
      <label>Model<input id="idModel" class="mono" value="${escapeHtml(a.identity_source === "manual" ? a.model : "")}" placeholder="${escapeHtml(a.model || "")}"></label>
      <label>Firmware<input id="idFirmware" class="mono" value="${escapeHtml(a.identity_source === "manual" ? a.firmware : "")}" placeholder="${escapeHtml(a.firmware || "")}"></label>
      <p class="hint">留空表示沿用自動推定（OUI/探測/示意）。手動輸入會優先於其他來源。</p>
      <div class="actions"><button type="button" class="btn btn-primary btn-sm" id="idSave">儲存</button></div>
    </div>`);
  $("#idSave").addEventListener("click", async () => {
    try {
      await api("/api/assets/identity", { method: "PUT", body: JSON.stringify({
        ip, vendor: $("#idVendor").value, model: $("#idModel").value, firmware: $("#idFirmware").value,
      }) });
      toast("已儲存資產識別", true);
      document.querySelector("#appDrawer")?.classList.remove("open");
      await loadInventory();
    } catch (e) { toast(e.message, false); }
  });
}

async function probeAsset(ip, btn) {
  btn.disabled = true; const orig = btn.textContent; btn.textContent = "探測中…";
  try {
    const r = await api("/api/assets/probe", { method: "POST", body: JSON.stringify({ ip }) });
    const id = r.probe?.identity || {};
    const ports = (r.probe?.open_ports || []).map((p) => p.port).join(",");
    toast(r.probe?.reachable ? `探測完成：開放埠 ${ports || "—"}${id.vendor ? ` · ${id.vendor}` : ""}` : "探測完成：無回應埠", true);
    await loadInventory();
  } catch (e) { toast(e.message, false); btn.disabled = false; btn.textContent = orig; }
}

function riskBadge(risk) {
  const lvl = risk?.level || "green";
  return `<span class="risk-badge ${lvl}">${dot(lvl)}${risk?.score ?? "—"} · ${RISK_LABEL[lvl]}</span>`;
}

// ---- EdgeX device management (ported) --------------------------------------
function wireDevices() {
  $("#toggleWizardBtn").addEventListener("click", () => {
    const w = $("#deviceWizard");
    if (w.classList.contains("hidden")) openDeviceWizard($("#dwProtocol")?.value);
    else w.classList.add("hidden");
  });
  $("#refreshDevicesBtn").addEventListener("click", () => loadDevicesPage().catch((e) => toast(e.message, false)));
  $("#diagSuiteBtn").addEventListener("click", () => runDiagSuite().catch((e) => toast(e.message, false)));
  $("#dwSaveBtn").addEventListener("click", () => saveDeviceWizard().catch((e) => toast(e.message, false)));
  $("#dwProbeBtn").addEventListener("click", () => probeDeviceWizard().catch((e) => toast(e.message, false)));
  $("#enablePhase2Btn").addEventListener("click", async () => {
    try { const r = await api("/api/edgex/phase2/enable", { method: "POST" }); toast(r.message || "Phase 2 已啟用"); await loadDevicesPage(); }
    catch (e) { toast(e.message, false); }
  });
  $("#deleteDeviceBtn").addEventListener("click", async () => {
    if (!selectedDeviceName || !confirm(`刪除 config 設備 ${selectedDeviceName}？`)) return;
    try {
      await api(`/api/edgex/config/devices/${encodeURIComponent(selectedDeviceName)}`, { method: "DELETE" });
      toast("已刪除"); selectedDeviceName = null; $("#deviceDetail").classList.add("hidden"); await loadDevicesPage();
    } catch (e) { toast(e.message, false); }
  });
  $("#dwProtocol").addEventListener("change", () => {
    delete $("#dwHost")?.dataset.touched; delete $("#dwPort")?.dataset.touched; syncWizardFields();
  });
  $("#dwHost").addEventListener("input", () => { $("#dwHost").dataset.touched = "1"; });
  $("#dwPort").addEventListener("input", () => { $("#dwPort").dataset.touched = "1"; });
}

function syncWizardFields() {
  const proto = $("#dwProtocol")?.value || "modbus";
  const defs = WIZARD_DEFAULTS[proto] || {};
  if ($("#dwHost") && !$("#dwHost").dataset.touched) $("#dwHost").value = defs.host || "";
  if ($("#dwPort") && !$("#dwPort").dataset.touched) $("#dwPort").value = defs.port ?? "";
  $("#dwRackLabel")?.classList.toggle("hidden", proto !== "s7");
  $("#dwSlotLabel")?.classList.toggle("hidden", proto !== "s7");
  $("#dwEndpointLabel")?.classList.toggle("hidden", proto !== "opcua");
}

function openDeviceWizard(protocol) {
  const w = $("#deviceWizard");
  if (w) w.classList.remove("hidden");
  if ($("#dwProtocol")) {
    $("#dwProtocol").value = protocol || "modbus";
    delete $("#dwHost")?.dataset.touched; delete $("#dwPort")?.dataset.touched;
    syncWizardFields();
  }
  w?.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

async function saveDeviceWizard() {
  const proto = $("#dwProtocol").value;
  const body = {
    protocol: proto, name: $("#dwName").value.trim(), host: $("#dwHost").value.trim(),
    port: parseInt($("#dwPort").value || "0", 10), interval: $("#dwInterval").value.trim() || "10s",
  };
  if (proto === "s7") { body.rack = parseInt($("#dwRack").value || "0", 10); body.slot = parseInt($("#dwSlot").value || "1", 10); }
  if (proto === "opcua" && $("#dwEndpoint").value.trim()) body.endpoint = $("#dwEndpoint").value.trim();
  const r = await api("/api/edgex/config/devices", { method: "POST", body: JSON.stringify(body) });
  $("#dwResult").textContent = JSON.stringify(r, null, 2);
  toast(`設備 ${r.name} 已寫入 ${r.file}`);
  await loadDevicesPage();
}

async function probeDeviceWizard() {
  const r = await api("/api/edgex/diagnostics/connect", {
    method: "POST",
    body: JSON.stringify({ protocol: $("#dwProtocol").value, host: $("#dwHost").value.trim(), port: parseInt($("#dwPort").value || "0", 10) }),
  });
  $("#dwResult").textContent = JSON.stringify(r, null, 2);
  toast(r.ok ? "連線成功" : r.error || "連線失敗", r.ok);
}

async function runDiagSuite() {
  const box = $("#diagResults"); const body = $("#diagResultsBody");
  box.classList.remove("hidden"); body.innerHTML = "診斷中…";
  const r = await api("/api/edgex/diagnostics/suite");
  const lines = (r.checks || []).map((c) =>
    `<div class="row"><span>${escapeHtml(c.protocol)} ${escapeHtml(c.host || "")}:${c.port || ""}</span><span class="${c.ok ? "ok" : "bad"}">${c.ok ? "OK" : escapeHtml(c.error || "fail")}</span></div>`);
  body.innerHTML = lines.join("") + `<div class="sub" style="margin-top:0.5rem">${r.phase2?.enabled ? "Phase2 ON" : "Phase2 OFF"}</div>`;
  body.classList.remove("muted");
}

async function loadPhase2Banner() {
  const banner = $("#phase2Banner"); const text = $("#phase2StatusText");
  try {
    const st = await api("/api/edgex/phase2/status");
    banner.classList.remove("hidden");
    const lines = (st.services || []).map((s) => `${s.container}: ${s.status}`).join(" · ");
    text.textContent = st.enabled ? `已啟用 · ${lines}` : `未啟用 · ${st.compose_hint || ""}`;
  } catch { banner.classList.add("hidden"); }
}

function renderDevicesTable(devices) {
  const rows = $("#devicesRows"); rows.innerHTML = "";
  if (!devices.length) { rows.innerHTML = `<tr><td colspan="6" class="hint">尚無設備</td></tr>`; return; }
  for (const d of devices) {
    const up = String(d.operatingState || "").toUpperCase() === "UP";
    const tr = document.createElement("tr");
    tr.className = "device-row"; tr.dataset.device = d.name;
    tr.innerHTML = `<td class="mono">${escapeHtml(d.name)}</td><td>${escapeHtml(d.protocol || "—")}</td>
      <td class="mono">${escapeHtml(d.profileName || "—")}</td><td class="mono">${escapeHtml(d.endpoint || "—")}</td>
      <td>${dot(up ? "green" : "red")}${escapeHtml(d.operatingState || "—")}</td><td class="mono">${escapeHtml(d.last_event_at || "—")}</td>`;
    tr.addEventListener("click", () => selectDevice(d.name, tr));
    rows.appendChild(tr);
  }
}

async function selectDevice(name, rowEl) {
  selectedDeviceName = name;
  $$("tr.device-row").forEach((r) => r.classList.toggle("selected", r === rowEl));
  $("#deviceDetail").classList.remove("hidden");
  $("#deviceDetailName").textContent = name;
  const readingsEl = $("#deviceReadings");
  readingsEl.innerHTML = '<span class="muted">載入點位中…</span>';
  try {
    const data = await api(`/api/edgex/devices/${encodeURIComponent(name)}/readings?limit=15`);
    if (!data.ok) { readingsEl.innerHTML = `<span class="muted">${escapeHtml(data.error || "無法載入")}</span>`; return; }
    const readings = data.readings || [];
    if (!readings.length) { readingsEl.innerHTML = '<span class="muted">尚無 readings</span>'; return; }
    readingsEl.classList.remove("muted");
    readingsEl.innerHTML = readings.slice(0, 20).map((r) =>
      `<div class="reading-row"><span class="mono">${escapeHtml(r.resourceName)}</span><span>${escapeHtml(String(r.value))} <span class="muted">${escapeHtml(r.valueType || "")}</span></span></div>`).join("");
  } catch (e) { readingsEl.innerHTML = `<span class="muted">${escapeHtml(e.message)}</span>`; }
}

async function loadDevicesPage() {
  const [dev] = await Promise.all([api("/api/edgex/devices")]);
  await loadPhase2Banner();
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
