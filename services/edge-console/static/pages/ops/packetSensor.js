// Packet Sensor Tab — capture interface + BPF builder + test capture.
import { $, $$, escapeHtml, toast } from "../../core/dom.js";
import { fmtTime } from "../../core/format.js";
import { getPacketSensorSettings, restartPacketSensor, testCapture,
  validateBpf, buildBpfFromPresets, PROTOCOL_PRESETS } from "../../core/opsApi.js";

export const id = "packet";
export const label = "Packet Sensor";

let base = null;

export function render(container, ctx) {
  container.innerHTML = `<div class="card-state is-loading">載入擷取設定…</div>`;
  load(container, ctx);
}

async function load(container, ctx) {
  try { base = await getPacketSensorSettings(); }
  catch (e) { container.innerHTML = `<div class="card-state is-error">${escapeHtml(e.message)}</div>`; return; }

  const curIface = ctx.value("capture.iface", base.capture_interface);
  const curBpf = ctx.value("capture.bpf", base.bpf);
  const selected = detectPresets(curBpf);

  const ifaceOpts = base.interfaces.map((i) =>
    `<option value="${escapeHtml(i.name)}" ${i.name === curIface ? "selected" : ""}>${escapeHtml(i.name)} · ${escapeHtml(i.ipv4 || "無 IP")}</option>`).join("");

  container.innerHTML = `
    <div class="ops-grid ps-grid">
      <div class="ops-card">
        <div class="ops-card-head"><span class="ops-card-title">擷取介面</span>
          <span class="restart-hint">需重啟 Packet Sensor</span></div>
        <label class="ops-field">Capture Interface
          <select id="psIface">${ifaceOpts || `<option value="${escapeHtml(curIface)}">${escapeHtml(curIface)}</option>`}</select>
        </label>
        <div id="psIfaceHealth" class="ps-iface-health"></div>
      </div>

      <div class="ops-card ps-bpf">
        <div class="ops-card-head"><span class="ops-card-title">BPF Filter Builder</span></div>
        <p class="ops-helper">勾選工控協定快速組合 BPF；或在下方進階區自訂。</p>
        <div class="ps-preset-grid">
          ${PROTOCOL_PRESETS.map((p) => `
            <label class="ps-preset">
              <input type="checkbox" data-preset="${p.key}" ${selected.includes(p.key) ? "checked" : ""}/>
              <span class="ps-preset-label">${escapeHtml(p.label)}</span>
              <span class="ps-preset-bpf mono">${escapeHtml(p.bpf)}</span>
            </label>`).join("")}
        </div>
        <label class="ops-field">Advanced Raw BPF
          <textarea id="psBpf" rows="3" class="mono">${escapeHtml(curBpf)}</textarea>
        </label>
        <div id="psBpfValid" class="ps-bpf-valid"></div>
        <p class="ops-helper">修改擷取介面或 BPF Filter 需要重啟 Packet Sensor 才會生效。</p>
      </div>

      <div class="ops-card ps-test">
        <div class="ops-card-head"><span class="ops-card-title">擷取測試</span></div>
        <div class="ops-form-actions">
          <button type="button" class="btn btn-secondary btn-sm" id="psTest">測試擷取（10 秒）</button>
          <button type="button" class="btn btn-danger btn-sm" id="psRestart">重啟 Packet Sensor</button>
        </div>
        <div id="psTestResult" class="ps-test-result"><p class="hint muted">點選測試以取得封包統計</p></div>
      </div>
    </div>`;

  wire(container, ctx);
  renderIfaceHealth(container, curIface);
  renderBpfValidity(container, curBpf);
}

function detectPresets(bpf) {
  const s = String(bpf || "").toLowerCase();
  return PROTOCOL_PRESETS.filter((p) => s.includes(p.bpf.toLowerCase())).map((p) => p.key);
}

function wire(container, ctx) {
  $("#psIface", container).addEventListener("change", (e) => {
    const val = e.target.value;
    if (val === base.capture_interface) ctx.unstage("capture.iface");
    else ctx.stage("capture.iface", { value: val, label: "Capture Interface", tab: "packet", risk: "medium", services: ["packet-sensor"], apply: "capture", patch: { capture_interface: val } });
    renderIfaceHealth(container, val);
  });

  const stageBpf = (val) => {
    if (val === base.bpf) ctx.unstage("capture.bpf");
    else ctx.stage("capture.bpf", { value: val, label: "BPF Filter", tab: "packet", risk: "medium", services: ["packet-sensor"], apply: "capture", patch: { bpf: val } });
    renderBpfValidity(container, val);
  };

  $$("[data-preset]", container).forEach((cb) => cb.addEventListener("change", () => {
    const keys = $$("[data-preset]", container).filter((c) => c.checked).map((c) => c.dataset.preset);
    const built = buildBpfFromPresets(keys);
    const ta = $("#psBpf", container);
    ta.value = built;
    stageBpf(built);
  }));

  $("#psBpf", container).addEventListener("input", (e) => stageBpf(e.target.value.trim()));
  $("#psTest", container).addEventListener("click", () => runTest(container));
  $("#psRestart", container).addEventListener("click", () => doRestart(ctx));
}

function renderIfaceHealth(container, name) {
  const box = $("#psIfaceHealth", container);
  if (!box) return;
  const iface = base.interfaces.find((i) => i.name === name);
  if (!iface) { box.innerHTML = `<p class="hint muted">介面 ${escapeHtml(name)} 不在偵測清單（可能為手動指定）</p>`; return; }
  box.innerHTML = `
    <div class="ps-health-row"><span class="status-dot ${iface.dot || "gray"}"></span>${escapeHtml(iface.state_label || "—")}</div>
    <div class="ps-health-kv"><span>IPv4</span><span class="mono">${escapeHtml(iface.ipv4 || "—")}</span></div>
    <div class="ps-health-kv"><span>MAC</span><span class="mono">${escapeHtml(iface.mac || "—")}</span></div>
    <div class="ps-health-kv"><span>速率 / MTU</span><span class="mono">${iface.speed_mbps ? iface.speed_mbps + " Mbps" : "—"} / ${iface.mtu || "—"}</span></div>`;
}

function renderBpfValidity(container, expr) {
  const box = $("#psBpfValid", container);
  if (!box) return;
  const r = validateBpf(expr);
  box.className = `ps-bpf-valid ${r.valid ? "ok" : "bad"}`;
  box.innerHTML = r.valid
    ? `<span class="status-dot green"></span> BPF 語法檢查通過`
    : `<span class="status-dot red"></span> ${escapeHtml(r.error)}`;
}

async function runTest(container) {
  const box = $("#psTestResult", container);
  box.innerHTML = `<p class="hint">擷取測試中（10 秒）…</p>`;
  const r = await testCapture(10);
  box.innerHTML = `
    <div class="ps-test-grid">
      <div class="ps-test-stat"><span class="ps-test-num">${r.packets}</span><span class="ps-test-cap">封包</span></div>
      <div class="ps-test-stat"><span class="ps-test-num">${r.protocol_matches}</span><span class="ps-test-cap">協定符合</span></div>
      <div class="ps-test-stat"><span class="ps-test-num">${r.unique_ips}</span><span class="ps-test-cap">來源 IP</span></div>
    </div>
    <div class="ps-test-foot mono muted">最後封包：${r.last_packet_at ? fmtTime(r.last_packet_at) : "—"}${r.MOCK ? " · 估算值" : ""}</div>`;
}

async function doRestart(ctx) {
  const ok = await ctx.confirm({
    title: "重啟 Packet Sensor", risk: "medium", services: ["packet-sensor"],
    bodyHtml: `<p>重啟期間將暫停封包擷取數秒。</p>`, confirmLabel: "重啟",
  });
  if (!ok) return;
  try { const r = await restartPacketSensor(); toast(r.message || "Packet Sensor 已重啟"); }
  catch (e) { toast(e.message, false); }
}
