// 北向連線 Tab — MQTT + SenseL cloud, with test + config preview.
import { $, escapeHtml, toast } from "../../core/dom.js";
import { fmtTime } from "../../core/format.js";
import { getMqttSettings, testMqttConnection } from "../../core/opsApi.js";

export const id = "northbound";
export const label = "北向連線";

let base = null;

const TLS_MODES = [
  { v: "lab", label: "Lab Disabled（關閉驗證）" },
  { v: "production", label: "Production Enabled（啟用 TLS）" },
  { v: "custom", label: "Custom CA（自訂憑證）" },
];

export function render(container, ctx) {
  container.innerHTML = `<div class="card-state is-loading">載入北向設定…</div>`;
  load(container, ctx);
}

async function load(container, ctx) {
  try { base = await getMqttSettings(); }
  catch (e) { container.innerHTML = `<div class="card-state is-error">${escapeHtml(e.message)}</div>`; return; }

  const v = (k) => ctx.value(`mqtt.${k}`, base[k]);
  container.innerHTML = `
    <div class="ops-grid nb-grid">
      <div class="ops-card nb-form">
        <div class="ops-card-head"><span class="ops-card-title">SenseL MQTT</span>
          <span class="restart-hint">需重啟 Edge Agent</span></div>
        <div class="ops-form">
          <label class="ops-field">MQTT Host
            <input id="nbHost" type="text" value="${escapeHtml(v("host"))}" placeholder="192.168.1.203" />
          </label>
          <label class="ops-field">MQTT Port
            <input id="nbPort" type="number" value="${escapeHtml(String(v("port")))}" placeholder="1883" />
          </label>
          <label class="ops-field">MQTT Tenant（唯讀）
            <input id="nbTenant" type="text" value="${escapeHtml(base.tenant || "")}" readonly placeholder="註冊後自動填入" />
          </label>
          <label class="ops-field">TLS Mode
            <select id="nbTls">${TLS_MODES.map((m) => `<option value="${m.v}" ${v("tls_mode") === m.v ? "selected" : ""}>${escapeHtml(m.label)}</option>`).join("")}</select>
          </label>
          <label class="ops-field ops-field-toggle">
            <input id="nbEnabled" type="checkbox" ${v("enabled") ? "checked" : ""}/> 啟用北向上行
          </label>
        </div>
        <p class="ops-helper">變更 Host / Port / TLS 後，需重啟 Edge Agent 才會生效。</p>
        <div class="ops-form-actions">
          <button type="button" class="btn btn-secondary btn-sm" id="nbTest">測試連線</button>
        </div>
      </div>

      <div class="ops-side">
        <div class="ops-card">
          <div class="ops-card-head"><span class="ops-card-title">連線測試結果</span></div>
          <div id="nbResult" class="nb-result"><p class="hint muted">尚未測試</p></div>
        </div>
        <div class="ops-card">
          <div class="ops-card-head"><span class="ops-card-title">Config Preview</span></div>
          <pre id="nbPreview" class="config-preview mono"></pre>
        </div>
      </div>
    </div>`;

  wire(container, ctx);
  renderPreview(ctx);
}

function wire(container, ctx) {
  const stageField = (key, value, label) => {
    const same = String(value) === String(base[key]);
    if (same) ctx.unstage(`mqtt.${key}`);
    else ctx.stage(`mqtt.${key}`, { value, label, tab: "northbound", risk: "medium", services: ["edge-agent"], apply: "mqtt", patch: { [key]: value } });
    renderPreview(ctx);
  };
  $("#nbHost", container).addEventListener("input", (e) => stageField("host", e.target.value.trim(), "MQTT Host"));
  $("#nbPort", container).addEventListener("input", (e) => stageField("port", parseInt(e.target.value, 10) || 1883, "MQTT Port"));
  $("#nbTls", container).addEventListener("change", (e) => stageField("tls_mode", e.target.value, "TLS Mode"));
  $("#nbEnabled", container).addEventListener("change", (e) => stageField("enabled", e.target.checked, "北向上行"));
  $("#nbTest", container).addEventListener("click", () => runTest(container));
}

function renderPreview(ctx) {
  const pre = $("#nbPreview");
  if (!pre) return;
  const v = (k) => ctx.value(`mqtt.${k}`, base[k]);
  pre.textContent = JSON.stringify({
    mqtt_host: v("host"),
    mqtt_port: v("port"),
    mqtt_tenant_id: base.tenant || "(register)",
    sensel_verify_tls: v("tls_mode") !== "lab",
    mqtt_enabled: v("enabled"),
  }, null, 2);
}

async function runTest(container) {
  const box = $("#nbResult", container);
  box.innerHTML = `<p class="hint">測試中…</p>`;
  const r = await testMqttConnection();
  box.innerHTML = `
    <div class="nb-result-row"><span class="status-dot ${r.mqtt.ok ? "green" : "red"}"></span> 北向 MQTT：${r.mqtt.ok ? "已連線" : "未連線"}</div>
    <div class="nb-result-row mono muted">${escapeHtml(r.mqtt.detail || "—")}</div>
    <div class="nb-result-row"><span class="status-dot ${r.cloud.ok ? "green" : "yellow"}"></span> SenseL Cloud：${r.cloud.ok ? "可達" : "不可達"}</div>
    <div class="nb-result-row mono muted">${escapeHtml(r.cloud.detail || "—")}</div>
    <div class="nb-result-foot mono">測試時間：${fmtTime(r.at)}</div>`;
  toast(r.ok ? "北向 MQTT 連線正常" : (r.error || "北向未連線"), r.ok);
}
