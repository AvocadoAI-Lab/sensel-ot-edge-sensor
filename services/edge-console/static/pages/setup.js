// 接入精靈 — sensor identity → SenseL connection → register.
import { $, $$, toast, escapeHtml } from "../core/dom.js";
import { api } from "../core/api.js";
import { navigate } from "../core/shell.js";

export const meta = { title: "接入精靈", sub: "感測器身分 · SenseL 註冊" };

let step = 1;

export function render(root) {
  root.innerHTML = `
    <section class="page panel">
      <p class="hint">三步完成：感測器身分 → 連線 SenseL → 測試註冊</p>
      <div class="wizard-steps">
        <span class="step-pill active" data-step="1">1 感測器</span>
        <span class="step-pill" data-step="2">2 SenseL</span>
        <span class="step-pill" data-step="3">3 註冊</span>
      </div>

      <div id="wizardStep1">
        <div class="grid-2">
          <label>Sensor ID<input id="wSensorId" placeholder="ot-edge-001" /></label>
          <label>Site ID<input id="wSiteId" placeholder="factory-lab-001" /></label>
        </div>
        <div class="actions"><button type="button" class="btn btn-primary" data-next="2">下一步</button></div>
      </div>

      <div id="wizardStep2" class="hidden">
        <div class="grid-2">
          <label>SenseL API URL<input id="wApiUrl" placeholder="http://192.168.1.108:8081" />
            <span class="hint">Lab：若 108 連不到，可填 <code>http://192.168.1.123:8765</code></span></label>
          <label>API Key<input id="wApiKey" type="password" placeholder="ingest secret" /></label>
          <label>企業邀請碼 (Registration Token)<input id="wInvite" type="password" placeholder="Avocado AI 邀請碼" autocomplete="off" /></label>
          <label>MQTT Host (Control Plane)<input id="wMqttHost" placeholder="192.168.1.203" /></label>
          <input type="hidden" id="sMqttPort" value="1883" />
          <input type="hidden" id="sVerifyTls" value="false" />
        </div>
        <div class="actions">
          <button type="button" class="btn btn-ghost" data-next="1">上一步</button>
          <button type="button" class="btn btn-secondary" id="pingSenselBtn">測試 SenseL 連線</button>
          <button type="button" class="btn btn-primary" data-next="3">下一步</button>
        </div>
      </div>

      <div id="wizardStep3" class="hidden">
        <div class="card" id="wizardSummary"></div>
        <div class="actions">
          <button type="button" class="btn btn-ghost" data-next="2">上一步</button>
          <button type="button" class="btn btn-primary" id="saveAndRegisterBtn">儲存並註冊</button>
        </div>
        <pre id="registerResult" class="card" style="margin-top:1rem; white-space:pre-wrap; font-size:0.85rem;"></pre>
      </div>
    </section>`;

  $$("[data-next]").forEach((b) => b.addEventListener("click", () => setStep(parseInt(b.dataset.next, 10))));
  $("#pingSenselBtn").addEventListener("click", pingSensel);
  $("#saveAndRegisterBtn").addEventListener("click", saveAndRegister);
  loadConfig().catch(() => {});
  step = 1;
}

export function leave() {}

function setStep(n) {
  step = n;
  [1, 2, 3].forEach((i) => {
    $(`#wizardStep${i}`)?.classList.toggle("hidden", i !== n);
    const pill = document.querySelector(`.step-pill[data-step="${i}"]`);
    pill?.classList.toggle("active", i === n);
    pill?.classList.toggle("done", i < n);
  });
  if (n === 3) {
    $("#wizardSummary").innerHTML = `
      <div><strong>Sensor</strong> ${escapeHtml($("#wSensorId").value)} @ ${escapeHtml($("#wSiteId").value)}</div>
      <div><strong>SenseL</strong> ${escapeHtml($("#wApiUrl").value)}</div>
      <div><strong>MQTT</strong> ${escapeHtml($("#wMqttHost").value)}:1883</div>
      <div><strong>邀請碼</strong> ${$("#wInvite").value ? "已填寫" : "未填寫"}</div>`;
  }
}

function collect(extra = {}) {
  return {
    sensor_id: $("#wSensorId").value.trim(), site_id: $("#wSiteId").value.trim(),
    sensel_api_url: $("#wApiUrl").value.trim(), sensel_api_key: $("#wApiKey").value.trim(),
    registration_token: $("#wInvite").value.trim(), mqtt_host: $("#wMqttHost").value.trim(),
    mqtt_port: parseInt($("#sMqttPort").value || "1883", 10),
    sensel_verify_tls: $("#sVerifyTls").value === "true",
    ...extra,
  };
}

async function loadConfig() {
  const cfg = await api("/api/config");
  $("#wSensorId").value = cfg.sensor_id || "";
  $("#wSiteId").value = cfg.site_id || "";
  $("#wApiUrl").value = cfg.sensel_api_url || "";
  $("#wMqttHost").value = cfg.mqtt_host || "";
  $("#sMqttPort").value = cfg.mqtt_port || 1883;
  $("#sVerifyTls").value = cfg.sensel_verify_tls ? "true" : "false";
  if (!cfg.sensel_api_key_set) $("#wApiKey").placeholder = "（已儲存，留空不變）";
  if (!cfg.registration_token_set) $("#wInvite").placeholder = "（已儲存，留空不變）";
}

async function pingSensel() {
  try {
    await api("/api/config", { method: "PUT", body: JSON.stringify(collect()) });
    const r = await api("/api/sensel/ping", { method: "POST" });
    toast(r.ok ? "SenseL 連線正常" : (r.error || "連線失敗"), r.ok);
  } catch (e) { toast(e.message, false); }
}

async function saveAndRegister() {
  try {
    await api("/api/config", { method: "PUT", body: JSON.stringify(collect()) });
    const r = await api("/api/register/test", { method: "POST", body: JSON.stringify({ save_first: true }) });
    $("#registerResult").textContent = JSON.stringify(r, null, 2);
    toast(r.ok ? `註冊成功 · tenant ${r.tenant_id}` : (r.error || "註冊失敗"), !!r.ok);
    if (r.ok) navigate("dashboard");
  } catch (e) { toast(e.message, false); }
}
