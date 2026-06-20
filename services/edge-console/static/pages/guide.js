// 操作手冊 — 淺顯易懂的快速上手指南，首頁可進入。
import { $, toast } from "../core/dom.js";
import { api } from "../core/api.js";
import { navigate } from "../core/shell.js";

export const meta = { title: "操作手冊", sub: "快速上手 · 三步完成接入" };

const STEPS = [
  {
    n: 1,
    title: "接好網路與鏡像流量",
    body: `把設備接上網路（取得管理 IP），並將交換器的 <b>SPAN / 鏡像埠</b> 接到擷取網卡。
           單網卡 Lab 環境可用同一張卡同時做管理與擷取。`,
    tip: "不確定要監看哪張網卡？到「系統維運 → 網路」可以查看與切換介面。",
  },
  {
    n: 2,
    title: "進入接入精靈，填寫平台資訊",
    body: `在「接入精靈」三步流程中填入 <b>SenseL API URL</b>、<b>API Key</b>、
           <b>企業邀請碼</b> 與 <b>控制平面 MQTT Host</b>，按「測試 SenseL 連線」確認可達。`,
    tip: "企業邀請碼由 SenseL 平台（SMB Portal）產生，用來把這台感測器綁定到你的企業帳號。",
    cta: { label: "前往接入精靈", page: "setup" },
  },
  {
    n: 3,
    title: "儲存並註冊，確認憑證落地",
    body: `按「儲存並註冊」。成功後會顯示 <b>tenant</b>，且「落地狀態」面板會出現
           <b>✓ MQTT 憑證已落地</b> — 代表北向上傳鏈路已打通。`,
    tip: "憑證是註冊後由控制平面自動下發的，不需要手動填 MQTT 帳密。",
  },
  {
    n: 4,
    title: "送一筆測試事件，確認 SenseL 看得到",
    body: `按下方的 <b>「送出測試事件」</b>，系統會產生一筆合成安全事件，走與真實偵測
           完全相同的上傳路徑。數秒後即可在 SenseL 平台的 OT 事件時間軸看到它。`,
    tip: "測試事件會標記為 synthetic，方便平台端與真實事件區分。",
    testButton: true,
  },
];

const READINESS = [
  { key: "score", label: "Edge Readiness 分數", desc: "綜合整備度，越高越好" },
  { key: "baseline", label: "Baseline 基線", desc: "資產與通訊白名單，偵測異常的基準" },
  { key: "events", label: "安全事件", desc: "本機偵測或外部引擎產生的告警" },
  { key: "northbound", label: "北向連線", desc: "事件上傳到 SenseL 平台的通道" },
];

const FAQ = [
  {
    q: "用瀏覽器怎麼進到這個主控台？",
    a: "同網段下開 <code>http://sensel.local:8090</code>（或 HTTPS <code>https://sensel.local:8443</code>）。若名稱解析不到，改用開機畫面顯示的 IP，例如 <code>http://&lt;裝置IP&gt;:8090</code>。",
  },
  {
    q: "「測試 SenseL 連線」綠燈，但註冊失敗？",
    a: "連線測試只檢查健康路徑；真正驗證是「儲存並註冊」那一步，它會檢查 API Key 與企業邀請碼是否正確、未過期。",
  },
  {
    q: "送了測試事件，SenseL 卻沒看到？",
    a: "請先確認「落地狀態」顯示憑證已落地、北向 MQTT 已連線。若北向未啟用，事件只會留在本機（在「安全事件」頁可見）。",
  },
  {
    q: "沒有鏡像流量會怎樣？",
    a: "被動偵測沒有流量就不會有告警，這是正常的。可先用「送出測試事件」驗證上傳鏈路，再接上 SPAN 流量做真實偵測。",
  },
];

export function render(root) {
  root.innerHTML = `
    <section class="page guide-page">
      <div class="guide-hero card-ot">
        <div class="guide-hero-main">
          <h2>歡迎使用 SenseL OT Edge Sensor</h2>
          <p class="hint">這是一台 OT 資安感測器。跟著下面四步，幾分鐘就能完成接入並驗證上傳。</p>
        </div>
        <div class="guide-hero-actions">
          <button type="button" class="btn btn-primary" id="guideGoSetup">開始接入</button>
          <button type="button" class="btn btn-ghost" id="guideGoDash">前往總覽</button>
        </div>
      </div>

      <h3 class="guide-section-title">四步快速上手</h3>
      <div class="guide-steps">
        ${STEPS.map(renderStep).join("")}
      </div>

      <h3 class="guide-section-title">看懂總覽儀表板</h3>
      <div class="guide-readiness card-ot">
        ${READINESS.map((r) => `
          <div class="guide-rd-item">
            <div class="guide-rd-label">${r.label}</div>
            <div class="guide-rd-desc hint">${r.desc}</div>
          </div>`).join("")}
      </div>

      <h3 class="guide-section-title">常見問題</h3>
      <div class="guide-faq">
        ${FAQ.map((f) => `
          <details class="guide-faq-item card">
            <summary>${f.q}</summary>
            <p class="hint">${f.a}</p>
          </details>`).join("")}
      </div>
    </section>`;

  $("#guideGoSetup")?.addEventListener("click", () => navigate("setup"));
  $("#guideGoDash")?.addEventListener("click", () => navigate("dashboard"));
  root.querySelectorAll("[data-goto]").forEach((b) =>
    b.addEventListener("click", () => navigate(b.dataset.goto)));
  $("#guideTestEvent")?.addEventListener("click", sendTestEvent);
}

export function leave() {}

function renderStep(s) {
  const cta = s.cta
    ? `<button type="button" class="btn btn-sm btn-secondary" data-goto="${s.cta.page}">${s.cta.label}</button>`
    : "";
  const testBtn = s.testButton
    ? `<button type="button" class="btn btn-sm btn-primary" id="guideTestEvent">送出測試事件</button>`
    : "";
  const actions = (cta || testBtn) ? `<div class="guide-step-actions">${cta}${testBtn}</div>` : "";
  const tip = s.tip ? `<div class="guide-step-tip">💡 ${s.tip}</div>` : "";
  return `
    <div class="guide-step card-ot">
      <div class="guide-step-num">${s.n}</div>
      <div class="guide-step-body">
        <div class="guide-step-title">${s.title}</div>
        <p class="guide-step-text">${s.body}</p>
        ${tip}
        ${actions}
      </div>
    </div>`;
}

async function sendTestEvent(ev) {
  const btn = ev.currentTarget;
  btn.disabled = true;
  const original = btn.textContent;
  btn.textContent = "送出中…";
  try {
    const r = await api("/api/test-event", { method: "POST" });
    toast(r.message || "測試事件已送出", !!r.ok);
  } catch (e) {
    toast(e.message || "送出失敗", false);
  } finally {
    btn.disabled = false;
    btn.textContent = original;
  }
}
