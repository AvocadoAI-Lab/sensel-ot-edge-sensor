// 診斷工具 Tab — service status, restart/logs, support bundle.
import { $, $$, escapeHtml, toast } from "../../core/dom.js";
import { fmtTime, relTime } from "../../core/format.js";
import { getServiceStatus, restartService, getServiceLogs, createSupportBundle } from "../../core/opsApi.js";

export const id = "diagnostics";
export const label = "診斷工具";

export function render(container, ctx) {
  container.innerHTML = `
    <div class="ops-grid diag-grid">
      <div class="ops-card diag-services ov-card-wide">
        <div class="ops-card-head"><span class="ops-card-title">服務狀態</span>
          <button type="button" class="btn btn-ghost btn-sm" id="diagRefresh">重新整理</button></div>
        <div id="diagServiceList" class="diag-service-list"><p class="hint muted">載入中…</p></div>
      </div>

      <div class="ops-card diag-bundle">
        <div class="ops-card-head"><span class="ops-card-title">Support Bundle</span><span class="mock-tag">用戶端打包</span></div>
        <p class="ops-helper">收集設定、狀態、網路診斷與稽核記錄，下載為單一檔案供支援分析。</p>
        <ul class="diag-bundle-items">
          <li>config / platform.json</li><li>system status</li>
          <li>network interfaces</li><li>vpn status</li><li>audit log（近 200 筆）</li>
        </ul>
        <div class="ops-form-actions"><button type="button" class="btn btn-secondary btn-sm" id="diagBundle">產生並下載</button></div>
      </div>

      <div class="ops-card diag-output ov-card-wide">
        <div class="ops-card-head"><span class="ops-card-title">指令輸出</span>
          <button type="button" class="btn btn-ghost btn-sm" id="diagClear">清空</button></div>
        <pre id="diagConsole" class="diag-console mono">尚無輸出。從上方服務選擇「查看日誌」或執行操作。</pre>
      </div>
    </div>`;

  loadServices(container, ctx);
  $("#diagRefresh", container).addEventListener("click", () => loadServices(container, ctx));
  $("#diagClear", container).addEventListener("click", () => { $("#diagConsole", container).textContent = "（已清空）"; });
  $("#diagBundle", container).addEventListener("click", async () => {
    out(container, "正在產生 support bundle…");
    try { await createSupportBundle(); out(container, "Support bundle 已下載（JSON）。"); toast("Support bundle 已下載"); }
    catch (e) { out(container, `失敗：${e.message}`); toast(e.message, false); }
  });
}

async function loadServices(container, ctx) {
  const host = $("#diagServiceList", container);
  const services = await getServiceStatus().catch(() => []);
  if (!services.length) { host.innerHTML = `<p class="hint muted">無法取得服務狀態</p>`; return; }
  host.innerHTML = services.map((s) => `
    <div class="diag-service ${s.state}">
      <span class="status-dot ${s.state}"></span>
      <div class="diag-service-info">
        <span class="diag-service-name">${escapeHtml(s.label)}</span>
        <span class="diag-service-detail mono muted">${escapeHtml(s.detail || "—")}${s.uptime && s.uptime !== "—" ? ` · ${relTime(s.uptime)}` : ""}</span>
      </div>
      <div class="diag-service-actions">
        <button type="button" class="btn btn-ghost btn-sm" data-diag-log="${s.id}">查看日誌</button>
        <button type="button" class="btn btn-secondary btn-sm" data-diag-restart="${s.id}" data-label="${escapeHtml(s.label)}">重啟</button>
      </div>
    </div>`).join("");

  $$("[data-diag-log]", host).forEach((b) => b.addEventListener("click", async () => {
    out(container, `讀取 ${b.dataset.diagLog} 日誌…`);
    const r = await getServiceLogs(b.dataset.diagLog);
    out(container, r.logs || "（無日誌）");
  }));
  $$("[data-diag-restart]", host).forEach((b) => b.addEventListener("click", async () => {
    const sid = b.dataset.diagRestart, lbl = b.dataset.label;
    const ok = await ctx.confirm({ title: `重啟 ${lbl}`, risk: "medium", services: [sid], bodyHtml: `<p>確定要重啟 ${escapeHtml(lbl)}？</p>`, confirmLabel: "重啟" });
    if (!ok) return;
    out(container, `重啟 ${lbl}…`);
    try {
      const r = await restartService(sid);
      if (r.MOCK || r.ok === false) { out(container, r.message || "不支援直接重啟"); toast(r.message || "不支援", false); }
      else { out(container, r.message || `${lbl} 已重啟`); toast(`${lbl} 已重啟`); }
      await loadServices(container, ctx);
    } catch (e) { out(container, `失敗：${e.message}`); toast(e.message, false); }
  }));
}

function out(container, text) {
  const c = $("#diagConsole", container);
  if (!c) return;
  const ts = fmtTime(Date.now());
  c.textContent = `[${ts}] ${text}\n` + (c.textContent.startsWith("尚無輸出") || c.textContent.startsWith("（已清空）") ? "" : c.textContent);
}
