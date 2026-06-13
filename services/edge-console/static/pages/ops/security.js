// 安全與稽核 Tab — console password + audit log.
import { $, $$, escapeHtml, toast } from "../../core/dom.js";
import { fmtTime, relTime } from "../../core/format.js";
import { changeConsolePassword, getAuditLogs, exportAuditLogs, clearLocalAuditLog,
  AUDIT_CATEGORIES } from "../../core/opsApi.js";

export const id = "security";
export const label = "安全與稽核";

let filterCat = "";
let searchQ = "";

export function render(container, ctx) {
  container.innerHTML = `
    <div class="ops-grid sec-grid">
      <div class="ops-card sec-pw">
        <div class="ops-card-head"><span class="ops-card-title">變更 Console 密碼</span></div>
        <div class="ops-form">
          <label class="ops-field">目前密碼<input id="pwCur" type="password" autocomplete="current-password"/></label>
          <label class="ops-field">新密碼<input id="pwNew" type="password" autocomplete="new-password"/></label>
          <label class="ops-field">確認新密碼<input id="pwNew2" type="password" autocomplete="new-password"/></label>
          <div class="pw-strength"><div class="pw-strength-bar" id="pwBar"></div></div>
          <div class="pw-strength-label mono muted" id="pwLabel">密碼強度：—</div>
        </div>
        <div class="ops-form-actions"><button type="button" class="btn btn-primary btn-sm" id="pwSubmit">更新密碼</button></div>
      </div>

      <div class="ops-card sec-session">
        <div class="ops-card-head"><span class="ops-card-title">登入 / 存取摘要</span></div>
        <div id="secSession" class="sec-session-body"><p class="hint muted">載入中…</p></div>
      </div>

      <div class="ops-card sec-audit ov-card-wide">
        <div class="ops-card-head"><span class="ops-card-title">稽核記錄</span>
          <div class="sec-audit-tools">
            <input id="auditSearch" class="audit-search" type="search" placeholder="搜尋…" value="${escapeHtml(searchQ)}"/>
            <button type="button" class="btn btn-ghost btn-sm" id="auditExport">匯出</button>
            <button type="button" class="btn btn-danger btn-sm" id="auditClear">清除本機記錄</button>
          </div>
        </div>
        <div class="audit-filters" id="auditFilters"></div>
        <div class="audit-table-wrap"><table class="audit-table">
          <thead><tr><th>時間</th><th>Actor</th><th>類別</th><th>Action</th><th>Target</th><th>結果</th></tr></thead>
          <tbody id="auditBody"><tr><td colspan="6" class="hint muted">載入中…</td></tr></tbody>
        </table></div>
      </div>
    </div>`;

  wirePassword(container);
  renderFilters(container);
  loadAudit(container);
  loadSession(container);

  $("#auditSearch", container).addEventListener("input", (e) => { searchQ = e.target.value; loadAudit(container); });
  $("#auditExport", container).addEventListener("click", async () => { const r = await exportAuditLogs(); toast(`已匯出 ${r.count} 筆`); });
  $("#auditClear", container).addEventListener("click", async () => {
    const ok = await ctx.confirm({ title: "清除本機稽核記錄", risk: "high", bodyHtml: `<p>此操作不可復原。</p>`, confirmLabel: "清除", danger: true });
    if (!ok) return;
    const r = clearLocalAuditLog();
    toast(r.message || "已清除", r.ok);
  });
}

// ---- password -------------------------------------------------------------
function strength(pw) {
  let s = 0;
  if (pw.length >= 8) s++;
  if (pw.length >= 12) s++;
  if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) s++;
  if (/\d/.test(pw)) s++;
  if (/[^A-Za-z0-9]/.test(pw)) s++;
  return Math.min(4, s);
}
function wirePassword(container) {
  const bar = $("#pwBar", container), lbl = $("#pwLabel", container);
  const levels = ["很弱", "弱", "中等", "強", "很強"];
  const colors = ["#e5484d", "#e5894d", "#e3c64d", "#9bd64a", "#4ad6a0"];
  $("#pwNew", container).addEventListener("input", (e) => {
    const s = strength(e.target.value);
    const pct = e.target.value ? (s + 1) * 20 : 0;
    bar.style.width = `${pct}%`;
    bar.style.background = colors[s] || colors[0];
    lbl.textContent = `密碼強度：${e.target.value ? levels[s] : "—"}`;
  });
  $("#pwSubmit", container).addEventListener("click", async () => {
    const cur = $("#pwCur", container).value, n1 = $("#pwNew", container).value, n2 = $("#pwNew2", container).value;
    if (!cur) return toast("請輸入目前密碼", false);
    if (n1.length < 8) return toast("新密碼至少 8 碼", false);
    if (n1 !== n2) return toast("兩次新密碼不一致", false);
    try {
      await changeConsolePassword(cur, n1);
      toast("密碼已更新");
      $("#pwCur", container).value = ""; $("#pwNew", container).value = ""; $("#pwNew2", container).value = "";
      bar.style.width = "0"; lbl.textContent = "密碼強度：—";
    } catch (e) { toast(e.message, false); }
  });
}

// ---- audit ----------------------------------------------------------------
function renderFilters(container) {
  const host = $("#auditFilters", container);
  const all = [{ key: "", label: "全部" }, ...AUDIT_CATEGORIES];
  host.innerHTML = all.map((c) =>
    `<button type="button" class="audit-chip ${filterCat === c.key ? "active" : ""}" data-cat="${c.key}">${escapeHtml(c.label)}</button>`).join("");
  $$("[data-cat]", host).forEach((b) => b.addEventListener("click", () => {
    filterCat = b.dataset.cat;
    renderFilters(container);
    loadAudit(container);
  }));
}

async function loadAudit(container) {
  const body = $("#auditBody", container);
  const rows = await getAuditLogs({ category: filterCat, q: searchQ, limit: 300 });
  if (!rows.length) { body.innerHTML = `<tr><td colspan="6" class="hint muted">無符合的記錄</td></tr>`; return; }
  const catLabel = Object.fromEntries(AUDIT_CATEGORIES.map((c) => [c.key, c.label]));
  body.innerHTML = rows.map((r) => `
    <tr>
      <td class="mono" title="${escapeHtml(fmtTime(r.at))}">${escapeHtml(fmtTime(r.at))}</td>
      <td>${escapeHtml(r.actor)}</td>
      <td><span class="audit-cat-tag ${r.category}">${escapeHtml(catLabel[r.category] || r.category)}</span></td>
      <td class="mono">${escapeHtml(r.action)}</td>
      <td class="mono">${escapeHtml(String(r.target))}</td>
      <td><span class="state-badge ${r.result === "ok" ? "green" : "red"}">${escapeHtml(r.result)}</span></td>
    </tr>`).join("");
}

async function loadSession(container) {
  const host = $("#secSession", container);
  const logins = await getAuditLogs({ category: "auth", limit: 50 });
  const last = logins.find((r) => /login/.test(r.action)) || null;
  let authed = null;
  try { authed = await (await fetch("/api/auth/status")).json(); } catch {}
  host.innerHTML = `
    <div class="net-card-kv"><span>最後登入</span><span class="mono">${last ? `${fmtTime(last.at)}（${relTime(last.at)}）` : "—"}</span></div>
    <div class="net-card-kv"><span>來源 IP</span><span class="mono">${escapeHtml(last?.detail?.ip || last?.detail?.source || "—")}</span></div>
    <div class="net-card-kv"><span>認證方式</span><span class="mono">${authed?.password_required ? "密碼" : "未設密碼"}</span></div>
    <div class="net-card-kv"><span>目前狀態</span><span>${authed?.authenticated ? "已登入" : "—"}</span></div>`;
}
