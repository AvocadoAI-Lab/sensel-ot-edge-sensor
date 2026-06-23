// IT NDR policy view — Suricata IDS bundle status only (no OT baseline / detection policy).
import { $, toast, escapeHtml } from "../core/dom.js";
import { fmtTime } from "../core/format.js";
import { badge, stateBlock } from "../ui/components.js";
import { getIdsRuleStatus, getStatus } from "../core/dataSource.js";

export const meta = { title: "偵測與政策", sub: "IT NDR · Suricata IDS 規則包" };

function engineRow(engine, entry) {
  const ok = entry?.ok === true && !entry?.rolled_back;
  const state = ok ? "green" : entry?.rolled_back ? "yellow" : entry?.ok === false ? "red" : "gray";
  const stateLabel = ok ? "已套用" : entry?.rolled_back ? "已回滾" : entry?.ok === false ? "失敗" : "未知";
  return `
    <tr>
      <td class="mono">${escapeHtml(engine)}</td>
      <td>${badge(stateLabel, state === "green" ? "green" : state === "red" ? "red" : state === "yellow" ? "yellow" : "gray")}</td>
      <td class="mono text-xs">${escapeHtml(entry?.version || "—")}</td>
      <td class="text-xs text-muted">${escapeHtml(entry?.etag || "—")}</td>
      <td class="text-xs">${fmtTime(entry?.applied_at || entry?.last_sync_at)}</td>
      <td class="text-xs">${escapeHtml(entry?.error || entry?.last_error || "—")}</td>
    </tr>`;
}

export function renderIt(root) {
  root.innerHTML = `
    <section class="page">
      <div class="title section-title">IT NDR · Suricata 規則</div>
      <p class="hint">部署模式固定為 IT NDR；規則包由 SenseL Portal → 網路安全營運 → 防護管理中心派送（<code>profile=it_ndr</code>）。此頁僅顯示邊緣套用狀態。</p>

      <div class="card-ot" style="margin-top:1rem">
        <div class="title">平台連線</div>
        <div id="itPolicyPlatform">${stateBlock("loading")}</div>
      </div>

      <div class="card-ot" style="margin-top:1rem">
        <div class="title">IDS 規則包狀態</div>
        <div id="itPolicyIds">${stateBlock("loading")}</div>
      </div>

      <div class="actions" style="margin-top:1rem">
        <button type="button" class="btn btn-secondary" id="itPolicyRefresh">重新整理</button>
      </div>
    </section>`;

  $("#itPolicyRefresh").addEventListener("click", () => loadIt().catch((e) => toast(e.message, false)));
  loadIt().catch((e) => {
    $("#itPolicyIds").innerHTML = stateBlock("error", e.message);
  });
}

async function loadIt() {
  const [status, ids] = await Promise.all([getStatus(), getIdsRuleStatus()]);
  const cards = status.cards || {};
  $("#itPolicyPlatform").innerHTML = `
    <ul class="sub" style="margin:0;padding-left:1.1rem">
      <li>部署模式：${badge("IT NDR", "blue")} · feed profile <span class="mono">${escapeHtml(ids.feed_profile || "it_ndr")}</span></li>
      <li>感測器註冊：${escapeHtml(cards.registration?.detail || "—")}</li>
      <li>SenseL Platform：${escapeHtml(cards.sensel?.detail || "—")}</li>
      <li>北向 MQTT：${escapeHtml(cards.mqtt?.detail || "—")}</li>
    </ul>`;

  const engines = ids.engines || {};
  const keys = Object.keys(engines);
  if (!ids.loaded || keys.length === 0) {
    $("#itPolicyIds").innerHTML = `<p class="hint">尚無 IDS 規則同步紀錄。請在 Portal 建立並派送 IT 規則包，agent 約每 5 分鐘拉取一次。</p>`;
    return;
  }
  $("#itPolicyIds").innerHTML = `
    <table class="baseline-history" style="width:100%">
      <thead><tr>
        <th>引擎</th><th>狀態</th><th>版本</th><th>ETag</th><th>套用時間</th><th>備註</th>
      </tr></thead>
      <tbody>${keys.map((k) => engineRow(k, engines[k])).join("")}</tbody>
    </table>`;
}
