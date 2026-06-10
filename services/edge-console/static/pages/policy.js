// 偵測與政策 — Policy Readiness categories, applied policy (read-only), Baseline Management.
import { $, $$, toast, escapeHtml } from "../core/dom.js";
import { api } from "../core/api.js";
import { fmtTime } from "../core/format.js";
import { dot, badge, stateBlock, copyField, openDrawer, STATE_LABEL } from "../ui/components.js";
import { getPolicyReadiness, getBaseline } from "../core/dataSource.js";
import { updateShield } from "../core/shell.js";

export const meta = { title: "偵測與政策", sub: "Policy Readiness · Baseline Management" };

export function render(root) {
  root.innerHTML = `
    <section class="page">
      <div class="title section-title">Policy Readiness</div>
      <div class="grid-policy" id="policyCategories">${stateBlock("loading")}</div>

      <div class="card-ot" id="baselineMgmt" style="margin-top:1rem">
        <div class="title">Baseline Management</div>
        <div id="baselineMgmtBody">${stateBlock("loading")}</div>
      </div>

      <div class="card-ot" id="appliedCard" style="margin-top:1rem">
        <div class="title">目前套用政策（唯讀）</div>
        <p class="hint">修改請至 SenseL Portal → 工控安全防護 → 偵測政策 → MQTT 發布。</p>
        <div id="appliedBody">${stateBlock("loading")}</div>
      </div>

      <div class="actions" style="margin-top:1rem">
        <button type="button" class="btn btn-secondary" id="policyRefresh">重新整理</button>
      </div>
    </section>`;

  $("#policyRefresh").addEventListener("click", () => load().catch((e) => toast(e.message, false)));
  load().catch((e) => { $("#policyCategories").innerHTML = stateBlock("error", e.message); });
}

export function leave() {}

async function load() {
  const [readiness, baseline] = await Promise.all([getPolicyReadiness(), getBaseline()]);
  renderCategories(readiness.categories);
  renderApplied(readiness.applied);
  renderBaselineMgmt(baseline);
  updateShield(baseline.state === "active" ? "green" : baseline.state === "not_loaded" ? "red" : "yellow");
}

function renderCategories(categories) {
  $("#policyCategories").innerHTML = categories.map((c) => `
    <div class="card-ot policy-cat ${c.state}">
      <div class="pc-head">${dot(c.state)}<span class="pc-label">${escapeHtml(c.label)}</span></div>
      <div class="pc-desc">${escapeHtml(c.desc)}</div>
      <div class="pc-action">action：<span class="action-pill action-${c.action.toLowerCase().replace(/\s+/g, "-")}">${escapeHtml(c.action)}</span></div>
      <div class="pc-avail">${c.actions_available.map((a) => `<span class="avail-pill ${a === c.action ? "on" : ""}">${escapeHtml(a)}</span>`).join("")}</div>
    </div>`).join("");
}

function renderBaselineMgmt(b) {
  const stateLabel = { not_loaded: "Not Loaded", learning: "Learning", active: "Active", drift: "Drift Detected" }[b.state] || b.state;
  const stateColor = { not_loaded: "gray", learning: "blue", active: "green", drift: "yellow" }[b.state] || "gray";
  const active = b.active;
  const cand = b.candidate;
  const history = Array.isArray(b.history) ? b.history : [];

  const activeBlock = active
    ? `<div class="baseline-sub-card">
         <div class="bs-title">目前啟用 Baseline</div>
         <div class="sub">版本 <span class="mono">${escapeHtml(active.version || "—")}</span> · ${fmtTime(active.applied_at)}</div>
         <div class="sub">${active.goose} GOOSE publisher · ${active.mms} MMS IED · 來源 ${escapeHtml(active.source || "—")}</div>
       </div>`
    : `<div class="baseline-sub-card empty"><div class="sub">尚未套用任何 baseline。匯入一段「正常流量」pcap 開始學習。</div></div>`;

  const st = cand?.stats || {};
  const candBlock = cand
    ? `<div class="baseline-sub-card ${cand.pending ? "pending" : ""}">
         <div class="bs-title">候選 Baseline ${cand.pending ? badge("待核准", "blue") : badge("已套用", "green")}</div>
         <div class="sub">來源 <span class="mono">${escapeHtml(cand.source_ref || "—")}</span> · ${fmtTime(cand.generated_at)}</div>
         <div class="sub">${st.goose_publishers || 0} GOOSE · ${st.mms_ieds || 0} MMS IED · ${st.modbus_servers || 0} Modbus · ${st.packets || 0} 封包 · ${st.comm_pairs || 0} comm pairs</div>
         ${cand.pending ? `<div class="baseline-actions"><button type="button" class="btn btn-primary btn-sm" id="blApprove">核准並套用</button></div>` : ""}
       </div>`
    : "";

  const dsum = b.drift?.summary || { total: 0, added: 0, removed: 0, changed: 0 };
  const driftBlock = (b.state === "drift" && dsum.total > 0)
    ? `<div class="baseline-sub-card pending">
         <div class="bs-title">偵測到漂移 ${badge(`${dsum.total} 項`, "yellow")}</div>
         <div class="sub">新增 ${dsum.added} · 移除 ${dsum.removed} · 變更 ${dsum.changed} · live ${fmtTime(b.drift?.live_generated_at)}</div>
         <div class="baseline-actions">
           <button type="button" class="btn btn-ghost btn-sm" id="blDriftView">查看差異</button>
           <button type="button" class="btn btn-primary btn-sm" id="blApproveDrift">核准目前觀測為新基線</button>
         </div>
       </div>`
    : "";

  const historyBlock = history.length
    ? `<div class="baseline-sub-card">
         <div class="bs-title">版本歷史</div>
         <table class="baseline-history"><tbody>${history.map((v) => `
           <tr>
             <td class="mono">${escapeHtml(v.version || "—")}</td>
             <td>${fmtTime(v.applied_at)}</td>
             <td>${v.goose || 0}G · ${v.mms || 0}M</td>
             <td>${v.active ? badge("使用中", "green") : `<button type="button" class="btn btn-ghost btn-xs" data-rollback="${escapeHtml(v.version)}">回滾</button>`}</td>
           </tr>`).join("")}</tbody></table>
       </div>`
    : "";

  $("#baselineMgmtBody").innerHTML = `
    <div class="baseline-mgmt-top">
      <div>${badge(stateLabel, stateColor)}</div>
      <div class="sub">${active ? `${active.goose + active.mms} 已基線資產` : "未基線"}${cand?.pending ? " · 有候選待核准" : ""}</div>
    </div>
    ${activeBlock}
    ${candBlock}
    ${driftBlock}
    ${historyBlock}
    <div class="baseline-actions">
      <button type="button" class="btn btn-secondary btn-sm" id="blLearn">從 pcap 學習</button>
      <button type="button" class="btn btn-ghost btn-sm" id="blDrift">Compare Drift</button>
    </div>
    <input type="file" id="blPcapInput" accept=".pcap,.pcapng,.cap" hidden>
    <p class="hint">學習素材必須是「已知正常」的流量；含攻擊/異常的 pcap 會污染 baseline。建議上傳乾淨時段 5–15 分鐘擷取（≤ 100MB 即可，OT 身分很快就會完整）。Drift 比對 live 觀測 vs 目前基線（sensor 約每 60s 更新觀測）。</p>`;

  const approveBtn = $("#blApprove");
  if (approveBtn) approveBtn.addEventListener("click", () => approveBaseline(approveBtn));
  $("#blLearn").addEventListener("click", () => $("#blPcapInput").click());
  $("#blPcapInput").addEventListener("change", (e) => {
    const file = e.target.files?.[0];
    if (file) learnFromPcap(file);
    e.target.value = "";
  });
  $("#blDrift").addEventListener("click", () => showDrift());
  const driftViewBtn = $("#blDriftView");
  if (driftViewBtn) driftViewBtn.addEventListener("click", () => showDrift());
  const approveDriftBtn = $("#blApproveDrift");
  if (approveDriftBtn) approveDriftBtn.addEventListener("click", () => approveDrift(approveDriftBtn));
  $$("[data-rollback]").forEach((btn) => btn.addEventListener("click", () => rollbackBaseline(btn.dataset.rollback, btn)));
}

function driftListHtml(items, render) {
  if (!items || !items.length) return `<div class="sub muted">—</div>`;
  return `<ul class="drift-list">${items.map((it) => `<li>${render(it)}</li>`).join("")}</ul>`;
}

function renderDriftDrawer(d) {
  if (!d.has_active) return `<div class="sub">尚未套用任何基線，無可比對對象。</div>`;
  if (!d.has_live) return `<div class="sub">尚無 live 觀測快照（sensor 累積中，約每 60s 更新一次）。</div>`;
  if (d.summary.total === 0) return `<div class="sub">✓ 無漂移：live 觀測與目前基線一致。</div>`;
  const g = d.goose, m = d.mms;
  const gp = (e) => `${escapeHtml(e.publisher_mac || "")} · APPID ${e.appid} · ${escapeHtml(e.gocb_ref || "")}`;
  return `
    <div class="drift-section"><div class="bs-title">GOOSE Publisher</div>
      <div class="drift-grp"><span class="drift-tag add">新增 ${g.added.length}</span>${driftListHtml(g.added, gp)}</div>
      <div class="drift-grp"><span class="drift-tag rm">消失 ${g.removed.length}</span>${driftListHtml(g.removed, gp)}</div>
      <div class="drift-grp"><span class="drift-tag chg">變更 ${g.changed.length}</span>${driftListHtml(g.changed, (e) => `${gp(e)} → ${escapeHtml(JSON.stringify(e.changes))}`)}</div>
    </div>
    <div class="drift-section"><div class="bs-title">MMS IED</div>
      <div class="drift-grp"><span class="drift-tag add">新增 ${m.added.length}</span>${driftListHtml(m.added, (e) => `${escapeHtml(e.ied_ip || "")}（${(e.allowed_mms_clients || []).length} clients）`)}</div>
      <div class="drift-grp"><span class="drift-tag rm">消失 ${m.removed.length}</span>${driftListHtml(m.removed, (e) => escapeHtml(e.ied_ip || ""))}</div>
      <div class="drift-grp"><span class="drift-tag chg">客戶端變更 ${m.client_changes.length}</span>${driftListHtml(m.client_changes, (e) => `${escapeHtml(e.ied_ip)}：+[${e.added_clients.map(escapeHtml).join(", ")}] -[${e.removed_clients.map(escapeHtml).join(", ")}]`)}</div>
    </div>`;
}

async function showDrift() {
  openDrawer("Baseline Drift（live vs 目前基線）", stateBlock("loading"));
  try {
    const d = await api("/api/baseline/drift");
    openDrawer("Baseline Drift（live vs 目前基線）", renderDriftDrawer(d));
  } catch (err) {
    openDrawer("Baseline Drift", stateBlock("error", err.message));
  }
}

async function approveDrift(btn) {
  btn.disabled = true;
  try {
    const r = await api("/api/baseline/approve-drift", { method: "POST" });
    toast(`已將 live 觀測套用為新基線 ${r.version}（${r.goose} GOOSE · ${r.mms} MMS）`, true);
    await load();
  } catch (err) {
    toast(err.message, false);
    btn.disabled = false;
  }
}

async function learnFromPcap(file) {
  const sizeMB = file.size / 1048576;
  if (sizeMB > 100 && !confirm(`此 pcap 約 ${sizeMB.toFixed(0)}MB，較大的擷取在 Pi 上解析較久（可能套用封包上限）。仍要繼續嗎？`)) return;
  const btn = $("#blLearn");
  btn.disabled = true;
  const original = btn.textContent;
  btn.textContent = `學習中…（${sizeMB.toFixed(1)}MB）`;
  try {
    const buf = await file.arrayBuffer();
    const resp = await fetch(`/api/baseline/learn?filename=${encodeURIComponent(file.name)}`, {
      method: "POST",
      body: buf,
      headers: { "Content-Type": "application/octet-stream" },
      credentials: "same-origin",
    });
    if (!resp.ok) {
      const detail = await resp.json().catch(() => ({}));
      throw new Error(detail.detail || `學習失敗（${resp.status}）`);
    }
    const data = await resp.json();
    const s = data.candidate?.stats || {};
    const capped = data.auto_limited ? `（已套用封包上限 ${data.packet_limit}）` : "";
    toast(`學習完成：${s.goose_publishers || 0} GOOSE · ${s.mms_ieds || 0} MMS · ${s.packets || 0} 封包${capped}`, true);
    await load();
  } catch (err) {
    toast(err.message, false);
  } finally {
    btn.disabled = false;
    btn.textContent = original;
  }
}

async function approveBaseline(btn) {
  btn.disabled = true;
  try {
    const r = await api("/api/baseline/approve", { method: "POST" });
    toast(`已套用 baseline ${r.version}（${r.goose} GOOSE · ${r.mms} MMS）`, true);
    await load();
  } catch (err) {
    toast(err.message, false);
    btn.disabled = false;
  }
}

async function rollbackBaseline(version, btn) {
  btn.disabled = true;
  try {
    const r = await api("/api/baseline/rollback", { method: "POST", body: JSON.stringify({ version }) });
    toast(`已回滾並套用 ${r.version}`, true);
    await load();
  } catch (err) {
    toast(err.message, false);
    btn.disabled = false;
  }
}

const RULE_LABELS = {
  "OT-001": "新 MAC 出現", "OT-002": "新 IP 出現", "OT-003": "MAC-IP 綁定異常",
  "OT-004": "新通訊對", "OT-005": "新目的埠", "OT-006": "埠掃描行為",
  "OT-007": "非預期 Modbus 寫入", "OT-008": "異常流量速率", "OT-009": "Relay 離線",
  "OT-010": "未授權主機存取 Relay", "OT-011": "新 GOOSE publisher", "OT-012": "GOOSE test bit（正式環境）",
  "OT-013": "GOOSE stNum 異常", "OT-014": "新 MMS 客戶端連線 IED", "OT-015": "MMS 連線速率異常",
  "OT-016": "非預期 MMS 寫入", "OT-017": "GOOSE 靜默（IED 離線）", "OT-018": "未授權 MMS 存取 Relay IED",
  "OT-019": "CTI IoC 命中",
};

function ruleEntries(data) {
  if (Array.isArray(data.rule_entries) && data.rule_entries.length) return data.rule_entries;
  return (data.rules_enabled || []).map((rid) => {
    const id = String(rid).trim().toUpperCase();
    return { rule_id: id, label_zh: RULE_LABELS[id] || id };
  });
}

function renderApplied(data) {
  const body = $("#appliedBody");
  if (!data || !data.loaded) {
    body.innerHTML = stateBlock("empty", data?.fallback?.note || data?.error || "尚未載入 Portal 下發政策");
    return;
  }
  const entries = ruleEntries(data);
  const sourceLabel = { mqtt: "MQTT", file: "本機檔案" }[String(data.source || "").toLowerCase()] || (data.source || "—");
  const rules = entries.length
    ? `<table class="policy-rules-table"><thead><tr><th>Rule ID</th><th>名稱</th></tr></thead><tbody>${entries.map((e) =>
        `<tr><td class="mono">${escapeHtml(e.rule_id)}</td><td>${escapeHtml(e.label_zh || e.rule_id)}</td></tr>`).join("")}</tbody></table>`
    : `<p class="hint muted">尚無已啟用規則</p>`;
  body.innerHTML = `
    <div class="policy-kv-grid">
      <div class="policy-kv"><span class="policy-k">版本</span><span class="policy-v mono">${escapeHtml(data.version || "—")}</span></div>
      <div class="policy-kv"><span class="policy-k">更新時間</span><span class="policy-v mono">${fmtTime(data.updated_at)}</span></div>
      <div class="policy-kv"><span class="policy-k">來源</span><span class="policy-v">${escapeHtml(sourceLabel)}</span></div>
      <div class="policy-kv"><span class="policy-k">租戶</span><span class="policy-v">${copyField(data.tenant_id || "—")}</span></div>
      <div class="policy-kv"><span class="policy-k">Site</span><span class="policy-v mono">${escapeHtml(data.site_id || "（全站預設）")}</span></div>
      <div class="policy-kv"><span class="policy-k">已啟用規則</span><span class="policy-v mono">${data.rules_count ?? entries.length} 條</span></div>
    </div>
    <div class="policy-rules-table-wrap" style="margin-top:0.75rem">${rules}</div>`;
}
