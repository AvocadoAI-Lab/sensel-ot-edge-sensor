// 即時流量 — Mirror capture telemetry, packet-rate chart, top talkers, lab traffic.
import { $, $$, toast, escapeHtml, setText } from "../core/dom.js";
import { api } from "../core/api.js";
import { fmtTime, formatRate } from "../core/format.js";
import { dot, stateBlock } from "../ui/components.js";

export const meta = { title: "即時流量", sub: "Mirror 埠鏡像 · Telemetry Flow" };

const BRAND = { lime: "#d8f25a", limeFill: "rgba(216,242,90,0.14)", grid: "rgba(221,234,242,0.08)", muted: "#8fa3b8" };
const HISTORY_MAX = 60;
const rateHistory = [];
let trafficTimer = null, labTimer = null;

export function render(root) {
  root.innerHTML = `
    <section class="page">
      <div class="traffic-header">
        <p class="hint" style="margin:0">Mirror 埠鏡像擷取 · packet-sensor 每秒更新</p>
        <div class="traffic-status"><span id="trafficLiveDot" class="status-dot unk"></span><span id="trafficLiveLabel" class="mono">連線中…</span></div>
      </div>

      <div id="labTrafficPanel" class="lab-traffic-panel card-ot hidden" style="margin-top:1rem">
        <div class="lab-traffic-head"><div>
          <div class="title">Lab 流量模擬 <span class="lab-badge">僅 PoC</span></div>
          <p class="hint lab-traffic-hint">本機 GOOSE/MMS publisher，非外部 SPAN。</p>
        </div></div>
        <div id="labTrafficCards" class="lab-traffic-cards"></div>
        <div id="labTrafficPresets" class="lab-traffic-presets"></div>
        <p id="labTrafficMsg" class="hint muted" style="margin:0.5rem 0 0"></p>
      </div>

      <div class="traffic-meta card-ot" style="margin-top:1rem">
        <div class="sub">介面 <span id="trafficIface" class="mono">—</span> · 後端 <span id="trafficBackend" class="mono">—</span> · BPF <span id="trafficBpf" class="mono">—</span></div>
      </div>

      <div id="trafficMetrics" class="grid-4" style="margin-top:1rem">${stateBlock("loading")}</div>

      <div class="traffic-chart-wrap card-ot" style="margin-top:1rem">
        <div class="title">Telemetry Flow · 封包速率 (pkt/s)</div>
        <canvas id="trafficRateChart" width="900" height="120" aria-label="封包速率圖表"></canvas>
      </div>

      <div class="grid-2" style="margin-top:1rem">
        <div class="card-ot"><div class="title">視窗 Top MAC</div><div id="trafficTopMacs" class="traffic-list muted">尚無資料</div></div>
        <div class="card-ot"><div class="title">Top 來源 IP</div><div id="trafficTopIps" class="traffic-list muted">尚無資料</div></div>
      </div>

      <div class="table-wrap" style="margin-top:1rem">
        <div class="title" style="margin-bottom:0.5rem;color:var(--text-muted);font-size:0.82rem">最近封包</div>
        <table><thead><tr><th>時間</th><th>協定</th><th>來源 MAC</th><th>來源 IP</th><th>目的 IP</th><th>大小</th></tr></thead>
        <tbody id="trafficRecentRows"></tbody></table>
      </div>
    </section>`;

  $("#labTrafficPanel").addEventListener("click", onLabClick);
  start();
}

export function leave() { stop(); }
export function onVisible() { loadTraffic().catch(() => {}); }

function start() {
  stop();
  loadTraffic().catch((e) => showError(e.message));
  loadLab().catch(() => {});
  trafficTimer = setInterval(() => { if (!document.hidden) loadTraffic().catch(() => {}); }, 3000);
  labTimer = setInterval(() => { if (!document.hidden) loadLab().catch(() => {}); }, 10000);
}
function stop() { clearInterval(trafficTimer); clearInterval(labTimer); trafficTimer = labTimer = null; }

function showError(msg) {
  const box = $("#trafficMetrics");
  if (box) box.innerHTML = stateBlock("error", msg || "無法載入流量");
}

function protoClass(p) {
  const s = String(p || "").toUpperCase();
  if (s.includes("GOOSE")) return "proto-goose";
  if (s.includes("MMS")) return "proto-mms";
  return "";
}

async function loadTraffic() {
  let data;
  try { data = await api("/api/traffic/live"); } catch (e) { showError(e.message); return; }
  const live = data.live === true;
  const d = $("#trafficLiveDot"), l = $("#trafficLiveLabel");
  if (d) d.className = `status-dot ${live ? "ok" : data.stale ? "bad" : "unk"}`;
  if (l) l.textContent = live ? `即時 · ${data.age_sec ?? 0}s 前更新` : (data.message || "資料過期或未連線");

  setText("#trafficIface", data.capture_interface || "—");
  setText("#trafficBackend", data.capture_backend || "—");
  const bpf = data.capture_bpf || "";
  setText("#trafficBpf", bpf.length > 72 ? `${bpf.slice(0, 72)}…` : bpf || "—");

  const m = data.metrics || {};
  rateHistory.push(Number(m.instant_rate) || 0);
  if (rateHistory.length > HISTORY_MAX) rateHistory.shift();
  drawChart();

  const idle = m.idle_sec != null ? `${m.idle_sec}s` : "—";
  const cards = [
    ["即時速率", `<span class="traffic-rate-big">${formatRate(m.instant_rate)}</span><span class="sub"> pkt/s</span>`, ""],
    ["平均速率", `${formatRate(m.packet_rate)} pkt/s`, `累計 ${m.total_packets ?? 0}`],
    ["視窗封包", `${m.window_packets ?? 0}`, `IPv4 ${m.ipv4_packets ?? 0} · IPv6 ${m.ipv6_packets ?? 0}`],
    ["IEC 61850", `GOOSE ${m.goose_messages ?? 0}`, `MMS 寫 ${m.mms_writes ?? 0} · 連線 ${m.mms_sessions ?? 0}`],
    ["資產指紋", `${m.unique_macs ?? 0} MAC`, `${m.unique_ips ?? 0} IP · 閒置 ${idle}`],
    ["執行時間", `${Math.round(m.elapsed_sec ?? 0)}s`, `IoC 條目 ${m.ioc_entries ?? 0}`],
  ].map(([t, v, s]) => `<div class="card card-ot"><div class="title">${t}</div><div class="value">${v}</div>${s ? `<div class="sub">${s}</div>` : ""}</div>`).join("");
  const box = $("#trafficMetrics");
  if (box) box.innerHTML = (!live ? `<div class="card card-ot traffic-alert warn" style="grid-column:1/-1"><div class="value">${escapeHtml(data.message || "等待 Packet Sensor 寫入")}</div></div>` : "") + cards;

  renderTopList($("#trafficTopMacs"), data.top_macs || [], "mac");
  renderTopList($("#trafficTopIps"), data.top_ips || [], "ip");
  renderRecent(data.recent_packets || []);
}

function renderTopList(el, items, key) {
  if (!el) return;
  if (!items.length) { el.innerHTML = '<span class="muted">尚無資料</span>'; el.classList.add("muted"); return; }
  el.classList.remove("muted");
  el.innerHTML = items.map((it) => `<div class="row"><span class="mono">${escapeHtml(it[key] || "—")}</span><span>${it.count}</span></div>`).join("");
}

function renderRecent(packets) {
  const rows = $("#trafficRecentRows");
  if (!rows) return;
  if (!packets.length) { rows.innerHTML = `<tr><td colspan="6" class="hint">尚無封包</td></tr>`; return; }
  rows.innerHTML = packets.slice(0, 30).map((p) =>
    `<tr><td class="mono">${escapeHtml(p.at || "")}</td><td><span class="rule-chip ${protoClass(p.proto)}">${escapeHtml(p.proto || "—")}</span></td>
     <td class="mono">${escapeHtml(p.src_mac || "—")}</td><td class="mono">${escapeHtml(p.src_ip || "—")}</td>
     <td class="mono">${escapeHtml(p.dst_ip || "—")}</td><td class="mono">${p.size || 0} B</td></tr>`).join("");
}

function drawChart() {
  const canvas = $("#trafficRateChart");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  const w = Math.max(rect.width, 300), h = 120;
  canvas.width = w * dpr; canvas.height = h * dpr;
  ctx.setTransform(1, 0, 0, 1, 0, 0); ctx.scale(dpr, dpr); ctx.clearRect(0, 0, w, h);
  const data = rateHistory;
  if (data.length < 2) { ctx.fillStyle = BRAND.muted; ctx.font = "12px Poppins, sans-serif"; ctx.fillText("等待流量資料…", 12, h / 2); return; }
  const max = Math.max(...data, 1), pad = 8, iw = w - pad * 2, ih = h - pad * 2;
  const step = iw / Math.max(data.length - 1, 1);
  ctx.strokeStyle = BRAND.grid; ctx.lineWidth = 1;
  for (let i = 0; i <= 3; i++) { const y = pad + (ih * i) / 3; ctx.beginPath(); ctx.moveTo(pad, y); ctx.lineTo(w - pad, y); ctx.stroke(); }
  ctx.beginPath(); ctx.strokeStyle = BRAND.lime; ctx.lineWidth = 2; ctx.shadowColor = BRAND.lime; ctx.shadowBlur = 8;
  data.forEach((v, i) => { const x = pad + i * step, y = pad + ih - (v / max) * ih; i ? ctx.lineTo(x, y) : ctx.moveTo(x, y); });
  ctx.stroke(); ctx.shadowBlur = 0;
  ctx.lineTo(pad + (data.length - 1) * step, pad + ih); ctx.lineTo(pad, pad + ih); ctx.closePath();
  ctx.fillStyle = BRAND.limeFill; ctx.fill();
  ctx.fillStyle = BRAND.muted; ctx.font = "11px IBM Plex Mono, monospace";
  ctx.fillText(`${formatRate(max)} pkt/s`, pad, 14);
  ctx.fillText(`${formatRate(data[data.length - 1])} now`, w - pad - 70, 14);
}

// ---- Lab traffic (ported) --------------------------------------------------
function labDot(running, exists) { return !exists ? "bad" : running ? "ok" : "unk"; }
function labLabel(running, exists, status) { return !exists ? "未部署" : running ? "運行中" : status === "exited" ? "已停止" : status || "—"; }

function labCard(item, dockerOk) {
  const disabled = !dockerOk ? "disabled" : "";
  const toggleAction = item.running ? "stop" : "start";
  const restartBtn = item.id === "capture" ? `<button type="button" class="btn btn-sm btn-ghost" data-lab-action="restart" data-lab-target="capture" ${disabled}>重啟</button>` : "";
  return `<div class="lab-card"><div class="lab-card-title">${escapeHtml(item.label || item.id)}</div>
    <div class="lab-card-status"><span class="status-dot ${labDot(item.running, item.exists !== false)}"></span><span>${labLabel(item.running, item.exists !== false, item.status)}</span></div>
    <div class="lab-card-sub mono">${escapeHtml(item.summary || item.interface || item.bpf_filter || "—")}</div>
    <div class="lab-card-actions"><button type="button" class="btn btn-sm" data-lab-action="${toggleAction}" data-lab-target="${item.id}" ${disabled}>${item.running ? "暫停" : "開始"}</button>${restartBtn}</div></div>`;
}

async function loadLab() {
  let data;
  try { data = await api("/api/lab/traffic/status"); } catch { return; }
  const panel = $("#labTrafficPanel");
  if (!panel) return;
  if (!data?.enabled) { panel.classList.add("hidden"); return; }
  panel.classList.remove("hidden");
  const dockerOk = data.docker_control_enabled === true;
  setText("#labTrafficMsg", dockerOk ? "" : "Docker 控制已停用或無 socket（EDGE_CONSOLE_DOCKER_RESTART=1）");
  const pub = (data.publishers || []).map((p) => labCard(p, dockerOk)).join("");
  const cap = data.capture ? labCard({ ...data.capture, id: "capture" }, dockerOk) : "";
  $("#labTrafficCards").innerHTML = pub + cap;
  $("#labTrafficPresets").innerHTML = (data.presets || []).map((p) => `<button type="button" class="btn btn-sm btn-ghost" data-lab-preset="${p.id}" ${!dockerOk ? "disabled" : ""}>${escapeHtml(p.label)}</button>`).join("");
}

async function onLabClick(ev) {
  const presetBtn = ev.target.closest("[data-lab-preset]");
  if (presetBtn && !presetBtn.disabled) {
    try { const r = await api("/api/lab/traffic/actions", { method: "POST", body: JSON.stringify({ preset: presetBtn.dataset.labPreset }) }); toast(r.ok ? "快捷已套用" : "部分失敗", !!r.ok); await Promise.all([loadLab(), loadTraffic()]); }
    catch (e) { toast(e.message, false); }
    return;
  }
  const btn = ev.target.closest("[data-lab-action]");
  if (!btn || btn.disabled) return;
  try {
    const r = await api("/api/lab/traffic/actions", { method: "POST", body: JSON.stringify({ action: btn.dataset.labAction, targets: [btn.dataset.labTarget] }) });
    toast(r.ok ? "已套用" : "部分失敗", !!r.ok);
    await Promise.all([loadLab(), loadTraffic()]);
  } catch (e) { toast(e.message, false); }
}
