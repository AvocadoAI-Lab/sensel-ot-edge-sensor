// Reusable UI primitives (pure string/DOM builders) used across pages.
import { truncate as _truncate, copyToClipboard } from "../core/format.js";
import { escapeHtml, toast } from "../core/dom.js";

export const STATE_LABEL = {
  green: "正常", yellow: "降級", red: "異常", blue: "學習/同步中", gray: "停用",
};

export function dot(state) {
  return `<span class="status-dot ${state || "gray"}"></span>`;
}

export function badge(text, state = "gray") {
  return `<span class="state-badge ${state}">${dot(state)}${escapeHtml(text)}</span>`;
}

// Non-ready card states: loading | empty | error | degraded.
export function stateBlock(state, message) {
  const map = {
    loading: { icon: "◌", cls: "is-loading", text: message || "載入中…" },
    empty: { icon: "∅", cls: "is-empty", text: message || "尚無資料" },
    error: { icon: "⚠", cls: "is-error", text: message || "載入失敗" },
    degraded: { icon: "▲", cls: "is-degraded", text: message || "資料降級或過期" },
  };
  const s = map[state] || map.loading;
  return `<div class="card-state ${s.cls}"><span class="card-state-icon">${s.icon}</span><span>${escapeHtml(s.text)}</span></div>`;
}

// Truncated value with tooltip + copy button. Used for tenant id / URL / topic / ts.
export function copyField(value, { mono = true, max = 28 } = {}) {
  const full = String(value ?? "");
  if (!full || full === "—") return `<span class="muted">—</span>`;
  const shown = _truncate(full, max);
  return `<span class="copy-field ${mono ? "mono" : ""}" title="${escapeHtml(full)}">${escapeHtml(shown)}<button type="button" class="copy-btn" data-copy="${escapeHtml(full)}" title="複製" aria-label="複製">⧉</button></span>`;
}

export function gauge(percent, label, sublabel) {
  const pct = Math.max(0, Math.min(100, Number(percent) || 0));
  const C = 2 * Math.PI * 48;
  const cls = pct >= 85 ? "green" : pct >= 50 ? "yellow" : "red";
  return `
    <div class="gauge-wrap">
      <svg viewBox="0 0 120 120" class="gauge-svg ${cls}" aria-hidden="true">
        <circle cx="60" cy="60" r="48" class="gauge-track"></circle>
        <circle cx="60" cy="60" r="48" class="gauge-fill" stroke-dasharray="${(C * pct) / 100} ${C}"></circle>
      </svg>
      <div class="gauge-center">
        <span class="gauge-pct">${Math.round(pct)}</span>
        <span class="gauge-label">${escapeHtml(label || "")}</span>
      </div>
    </div>
    ${sublabel ? `<div class="gauge-sub">${escapeHtml(sublabel)}</div>` : ""}`;
}

export function sparkline(canvas, data, color = "#d8f25a") {
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  const w = Math.max(rect.width, 120), h = canvas.dataset.h ? +canvas.dataset.h : 56;
  canvas.width = w * dpr; canvas.height = h * dpr;
  ctx.setTransform(1, 0, 0, 1, 0, 0); ctx.scale(dpr, dpr); ctx.clearRect(0, 0, w, h);
  if (!data || data.length < 2) {
    ctx.fillStyle = "#8fa3b8"; ctx.font = "11px Poppins, sans-serif";
    ctx.fillText("等待資料…", 8, h / 2); return;
  }
  const max = Math.max(...data, 1), pad = 6, iw = w - pad * 2, ih = h - pad * 2;
  const step = iw / Math.max(data.length - 1, 1);
  ctx.beginPath(); ctx.strokeStyle = color; ctx.lineWidth = 2;
  data.forEach((v, i) => {
    const x = pad + i * step, y = pad + ih - (v / max) * ih;
    i ? ctx.lineTo(x, y) : ctx.moveTo(x, y);
  });
  ctx.stroke();
}

// Horizontal pipeline flow: [{label, state, detail, hint}]
// Links animate a flowing dot when data is healthy through that segment, and
// stall (red) otherwise. Non-green nodes with a hint get a ⚠ button whose
// data-* payload the caller can surface (e.g. open a drawer with the detail).
export function pipeline(nodes) {
  return `<div class="pipeline">${nodes.map((n, i) => {
    const next = nodes[i + 1];
    const flowing = n.state === "green" && next && (next.state === "green" || next.state === "blue");
    const bad = n.state && n.state !== "green" && n.state !== "blue";
    const alert = bad && n.hint
      ? `<button type="button" class="pipeline-alert" data-pipeline-hint="${escapeHtml(n.hint)}" data-pipeline-title="${escapeHtml(n.label)}" title="檢視問題" aria-label="檢視問題">⚠</button>`
      : "";
    const link = i < nodes.length - 1
      ? `<div class="pipeline-link ${flowing ? "flowing" : "stalled"}" aria-hidden="true"></div>`
      : "";
    return `
    <div class="pipeline-node ${n.state || "gray"}">
      <div class="pipeline-node-head">${dot(n.state)}${alert}</div>
      <div class="pipeline-label">${escapeHtml(n.label)}</div>
      ${n.detail ? `<div class="pipeline-detail mono">${escapeHtml(n.detail)}</div>` : ""}
    </div>${link}`;
  }).join("")}</div>`;
}

// Fixed-layout dependency graph for the 6 EdgeX nodes.
const GRAPH_POS = {
  "core-keeper": [60, 105], "mqtt-broker": [60, 185],
  "core-metadata": [185, 50], "core-data": [185, 130],
  "device-mqtt": [320, 60], "northbound-mqtt": [320, 165],
};
export function depGraph(graph) {
  const idMap = Object.fromEntries((graph.nodes || []).map((n) => [n.id, n]));
  const edges = (graph.edges || []).map((e) => {
    const a = GRAPH_POS[e.from], b = GRAPH_POS[e.to];
    if (!a || !b) return "";
    return `<line x1="${a[0]}" y1="${a[1]}" x2="${b[0]}" y2="${b[1]}" class="dep-edge" />`;
  }).join("");
  const nodes = (graph.nodes || []).map((n) => {
    const p = GRAPH_POS[n.id]; if (!p) return "";
    const [x, y] = p;
    return `<g class="dep-node ${n.state || "gray"}" transform="translate(${x - 56},${y - 16})">
      <rect width="112" height="32" rx="8" class="dep-rect" />
      <circle cx="14" cy="16" r="4" class="dep-dot" />
      <text x="26" y="20" class="dep-text">${escapeHtml(n.label || n.id)}</text>
    </g>`;
  }).join("");
  return `<svg viewBox="0 0 400 220" class="dep-graph" role="img" aria-label="服務依賴圖">${edges}${nodes}</svg>`;
}

export function signalBars(sig) {
  const n = sig >= 75 ? 4 : sig >= 55 ? 3 : sig >= 35 ? 2 : sig >= 15 ? 1 : 0;
  return "▮".repeat(n) + "▯".repeat(4 - n);
}

// Right-side drawer (single shared instance).
export function openDrawer(title, contentHtml) {
  let drawer = document.querySelector("#appDrawer");
  if (!drawer) {
    drawer = document.createElement("div");
    drawer.id = "appDrawer";
    drawer.className = "drawer-overlay";
    drawer.innerHTML = `<div class="drawer-panel"><div class="drawer-head"><h3 class="drawer-title"></h3><button type="button" class="drawer-close" aria-label="關閉">✕</button></div><div class="drawer-body"></div></div>`;
    document.body.appendChild(drawer);
    drawer.addEventListener("click", (e) => {
      if (e.target === drawer || e.target.closest(".drawer-close")) drawer.classList.remove("open");
    });
  }
  drawer.querySelector(".drawer-title").textContent = title;
  drawer.querySelector(".drawer-body").innerHTML = contentHtml;
  requestAnimationFrame(() => drawer.classList.add("open"));
  return drawer;
}

// Global delegation for copy buttons (call once at boot).
export function initComponents() {
  document.addEventListener("click", async (e) => {
    const btn = e.target.closest(".copy-btn");
    if (!btn) return;
    e.stopPropagation();
    const ok = await copyToClipboard(btn.dataset.copy || "");
    toast(ok ? "已複製" : "複製失敗", ok);
  });
}
