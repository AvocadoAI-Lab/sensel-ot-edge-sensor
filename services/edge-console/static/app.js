// SenseL OT Edge Runtime + Security Validation Console — module entry/router.
import { $, $$, toast } from "./core/dom.js";
import { api } from "./core/api.js";
import { startClock } from "./core/format.js";
import { initComponents } from "./ui/components.js";
import { setHeader, setConsoleMode, updateOperationalModeBadge } from "./core/shell.js";

import * as dashboard from "./pages/dashboard.js";
import * as guide from "./pages/guide.js";
import * as runtime from "./pages/runtime.js";
import * as assets from "./pages/assets.js";
import * as setup from "./pages/setup.js";
import * as events from "./pages/events.js";
import * as policy from "./pages/policy.js";
import * as policyIt from "./pages/policy-it.js";
import * as traffic from "./pages/traffic.js";
import * as ops from "./pages/ops.js";
import * as vpn from "./pages/vpn.js";

const PAGES = { dashboard, guide, runtime, assets, setup, events, policy, traffic, ops, vpn };

function policyPage() {
  return consoleMode === "it"
    ? { meta: policyIt.meta, render: policyIt.renderIt, leave: () => {} }
    : policy;
}

function resolvePage(name) {
  if (name === "policy") return policyPage();
  return PAGES[name];
}

const NAV = [
  { id: "dashboard", icon: "◉", label: "總覽" },
  { id: "guide", icon: "📖", label: "操作手冊" },
  { id: "runtime", icon: "⬡", label: "Edge Runtime" },
  { id: "assets", icon: "🏭", label: "資產與協定" },
  { id: "setup", icon: "✦", label: "接入精靈" },
  { id: "events", icon: "⚠", label: "安全事件" },
  { id: "policy", icon: "🛡", label: "偵測與政策" },
  { id: "traffic", icon: "〰", label: "即時流量" },
  { id: "vpn", icon: "🔒", label: "VPN 連線" },
  { id: "ops", icon: "⚙", label: "系統維運" },
];

const IT_NDR_NAV_IDS = new Set(["dashboard", "setup", "events", "policy", "traffic", "vpn", "ops"]);
let consoleMode = "ot";

const NDR_LOGO = "/assets/brand/logo-ndr.png";
const OT_LOGO = "/assets/brand/logo-horizontal.jpg";

function applyConsoleMode(mode) {
  consoleMode = mode === "it" ? "it" : "ot";
  setConsoleMode(consoleMode);
  const isIt = consoleMode === "it";
  document.documentElement.classList.toggle("ndr-it-mode", isIt);
  document.body.classList.toggle("ndr-it-mode", isIt);
  const themeLink = $("#ndrItTheme");
  if (themeLink) themeLink.disabled = !isIt;
  if (isIt) {
    document.title = "SenseL IT NDR Console";
    applyNdrBranding();
  } else {
    document.title = "SenseL OT Edge Console";
    $$(".sidebar-logo-horizontal, .login-logo").forEach((img) => {
      img.src = OT_LOGO;
      img.alt = "SenseL EdgeX by AvocadoAI";
    });
    const tag = $(".login-tagline");
    if (tag) tag.textContent = "OT Edge Runtime · Telemetry Pipeline · Security Validation";
    $("#ndrProfileBadge")?.remove();
  }
}

function applyNdrBranding() {
  $$(".sidebar-logo-horizontal, .login-logo").forEach((img) => {
    img.src = NDR_LOGO;
    img.alt = "SenseL NDR";
    img.classList.add("logo-ndr");
  });
  const tag = $(".login-tagline");
  if (tag) tag.textContent = "IT Network Detection & Response · Suricata Edge Sensor";
  const brand = $(".sidebar-brand");
  if (brand && !$("#ndrProfileBadge")) {
    const badge = document.createElement("span");
    badge.id = "ndrProfileBadge";
    badge.className = "ndr-profile-badge";
    badge.textContent = "IT NDR · 部署固定";
    brand.appendChild(badge);
  }
  const avatar = $("#headerAvatar");
  if (avatar) avatar.textContent = "ND";
}

function navItems() {
  return consoleMode === "it" ? NAV.filter((n) => IT_NDR_NAV_IDS.has(n.id)) : NAV;
}

let currentName = null;
let currentPage = null;

function renderNav() {
  const nav = $("#sidebarNav");
  if (!nav) return;
  nav.innerHTML = navItems().map((n) => `
    <button type="button" class="nav-item" data-tab="${n.id}" title="${n.label}">
      <span class="nav-icon" aria-hidden="true">${n.icon}</span>
      <span class="nav-label">${n.label}</span>
    </button>`).join("");
  $$(".nav-item[data-tab]", nav).forEach((btn) => {
    btn.addEventListener("click", () => setTab(btn.dataset.tab));
  });
}

function setTab(name) {
  if (!resolvePage(name)) name = "dashboard";
  if (name === currentName) return;
  try { currentPage?.leave?.(); } catch {}
  currentName = name;
  currentPage = resolvePage(name);
  $$(".nav-item[data-tab]").forEach((t) => t.classList.toggle("active", t.dataset.tab === name));
  const meta = currentPage.meta || { title: name, sub: "" };
  setHeader(meta.title, meta.sub);
  const root = $("#viewRoot");
  root.innerHTML = "";
  try {
    currentPage.render(root);
  } catch (e) {
    root.innerHTML = `<section class="page panel"><div class="card-state is-error">頁面載入失敗：${e.message}</div></section>`;
  }
}

function showLogin() {
  $("#loginView")?.classList.remove("hidden");
  $("#appView")?.classList.add("hidden");
}
function showApp() {
  $("#loginView")?.classList.add("hidden");
  $("#appView")?.classList.remove("hidden");
}

async function initBranding() {
  try {
    const b = await fetch("/api/branding").then((r) => r.json());
    if (b?.mode === "it_ndr") applyConsoleMode("it");
  } catch { /* static fallback: config in boot() */ }
}

async function boot() {
  await initBranding();
  const auth = await fetch("/api/auth/status").then((r) => r.json()).catch(() => ({}));
  if (auth.password_required && !auth.authenticated) {
    showLogin();
    return;
  }
  showApp();
  let cfg = {};
  try { cfg = await api("/api/config"); } catch {}
  const profile = (cfg.ndr_profile || "").toLowerCase();
  if (profile === "it_ndr" || (cfg.sensor_type || "").startsWith("it-ndr")) applyConsoleMode("it");
  renderNav();
  if (!cfg.configured) setTab("setup");
  else setTab("dashboard");
}

function wireShell() {
  renderNav();
  startClock();
  initComponents();
  refreshOperationalModeBadge();
  setInterval(() => {
    if (!document.hidden) refreshOperationalModeBadge();
  }, 30000);

  $("#loginBtn")?.addEventListener("click", async () => {
    try {
      await api("/api/auth/login", { method: "POST", body: JSON.stringify({ password: $("#loginPassword").value }) });
      await boot();
    } catch (e) { toast(e.message, false); }
  });
  $("#loginPassword")?.addEventListener("keydown", (e) => { if (e.key === "Enter") $("#loginBtn")?.click(); });
  $("#logoutBtn")?.addEventListener("click", async () => {
    try { await api("/api/auth/logout", { method: "POST" }); } catch {}
    showLogin();
  });
  $("#sidebarToggle")?.addEventListener("click", () => $("#appView")?.classList.toggle("sidebar-collapsed"));
  $("#headerAddDeviceBtn")?.addEventListener("click", () => {
    setTab("assets");
    window.dispatchEvent(new CustomEvent("edge:assets:add-device"));
  });

  window.addEventListener("edge:navigate", (e) => setTab(e.detail?.name));
  window.addEventListener("edge:unauthorized", () => showLogin());
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden && currentPage?.onVisible) currentPage.onVisible();
  });
}

async function refreshOperationalModeBadge() {
  try {
    const status = await api("/api/status");
    updateOperationalModeBadge(status.operational_mode || {});
  } catch {}
}

wireShell();
boot().catch(() => showLogin());
