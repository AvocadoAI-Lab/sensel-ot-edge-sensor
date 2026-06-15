// Shell helpers shared between the router (app.js) and pages, without coupling
// pages to the router. Pages call navigate()/setSensorMeta()/updateShield().

import { $ } from "./dom.js";

export function setHeader(title, sub) {
  const t = $("#pageTitle");
  const s = $("#pageSubtitle");
  if (t) t.textContent = title;
  if (s && !s.dataset.sensorBound) s.textContent = sub;
}

export function setSensorMeta(sensorId, siteId) {
  const sub = $("#pageSubtitle");
  if (sub && sensorId) {
    sub.textContent = `${sensorId} @ ${siteId || "—"}`;
    sub.dataset.sensorBound = "1";
  }
  const avatar = $("#headerAvatar");
  if (avatar && sensorId) {
    const parts = String(sensorId).split(/[-_]/).filter(Boolean);
    avatar.textContent = parts.length >= 2
      ? (parts[0][0] + parts[1][0]).toUpperCase()
      : String(sensorId).slice(0, 2).toUpperCase();
    avatar.title = sensorId;
  }
}

export function updateShield(state) {
  const shield = $("#headerShield");
  if (!shield) return;
  if (state === "green" || state === true) {
    shield.className = "header-shield ok";
    shield.title = "Baseline 已載入";
  } else if (state === "red" || state === false) {
    shield.className = "header-shield bad";
    shield.title = "Baseline 未就緒";
  } else {
    shield.className = "header-shield";
    shield.title = "Policy / Baseline";
  }
}

const MODE_BADGE = {
  listen: { label: "聆聽中", className: "listen" },
  learning: { label: "學習中", className: "learning" },
  detect: { label: "偵測中", className: "detect" },
  idle: { label: "空閒", className: "idle" },
};

export function updateOperationalModeBadge(info) {
  const badge = $("#headerModeBadge");
  if (!badge) return;
  const mode = String(info?.operational_mode || "idle").toLowerCase();
  const ui = MODE_BADGE[mode] || MODE_BADGE.idle;
  badge.className = `header-mode-badge ${ui.className}`;
  badge.textContent = ui.label;
  const parts = [ui.label];
  if (info?.capture_interface) parts.push(info.capture_interface);
  if (info?.session_id) parts.push(String(info.session_id).slice(0, 8));
  if (info?.interrupt_hint) parts.push("上次學習已中斷");
  badge.title = info?.cloud_controlled ? `雲端控制 · ${parts.join(" · ")}` : parts.join(" · ");
}

export function navigate(name) {
  window.dispatchEvent(new CustomEvent("edge:navigate", { detail: { name } }));
}
