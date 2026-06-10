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

export function navigate(name) {
  window.dispatchEvent(new CustomEvent("edge:navigate", { detail: { name } }));
}
