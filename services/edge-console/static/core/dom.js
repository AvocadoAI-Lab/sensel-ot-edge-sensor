// DOM utilities shared across pages.

export const $ = (sel, root = document) => root.querySelector(sel);
export const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

export function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null) continue;
    if (k === "class") node.className = v;
    else if (k === "html") node.innerHTML = v;
    else if (k === "text") node.textContent = v;
    else if (k.startsWith("on") && typeof v === "function") node.addEventListener(k.slice(2).toLowerCase(), v);
    else if (k === "dataset") Object.assign(node.dataset, v);
    else node.setAttribute(k, v);
  }
  for (const c of children.flat()) {
    if (c == null) continue;
    node.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
  }
  return node;
}

export function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]
  ));
}

export function setText(sel, text, root = document) {
  const node = typeof sel === "string" ? $(sel, root) : sel;
  if (node) node.textContent = text;
}

let _toastTimer = null;
export function toast(msg, ok = true) {
  const node = $("#toast");
  if (!node) return;
  node.textContent = msg;
  node.className = `toast ${ok ? "ok" : "err"}`;
  node.classList.remove("hidden");
  clearTimeout(_toastTimer);
  _toastTimer = setTimeout(() => node.classList.add("hidden"), 3500);
}
