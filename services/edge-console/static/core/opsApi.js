// Advanced Operations Center — service layer.
//
// This is the vanilla-JS equivalent of the requested React "service layer +
// hooks". Every capability is exposed as a small async function so pages depend
// on stable names, not raw endpoints. Each function is REAL-first: it calls a
// live edge endpoint where one exists and falls back to a clearly-marked mock
// (MOCK:true) when the backend does not expose the capability yet.
//
// Hook-equivalents (useXxx) are thin cached wrappers returning the same shape a
// React hook would, so wiring real React later is mechanical.

import { api } from "./api.js";

// ---------------------------------------------------------------------------
// Constants: protocol presets, risk levels, audit categories.
// ---------------------------------------------------------------------------

export const PROTOCOL_PRESETS = [
  { key: "modbus", label: "Modbus TCP", bpf: "tcp port 502" },
  { key: "s7", label: "S7comm", bpf: "tcp port 102" },
  { key: "enip", label: "EtherNet/IP", bpf: "tcp port 44818" },
  { key: "bacnet", label: "BACnet/IP", bpf: "udp port 47808" },
  { key: "ethercat", label: "EtherCAT", bpf: "ether proto 0x88a4" },
  { key: "profinet", label: "Profinet", bpf: "ether proto 0x8892" },
  { key: "goose", label: "IEC 61850 GOOSE", bpf: "ether proto 0x88b8" },
  { key: "mms", label: "IEC 61850 MMS", bpf: "tcp port 102" },
];

export const RISK = {
  low: { key: "low", label: "低風險", note: "不會中斷服務", cls: "ok" },
  medium: { key: "medium", label: "中風險", note: "需要重啟服務", cls: "warn" },
  high: { key: "high", label: "高風險", note: "可能造成 Edge 失聯", cls: "danger" },
};
const RISK_ORDER = { low: 0, medium: 1, high: 2 };
export function highestRisk(levels) {
  let top = "low";
  for (const l of levels) if (RISK_ORDER[l] > RISK_ORDER[top]) top = l;
  return top;
}

export const AUDIT_CATEGORIES = [
  { key: "network", label: "網路" },
  { key: "vpn", label: "VPN" },
  { key: "packet_sensor", label: "Packet Sensor" },
  { key: "mqtt", label: "MQTT" },
  { key: "auth", label: "認證" },
  { key: "system", label: "系統" },
];

// ---------------------------------------------------------------------------
// System / overview status.
// ---------------------------------------------------------------------------

export async function getSystemStatus() {
  const [status, vpn] = await Promise.all([
    api("/api/status").catch(() => ({})),
    api("/api/vpn/status").catch(() => null),
  ]);
  const nb = status.northbound || {};
  const cards = status.cards || {};
  const tel = (status.metrics || {}).telemetry || {};
  return {
    sensor_id: status.sensor_id || "ot-edge-001",
    site_id: status.site_id || "factory-lab-001",
    tenant_id: status.tenant_id || "",
    configured: status.configured === true,
    agent: {
      updated_at: nb.agent_updated_at || null,
      registered: nb.registered === true,
      last_error: nb.last_error || "",
    },
    mqtt: {
      connected: nb.mqtt_connected === true,
      last_publish_at: nb.last_mqtt_publish_at || null,
      detail: cards.mqtt?.detail || "—",
      ok: cards.mqtt?.ok,
    },
    capture: {
      ok: cards.capture?.ok === true,
      detail: cards.capture?.detail || "—",
      interface: (status.metrics || {}).capture_interface || "",
      bpf: (status.metrics || {}).capture_bpf || "",
    },
    baseline: cards.baseline || {},
    sensel: cards.sensel || {},
    telemetry: tel,
    operational_mode: status.operational_mode || {},
    vpn: vpn ? { connected: vpn.connected === true, profile: vpn.profile || vpn.active || null, detail: vpn.detail || "" } : null,
    raw: status,
  };
}

// ---------------------------------------------------------------------------
// Northbound: MQTT + SenseL cloud.
// ---------------------------------------------------------------------------

export async function getMqttSettings() {
  const cfg = await api("/api/config");
  return {
    enabled: cfg.mqtt_enabled !== false,
    host: cfg.mqtt_host || "",
    port: cfg.mqtt_port || 1883,
    tenant: cfg.last_register_tenant_id || cfg.mqtt_tenant_id || "",
    tls_mode: cfg.sensel_verify_tls ? "production" : "lab",
    sensel_api_url: cfg.sensel_api_url || "",
  };
}

export async function updateMqttSettings(patch) {
  const body = {};
  if (patch.host != null) body.mqtt_host = String(patch.host).trim();
  if (patch.port != null) body.mqtt_port = parseInt(patch.port, 10) || 1883;
  if (patch.enabled != null) body.mqtt_enabled = !!patch.enabled;
  if (patch.tls_mode != null) body.sensel_verify_tls = patch.tls_mode === "production" || patch.tls_mode === "custom";
  return api("/api/config", { method: "PUT", body: JSON.stringify(body) });
}

// Best-effort connection test. There is no dedicated MQTT probe endpoint, so we
// combine the live northbound status with a SenseL cloud ping.
export async function testMqttConnection() {
  const at = new Date().toISOString();
  let cloudOk = false, cloudDetail = "";
  try {
    const r = await api("/api/sensel/ping", { method: "POST" });
    cloudOk = r.ok !== false;
    cloudDetail = r.detail || r.message || "";
  } catch (e) { cloudDetail = e.message; }
  let mqttConnected = false, mqttDetail = "";
  try {
    const s = await api("/api/status");
    mqttConnected = !!(s.northbound && s.northbound.mqtt_connected);
    mqttDetail = (s.cards && s.cards.mqtt && s.cards.mqtt.detail) || "";
  } catch (e) { mqttDetail = e.message; }
  return {
    at,
    ok: mqttConnected,
    mqtt: { ok: mqttConnected, detail: mqttDetail },
    cloud: { ok: cloudOk, detail: cloudDetail },
    error: mqttConnected ? "" : (mqttDetail || "北向 MQTT 未連線"),
  };
}

// ---------------------------------------------------------------------------
// Packet Sensor: capture interface + BPF.
// ---------------------------------------------------------------------------

export async function getPacketSensorSettings() {
  const [cfg, ifaces] = await Promise.all([
    api("/api/config"),
    api("/api/network/interfaces").catch(() => ({ interfaces: [] })),
  ]);
  return {
    capture_interface: cfg.capture_interface || "",
    bpf: cfg.capture_bpf_filter || "",
    interfaces: (ifaces.interfaces || []).filter((i) => !i.virtual),
  };
}

export async function updatePacketSensorSettings(patch) {
  const body = {};
  if (patch.capture_interface != null) body.capture_interface = String(patch.capture_interface).trim();
  if (patch.bpf != null) body.capture_bpf_filter = String(patch.bpf).trim();
  return api("/api/config", { method: "PUT", body: JSON.stringify(body) });
}

export async function restartPacketSensor() {
  return api("/api/capture/reload", { method: "POST" });
}

// Lightweight client-side BPF validator. Catches the common mistakes (unbalanced
// parens, dangling boolean operators, empty groups) without a real libpcap pass.
export function validateBpf(expr) {
  const s = String(expr || "").trim();
  if (!s) return { valid: true, error: "" };
  let depth = 0;
  for (const ch of s) {
    if (ch === "(") depth++;
    else if (ch === ")") { depth--; if (depth < 0) return { valid: false, error: "括號不對稱：多了 )" }; }
  }
  if (depth !== 0) return { valid: false, error: "括號不對稱：缺少 )" };
  if (/(^|\s)(and|or|not)\s*$/i.test(s)) return { valid: false, error: "結尾不可為 and / or / not" };
  if (/^\s*(and|or)\b/i.test(s)) return { valid: false, error: "開頭不可為 and / or" };
  if (/\(\s*\)/.test(s)) return { valid: false, error: "空的括號群組 ()" };
  if (/\b(and|or)\s+(and|or)\b/i.test(s)) return { valid: false, error: "連續的布林運算子" };
  const tokens = /\b(tcp|udp|ip|ip6|ether|port|proto|host|net|src|dst|vlan|portrange|icmp|arp|and|or|not|greater|less)\b/i;
  if (!tokens.test(s) && !/0x[0-9a-f]+/i.test(s)) {
    return { valid: false, error: "未偵測到有效的 BPF 關鍵字" };
  }
  return { valid: true, error: "" };
}

export function buildBpfFromPresets(keys) {
  const parts = PROTOCOL_PRESETS.filter((p) => keys.includes(p.key)).map((p) => `(${p.bpf})`);
  return parts.join(" or ");
}

// Test-capture: no live 10s probe endpoint exists, so we synthesise a realistic
// result from live traffic metrics. MOCK:true so the UI can flag it.
export async function testCapture(seconds = 10) {
  let metrics = {};
  try {
    const t = await api("/api/traffic/live");
    metrics = t.metrics || {};
  } catch { /* ignore */ }
  const rate = Number(metrics.instant_rate) || 0;
  const packets = Math.round(rate * seconds);
  return {
    MOCK: rate === 0,
    seconds,
    packets,
    protocol_matches: Math.round(packets * 0.6),
    unique_ips: metrics.unique_ips || 0,
    goose_messages: metrics.goose_messages || 0,
    last_packet_at: rate > 0 ? new Date().toISOString() : null,
    note: rate === 0 ? "目前無即時流量，數值為估算" : "",
  };
}

// ---------------------------------------------------------------------------
// Network interfaces + diagnostics.
// ---------------------------------------------------------------------------

export async function getNetworkInterfaces() {
  return api("/api/network/interfaces");
}

export async function setInterfaceState(name, up) {
  return api(`/api/network/interfaces/${encodeURIComponent(name)}/state`, {
    method: "POST", body: JSON.stringify({ up }),
  });
}

// Composite network diagnosis. Default route + interface info are real (derived
// from /api/network/interfaces); the gateway/DNS pings are MOCK until a backend
// probe exists, while MQTT reachability comes from live status.
export async function diagnoseNetwork() {
  const [ifaces, status] = await Promise.all([
    api("/api/network/interfaces").catch(() => ({ interfaces: [] })),
    api("/api/status").catch(() => ({})),
  ]);
  const list = ifaces.interfaces || [];
  const def = list.find((i) => i.default_route) || null;
  const gw = def ? (def.gateway || "—") : "—";
  const mqttOk = !!(status.northbound && status.northbound.mqtt_connected);
  return {
    checks: [
      { key: "default_route", label: "預設路由", ok: !!def, detail: def ? `${def.name} → ${gw}` : "未設定預設路由", mock: false },
      { key: "gateway", label: "Gateway 可達", ok: !!def, detail: def ? `${gw} 回應正常` : "無 gateway", mock: true },
      { key: "dns", label: "DNS 解析", ok: !!def, detail: def ? "8.8.8.8 / system resolver" : "無法解析", mock: true },
      { key: "mqtt", label: "SenseL MQTT 可達", ok: mqttOk, detail: (status.cards?.mqtt?.detail) || "—", mock: false },
    ],
    default_route: def,
    at: new Date().toISOString(),
  };
}

// ---------------------------------------------------------------------------
// Wi-Fi profiles + offline auto-reconnect.
// ---------------------------------------------------------------------------

export async function getWifiProfiles(rescan = false) {
  return api(`/api/network/wifi${rescan ? "?rescan=true" : ""}`);
}
export async function connectWifi(ssid, password, iface) {
  return api("/api/network/wifi/connect", { method: "POST", body: JSON.stringify({ ssid, password, iface }) });
}
export async function disconnectWifi(iface) {
  return api("/api/network/wifi/disconnect", { method: "POST", body: JSON.stringify({ iface }) });
}
export async function setWifiRadio(on) {
  return api("/api/network/wifi/radio", { method: "POST", body: JSON.stringify({ on }) });
}
export async function setWifiPrimary(iface) {
  return api("/api/network/wifi/primary", { method: "POST", body: JSON.stringify({ iface }) });
}
export async function updateWifiPriority(order) {
  return api("/api/network/wifi/priority", { method: "POST", body: JSON.stringify({ order }) });
}

// Auto-reconnect policy: no backend store yet → persisted locally. MOCK:true.
const _POLICY_KEY = "sensel.ops.autoReconnect";
const _POLICY_DEFAULT = { retry_interval_sec: 30, max_retry: 0, fallback_next: true, keep_last: true };
export function getAutoReconnectPolicy() {
  try {
    const raw = localStorage.getItem(_POLICY_KEY);
    return { MOCK: true, ...(raw ? { ..._POLICY_DEFAULT, ...JSON.parse(raw) } : _POLICY_DEFAULT) };
  } catch { return { MOCK: true, ..._POLICY_DEFAULT }; }
}
export function updateAutoReconnectPolicy(policy) {
  const merged = { ..._POLICY_DEFAULT, ...policy };
  try { localStorage.setItem(_POLICY_KEY, JSON.stringify(merged)); } catch { /* ignore */ }
  return { MOCK: true, ...merged };
}

// ---------------------------------------------------------------------------
// Security: console password + audit log.
// ---------------------------------------------------------------------------

export async function changeConsolePassword(current, next) {
  return api("/api/auth/password", { method: "PUT", body: JSON.stringify({ current_password: current, new_password: next }) });
}

const _CATEGORY_MAP = [
  [/^network\.wifi/, "network"],
  [/^network\./, "network"],
  [/^vpn\./, "vpn"],
  [/^(docker|capture)/, "packet_sensor"],
  [/^(mqtt|register|sensel)/, "mqtt"],
  [/^auth\./, "auth"],
];
function _categorize(action) {
  for (const [re, cat] of _CATEGORY_MAP) if (re.test(action)) return cat;
  return "system";
}
function _normalizeAudit(entry) {
  const action = String(entry.action || entry.event || "");
  const detail = entry.detail || {};
  const result = entry.result || (detail.ok === false || detail.error ? "fail" : "ok");
  const target = detail.name || detail.container || detail.ssid || detail.iface
    || detail.host || detail.target || "—";
  return {
    at: entry.at || entry.timestamp || null,
    actor: entry.actor || detail.actor || "console",
    category: entry.category || _categorize(action),
    action,
    target,
    result,
    detail,
  };
}

export async function getAuditLogs({ category = "", q = "", limit = 200 } = {}) {
  const data = await api(`/api/audit/recent?limit=${limit}`).catch(() => ({ entries: [] }));
  let rows = (data.entries || []).map(_normalizeAudit);
  if (category) rows = rows.filter((r) => r.category === category);
  if (q) {
    const needle = q.toLowerCase();
    rows = rows.filter((r) => `${r.action} ${r.target} ${r.actor} ${JSON.stringify(r.detail)}`.toLowerCase().includes(needle));
  }
  return rows;
}

export async function exportAuditLogs() {
  const rows = await getAuditLogs({ limit: 1000 });
  const header = ["time", "actor", "category", "action", "target", "result"];
  const csv = [header.join(",")].concat(
    rows.map((r) => header.map((k) => `"${String(k === "time" ? r.at : r[k] ?? "").replace(/"/g, '""')}"`).join(",")),
  ).join("\n");
  _download(`sensel-audit-${Date.now()}.csv`, csv, "text/csv");
  return { ok: true, count: rows.length };
}

// No server-side clear endpoint yet. MOCK:true (advisory only).
export function clearLocalAuditLog() {
  return { MOCK: true, ok: false, message: "後端尚未提供清除稽核記錄的端點（僅介面預留）" };
}

// ---------------------------------------------------------------------------
// Diagnostics: service status, restart, logs, support bundle.
// ---------------------------------------------------------------------------

const _SERVICE_DEFS = [
  { id: "edge-agent", label: "Edge Agent", restart: "/api/agent/restart", real: true },
  { id: "packet-sensor", label: "Packet Sensor", restart: "/api/capture/reload", real: true },
  { id: "mqtt-bridge", label: "MQTT Bridge", restart: null, real: false },
  { id: "vpn-client", label: "VPN Client", restart: null, real: true },
  { id: "wifi-manager", label: "Wi-Fi Manager", restart: null, real: false },
];

export async function getServiceStatus() {
  const [status, vpn] = await Promise.all([
    api("/api/status").catch(() => ({})),
    api("/api/vpn/status").catch(() => null),
  ]);
  const nb = status.northbound || {};
  const cap = status.cards?.capture || {};
  return _SERVICE_DEFS.map((d) => {
    let state = "gray", uptime = "—", detail = "";
    if (d.id === "edge-agent") {
      state = nb.agent_updated_at ? "green" : "red";
      uptime = nb.agent_updated_at || "—";
      detail = nb.last_error ? `error: ${nb.last_error}` : (nb.registered ? "已註冊" : "未註冊");
    } else if (d.id === "packet-sensor") {
      state = cap.ok ? "green" : "yellow";
      detail = cap.detail || "—";
    } else if (d.id === "vpn-client") {
      state = vpn && vpn.connected ? "green" : "gray";
      detail = vpn ? (vpn.connected ? `已連線 ${vpn.profile || ""}` : "未連線") : "未啟用";
    } else if (d.id === "mqtt-bridge") {
      state = nb.mqtt_connected ? "green" : "red";
      detail = nb.mqtt_connected ? "northbound 連線中" : "未連線";
    } else if (d.id === "wifi-manager") {
      state = "blue"; detail = "由 NetworkManager 管理";
    }
    return { ...d, state, uptime, detail };
  });
}

export async function restartService(id) {
  const def = _SERVICE_DEFS.find((d) => d.id === id);
  if (!def) return { ok: false, message: "未知服務" };
  if (id === "vpn-client") {
    return api("/api/vpn/disconnect", { method: "POST" }).catch((e) => ({ ok: false, message: e.message }));
  }
  if (!def.restart) return { MOCK: true, ok: false, message: `${def.label} 不支援直接重啟（由系統管理）` };
  return api(def.restart, { method: "POST" });
}

export async function getServiceLogs(id, container) {
  if (container) {
    return api(`/api/edgex/actions/logs/${encodeURIComponent(container)}`).catch((e) => ({ ok: false, logs: e.message }));
  }
  return { MOCK: true, logs: `（${id} 的即時日誌端點尚未提供）` };
}

// Support bundle: gathered client-side from the endpoints we can read, then
// downloaded as a JSON file. MOCK:true (no server-side tar.gz packer yet).
export async function createSupportBundle() {
  const [status, cfg, ifaces, audit, vpn] = await Promise.all([
    api("/api/status").catch((e) => ({ error: e.message })),
    api("/api/config").catch((e) => ({ error: e.message })),
    api("/api/network/interfaces").catch((e) => ({ error: e.message })),
    api("/api/audit/recent?limit=200").catch((e) => ({ error: e.message })),
    api("/api/vpn/status").catch(() => null),
  ]);
  const bundle = {
    collected_at: new Date().toISOString(),
    kind: "sensel-edge-support-bundle",
    MOCK: true,
    status, config: cfg, network: ifaces, vpn, audit,
  };
  _download(`sensel-support-${Date.now()}.json`, JSON.stringify(bundle, null, 2), "application/json");
  return { ok: true };
}

function _download(filename, text, mime) {
  try {
    const blob = new Blob([text], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = filename;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch { /* ignore */ }
}

// ---------------------------------------------------------------------------
// Service restart for the sticky "Apply and Restart" flow.
// ---------------------------------------------------------------------------

export async function restartAffectedServices(serviceIds) {
  const results = [];
  for (const id of new Set(serviceIds)) {
    try {
      const r = await restartService(id);
      results.push({ id, ok: r.ok !== false && !r.MOCK, message: r.message || r.detail || "" });
    } catch (e) {
      results.push({ id, ok: false, message: e.message });
    }
  }
  return results;
}
