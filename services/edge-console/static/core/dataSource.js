// Real-first data access. Uses live endpoints where they exist and augments
// with mockApi for not-yet-available capabilities. Pages depend only on this.

import { api } from "./api.js";
import { relTime } from "./format.js";
import { mitreForEvent } from "./mitreMap.js";
import * as mock from "./mockApi.js";

const FACTOR_VAL = { green: 1, blue: 0.7, yellow: 0.5, red: 0, gray: null };

export function stateFromOk(ok) {
  if (ok === true) return "green";
  if (ok === false) return "red";
  return "gray";
}

// Short cache to avoid duplicate /api/status fetches within a render burst.
let _statusCache = { at: 0, data: null };
export async function getStatus(force = false) {
  if (!force && _statusCache.data && Date.now() - _statusCache.at < 2000) return _statusCache.data;
  const data = await api("/api/status");
  _statusCache = { at: Date.now(), data };
  return data;
}

export async function getReadiness() {
  const status = await getStatus();
  let platform = null;
  try { platform = await api("/api/edgex/platform"); } catch { platform = null; }
  const cards = status.cards || {};
  const gauge = status.metrics?.policy_gauge || {};

  const svc = platform?.services || [];
  const running = svc.filter((s) => s.docker?.running === true).length;
  const dockerState = !svc.length ? "gray" : running === svc.length ? "green" : running > 0 ? "yellow" : "red";
  const edgexState = !platform ? "red" : platform.reachable ? "green" : "red";
  const mqttState = cards.mqtt ? stateFromOk(cards.mqtt.ok) : "gray";
  const regState = cards.registration ? stateFromOk(cards.registration.ok) : "gray";
  const baseState = cards.baseline ? (cards.baseline.ok ? "green" : "yellow") : "gray";
  const pct = Number(gauge.percent) || 0;
  const policyState = pct >= 85 ? "green" : pct >= 50 ? "yellow" : "red";

  const factors = [
    { key: "docker", label: "Docker Services", weight: 20, state: dockerState, value: svc.length ? `${running}/${svc.length} 運行` : "未知" },
    { key: "edgex", label: "EdgeX Core", weight: 20, state: edgexState, value: platform?.reachable ? "core 連線正常" : "core 無法連線" },
    { key: "mqtt", label: "Northbound MQTT", weight: 15, state: mqttState, value: cards.mqtt?.detail || "—" },
    { key: "registration", label: "Sensor Registration", weight: 15, state: regState, value: cards.registration?.detail || "—" },
    { key: "baseline", label: "Baseline", weight: 15, state: baseState, value: cards.baseline?.detail || "—" },
    { key: "policy", label: "Policy Readiness", weight: 15, state: policyState, value: `${pct}%` },
  ];

  let num = 0, den = 0;
  for (const f of factors) {
    const v = FACTOR_VAL[f.state];
    if (v == null) continue;
    num += f.weight * v;
    den += f.weight;
  }
  const score = den ? Math.round((num / den) * 100) : 0;
  const grade = score >= 85 ? "ready" : score >= 50 ? "partial" : "attention";
  return { score, grade, factors, status };
}

export async function getRuntime() {
  let platform;
  try { platform = await api("/api/edgex/platform"); }
  catch (e) { return { ok: false, error: e.message, services: [], graph: mock.SERVICE_TOPOLOGY, latency: null }; }

  const services = (platform.services || []).map((s) => {
    const running = s.docker?.running === true;
    const missing = s.docker?.running == null;
    const state = running ? (s.api?.ok === false ? "yellow" : "green") : missing ? "gray" : "red";
    let actions;
    if (missing) actions = ["Install", "Configure"];
    else if (!running) actions = ["Enable", "View Logs"];
    else if (s.api?.ok === false) actions = ["Configure", "Restart", "View Logs"];
    else actions = ["Restart", "View Logs"];
    const diagnosis = missing ? "未安裝 / 未啟用"
      : !running ? "容器未運行"
      : s.api?.ok === false ? "API 無回應"
      : (s.health && s.health !== "healthy") ? `health: ${s.health}`
      : "正常";
    const heartbeat = running
      ? (s.api?.ok ? "live" : (s.started_at ? `up ${relTime(s.started_at).replace(" 前", "")}` : "running"))
      : "—";
    return {
      name: s.label, container: s.container, port: s.port, state,
      version: s.version || "—",
      cpu_pct: s.cpu_pct ?? null,
      mem_mb: s.mem_mb ?? null,
      heartbeat, diagnosis,
      depends_on: depsFor(s.container),
      api_ms: s.api?.latency_ms ?? null,
      can_restart: running && /device-(modbus|mqtt|opc-ua|s7)/.test(s.container || ""),
      actions,
    };
  });

  // Overlay live state onto the static topology.
  const stateByNode = nodeStateMap(platform);
  const graph = {
    nodes: mock.SERVICE_TOPOLOGY.nodes.map((n) => ({ ...n, state: stateByNode[n.id] || "gray" })),
    edges: mock.SERVICE_TOPOLOGY.edges,
  };
  const curLat = services.map((s) => s.api_ms).filter((n) => typeof n === "number");
  const latency = mock.mockLatency(curLat.length ? Math.round(curLat.reduce((a, b) => a + b, 0) / curLat.length) : null);
  return { ok: true, reachable: platform.reachable, services, graph, latency, message_bus: platform.message_bus, ui_url: platform.ui_url };
}

function depsFor(container) {
  const map = {
    "edgex-core-metadata": ["Core Keeper"],
    "edgex-core-data": ["Core Keeper", "Core Metadata"],
    "edgex-device-modbus": ["Core Metadata", "Core Data"],
    "edgex-device-mqtt": ["Core Metadata", "Core Data", "MQTT Broker"],
    "edgex-device-opc-ua": ["Core Metadata", "Core Data"],
    "edgex-device-s7": ["Core Metadata", "Core Data"],
  };
  return map[container] || [];
}

function nodeStateMap(platform) {
  const byContainer = {};
  for (const s of platform.services || []) {
    byContainer[s.container] = s.docker?.running === true ? "green" : s.docker?.running == null ? "gray" : "red";
  }
  return {
    "core-keeper": byContainer["edgex-core-keeper"] || (platform.reachable ? "green" : "gray"),
    "core-metadata": byContainer["edgex-core-metadata"] || (platform.reachable ? "green" : "red"),
    "core-data": byContainer["edgex-core-data"] || (platform.reachable ? "green" : "red"),
    "device-mqtt": byContainer["edgex-device-mqtt"] || "gray",
    "mqtt-broker": byContainer["edgex-mqtt-broker"] || byContainer["mqtt-broker"] || "gray",
    "northbound-mqtt": platform.message_bus?.local_features ? "green" : "gray",
  };
}

const SEV_WEIGHT = { critical: 40, high: 25, medium: 10, low: 3 };

// Aggregate a per-asset risk score from recent security events.
function aggregateRisk(events) {
  const acc = {};
  for (const e of events || []) {
    const key = e.matched_device || e.src_ip;
    if (!key) continue;
    const sev = String(e.severity || "medium").toLowerCase();
    const ioc = /019/.test(String(e.rule_id || "")) || /ioc/i.test(String(e.event_type || "")) ? 15 : 0;
    const cur = acc[key] || { score: 0, events: 0 };
    cur.score += (SEV_WEIGHT[sev] ?? 10) + ioc;
    cur.events += 1;
    acc[key] = cur;
  }
  for (const k of Object.keys(acc)) {
    const s = Math.min(100, acc[k].score);
    acc[k] = { score: s, level: s >= 70 ? "red" : s >= 40 ? "yellow" : "green", events: acc[k].events };
  }
  return acc;
}

export async function getAssets() {
  const [discovery, status, traffic, events, inv] = await Promise.all([
    api("/api/edgex/discovery").catch(() => ({ assets: [] })),
    getStatus().catch(() => ({})),
    api("/api/traffic/live").catch(() => ({ recent_packets: [] })),
    api("/api/events/recent?limit=200").then((d) => d.events || []).catch(() => []),
    api("/api/assets/inventory").catch(() => ({ entries: {}, active_probe_enabled: false })),
  ]);
  // Pair IP → MAC from recent packets (real), so OUI vendor lookup can work.
  const ipMac = {};
  for (const p of traffic.recent_packets || []) {
    if (p.src_ip && p.src_mac && !ipMac[p.src_ip]) ipMac[p.src_ip] = p.src_mac;
    if (p.dst_ip && p.dst_mac && !ipMac[p.dst_ip]) ipMac[p.dst_ip] = p.dst_mac;
  }
  const riskByKey = aggregateRisk(events);
  const invEntries = inv.entries || {};
  const assets = (discovery.assets || []).map((a) => {
    const mac = a.mac || ipMac[a.ip] || null;
    const enriched = mock.enrichAsset({ ...a, mac });
    const risk = riskByKey[a.edgex_device] || riskByKey[a.ip] || { score: 0, level: "green", events: 0 };
    // Real identity (manual > probe) overrides mock; vendor also falls back to OUI.
    const ov = invEntries[a.ip] || {};
    const manual = ov.manual || {};
    const probe = ov.probe || {};
    const vendor = manual.vendor || probe.vendor || enriched.vendor;
    const model = manual.model || probe.model || enriched.model;
    const firmware = manual.firmware || probe.firmware || enriched.firmware;
    const hasManual = !!(manual.vendor || manual.model || manual.firmware);
    const hasProbe = !!(probe.vendor || probe.model || probe.firmware);
    const identity_source = hasManual ? "manual" : hasProbe ? "probe" : enriched.vendor_source === "oui" ? "oui" : "mock";
    return {
      ip: a.ip, mac, label: a.label || a.ip,
      edgex_device: a.edgex_device || null,
      source: a.source || "mirror",
      last_seen: a.last_seen || status.last_register_at || null,
      packets: a.packets ?? null,
      ...enriched,
      vendor, model, firmware, identity_source,
      open_ports: probe.open_ports || null,
      risk,
    };
  });
  return {
    assets,
    active_probe_enabled: inv.active_probe_enabled === true,
    summary: {
      total: assets.length,
      edgex: discovery.edgex_device_count ?? 0,
      mirror_only: discovery.mirror_only_count ?? 0,
      live: discovery.traffic_live === true,
    },
  };
}

const PROTOCOL_DEFS = [
  { key: "goose", label: "IEC 61850 GOOSE", match: ["goose"] },
  { key: "modbus", label: "Modbus TCP", match: ["modbus"] },
  { key: "opcua", label: "OPC UA", match: ["opcua", "opc-ua", "opc ua"] },
  { key: "s7", label: "Siemens S7", match: ["s7"] },
  { key: "mqtt", label: "MQTT", match: ["mqtt"] },
];

export async function getProtocolCoverage() {
  const [proto, traffic] = await Promise.all([
    api("/api/edgex/protocols").catch(() => ({ protocols: [] })),
    api("/api/traffic/live").catch(() => ({ metrics: {} })),
  ]);
  const m = traffic.metrics || {};
  const trafficSeen = {
    goose: (m.goose_messages || 0) > 0,
    modbus: false, opcua: false, s7: false,
    mqtt: (m.unique_ips || 0) > 0,
  };
  const found = proto.protocols || [];
  const protocols = PROTOCOL_DEFS.map((def) => {
    const p = found.find((x) => def.match.some((k) => String(x.id || x.label || "").toLowerCase().includes(k)));
    let status = "missing";
    if (p) status = p.enabled ? "enabled" : "disabled";
    return {
      key: def.key, label: def.label, status,
      phase: p?.phase ?? 1,
      reason: p?.reason || "",
      traffic: !!trafficSeen[def.key],
      state: status === "enabled" ? (trafficSeen[def.key] ? "green" : "yellow") : status === "disabled" ? "gray" : "red",
    };
  });
  return { protocols };
}

export async function getPolicyReadiness() {
  const applied = await api("/api/detection-policy/applied").catch(() => ({ loaded: false }));
  const loaded = applied.loaded === true;
  const rulesCount = applied.rules_count ?? (applied.rules_enabled || []).length;
  // Derive per-category state from applied policy (heuristic; TODO:real).
  const stateMap = {
    telemetry_forwarding: loaded ? "green" : "red",
    ioc_matching: rulesCount > 0 ? "green" : "yellow",
    baseline_anomaly: "blue",
    protocol_command: rulesCount >= 8 ? "green" : "yellow",
    response_action: loaded ? "yellow" : "gray",
  };
  const actionMap = {
    telemetry_forwarding: "Forward to SOC",
    ioc_matching: "Alert",
    baseline_anomaly: "Observe",
    protocol_command: "Alert",
    response_action: "Observe",
  };
  const categories = mock.POLICY_CATEGORIES.map((c) => ({
    ...c,
    state: stateMap[c.key] || "gray",
    action: actionMap[c.key] || "Observe",
    actions_available: mock.POLICY_ACTIONS,
  }));
  return { loaded, categories, applied };
}

export async function getBaseline() {
  // Real baseline lifecycle: pcap → candidate → approve / rollback.
  try {
    return await api("/api/baseline");
  } catch {
    return { state: "not_loaded", active: null, candidate: null, history: [], assets: 0, comm_pairs: 0 };
  }
}

export async function getEvents(limit = 50) {
  const data = await api(`/api/events/recent?limit=${limit}`);
  return data.events || [];
}

// Context shared by all events on the page: which rules the applied policy
// enables, and northbound (Control Plane) sync state. Fetched once per load.
export async function getEventsContext() {
  const [applied, status] = await Promise.all([
    api("/api/detection-policy/applied").catch(() => ({})),
    getStatus().catch(() => ({})),
  ]);
  const rules = (Array.isArray(applied.rule_entries) && applied.rule_entries.length
    ? applied.rule_entries.map((r) => r.rule_id)
    : applied.rules_enabled || []).map((r) => String(r).toUpperCase());
  return {
    enabledRules: new Set(rules),
    policyLoaded: applied.loaded === true,
    mqttConnected: !!(status.northbound && status.northbound.mqtt_connected),
    lastPublishAt: status.northbound ? status.northbound.last_mqtt_publish_at : null,
  };
}

function formatParsedEvidence(ev) {
  const keys = Object.keys(ev || {}).filter((k) => k !== "pcap_ref" && k !== "pcap");
  if (!keys.length) return null;
  return keys.slice(0, 5).map((k) => `${k}=${ev[k]}`).join(" · ");
}

// Build the Evidence Chain from REAL event fields (risk_score, evidence,
// pcap_ref) plus page context (policy match, northbound sync). Only the
// recommended action is a heuristic on top of real data.
export function getEventEvidence(event, ctx = {}) {
  const sev = String(event.severity || "medium").toLowerCase();
  const realRisk = Number(event.risk_score);
  const risk = Number.isFinite(realRisk) ? realRisk
    : (sev === "critical" ? 95 : sev === "high" ? 78 : sev === "medium" ? 52 : 25);
  const evd = event.evidence || {};
  const pcap = evd.pcap_ref || evd.pcap || event.evidence_ref || null;
  const parsed = formatParsedEvidence(evd);
  const rid = String(event.rule_id || "").toUpperCase();
  const matched = ctx.enabledRules ? ctx.enabledRules.has(rid) : false;
  const action = !matched ? "Observe"
    : sev === "critical" ? "Block"
    : (sev === "high" || sev === "medium") ? "Alert"
    : "Observe";
  const synced = ctx.mqttConnected;

  const chain = [
    { step: "Packet", detail: `${event.protocol || event.event_type || "frame"}${pcap ? ` · ${pcap}` : ""}`, state: "green" },
    { step: "Parsed Event", detail: parsed || event.event_type || "normalized", state: parsed ? "green" : "blue" },
    { step: "Detection Rule", detail: rid || "—", state: rid ? "green" : "gray" },
    { step: "Risk Score", detail: `${risk}/100${Number.isFinite(realRisk) ? "" : "（推估）"}`, state: risk >= 70 ? "red" : risk >= 40 ? "yellow" : "green" },
    { step: "Policy Decision", detail: matched ? `${action}（規則已套用）` : (ctx.policyLoaded ? "Observe（規則未在政策中）" : "Observe（未載入政策）"), state: matched ? "yellow" : "blue" },
    { step: "Control Plane Sync", detail: synced ? `已發布${ctx.lastPublishAt ? ` · ${relTime(ctx.lastPublishAt)}` : ""}` : "北向未連線", state: synced ? "blue" : "red" },
  ];
  return { chain, risk, recommended_action: action, matched, mitre: mitreForEvent(event) };
}
