// Mock data for capabilities the edge backend does not expose yet.
// TODO:real — replace each generator with a real endpoint when available.
// All generators are deterministic so the UI is stable across refreshes.
import { mitreForEvent } from "./mitreMap.js";
import { ouiVendor } from "./ouiMap.js";

function hash(str) {
  let h = 2166136261;
  for (let i = 0; i < String(str).length; i++) {
    h ^= String(str).charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return Math.abs(h);
}
const pick = (seed, arr) => arr[hash(seed) % arr.length];
const between = (seed, lo, hi) => lo + (hash(seed) % (hi - lo + 1));

// ---- Vendor / asset enrichment (deterministic by IP+MAC) --------------------
const VENDORS = [
  { vendor: "Siemens", models: ["S7-1500", "S7-1200", "SCALANCE XC216"], proto: "S7" },
  { vendor: "Schneider Electric", models: ["Modicon M580", "Modicon M340"], proto: "Modbus TCP" },
  { vendor: "ABB", models: ["RELION REF615", "AC500 PM573"], proto: "IEC 61850 GOOSE" },
  { vendor: "Rockwell", models: ["ControlLogix 1756", "CompactLogix 5380"], proto: "OPC UA" },
  { vendor: "SEL", models: ["SEL-451", "SEL-787"], proto: "IEC 61850 GOOSE" },
  { vendor: "Moxa", models: ["EDS-508A", "MGate 5118"], proto: "Modbus TCP" },
];
const ZONES = ["Process-Cell-A", "Process-Cell-B", "Substation-Bay-1", "DMZ", "Control-Room"];
const PURDUE = ["L0", "L1", "L2", "L3"];

// Vendor is resolved from the real MAC OUI when available; everything else
// (model/firmware/purdue/zone) stays deterministic mock until a real source
// exists. Risk is computed from events in dataSource.getAssets (no longer here).
export function enrichAsset(asset) {
  const seed = `${asset.ip || ""}|${asset.mac || asset.edgex_device || ""}`;
  const ouiName = asset.mac ? ouiVendor(asset.mac) : null;
  const v = pick(seed, VENDORS);
  return {
    vendor: ouiName || v.vendor,
    vendor_source: ouiName ? "oui" : "mock",
    model: pick(seed + "m", v.models),
    firmware: `v${between(seed + "fwa", 1, 6)}.${between(seed + "fwb", 0, 9)}.${between(seed + "fwc", 0, 20)}`,
    protocol: asset.protocol || v.proto,
    purdue: pick(seed + "p", PURDUE),
    zone: pick(seed + "z", ZONES),
  };
}

// ---- Runtime service augmentation ------------------------------------------
export function augmentService(svc) {
  const seed = svc.container || svc.label || "svc";
  const running = svc.docker?.running === true;
  const missing = svc.docker?.running == null && !svc.api?.ok;
  return {
    version: pick(seed, ["4.0.0", "4.0.1", "3.1.0"]),
    last_heartbeat_sec: running ? between(seed + "hb", 1, 28) : null,
    cpu_pct: running ? +(between(seed + "cpu", 2, 240) / 10).toFixed(1) : null,
    mem_mb: running ? between(seed + "mem", 28, 320) : null,
    diagnosis: missing ? "未安裝 / 未啟用" : running ? "正常" : "容器未運行",
  };
}

// Static EdgeX dependency topology (overlaid with live state in dataSource).
export const SERVICE_TOPOLOGY = {
  nodes: [
    // SenseL NDR pipeline (capture → detect → forward).
    { id: "suricata", label: "Suricata IDS" },
    { id: "packet-sensor", label: "Packet Sensor" },
    { id: "edge-agent", label: "Edge Agent" },
    { id: "local-mqtt", label: "Local MQTT" },
    // EdgeX Foundry core + egress.
    { id: "core-keeper", label: "Core Keeper" },
    { id: "core-metadata", label: "Core Metadata" },
    { id: "core-data", label: "Core Data" },
    { id: "device-mqtt", label: "Device MQTT" },
    { id: "mqtt-broker", label: "MQTT Broker" },
    { id: "northbound-mqtt", label: "Northbound MQTT" },
  ],
  edges: [
    { from: "core-metadata", to: "core-keeper" },
    { from: "core-data", to: "core-keeper" },
    { from: "core-data", to: "core-metadata" },
    { from: "device-mqtt", to: "core-metadata" },
    { from: "device-mqtt", to: "core-data" },
    { from: "device-mqtt", to: "mqtt-broker" },
    { from: "northbound-mqtt", to: "core-data" },
    { from: "northbound-mqtt", to: "mqtt-broker" },
    // SenseL NDR data path.
    { from: "packet-sensor", to: "suricata" },
    { from: "packet-sensor", to: "local-mqtt" },
    { from: "device-mqtt", to: "local-mqtt" },
    { from: "edge-agent", to: "packet-sensor" },
    { from: "edge-agent", to: "northbound-mqtt" },
  ],
};

export function mockLatency(currentMs) {
  const base = Number(currentMs) || between("lat", 8, 40);
  return { current_ms: base, p50_ms: Math.round(base * 0.85), p95_ms: Math.round(base * 2.4) };
}

// ---- Policy readiness categories -------------------------------------------
export const POLICY_CATEGORIES = [
  { key: "telemetry_forwarding", label: "Telemetry Forwarding", desc: "事件北向轉發至 Control Plane" },
  { key: "ioc_matching", label: "IoC Matching", desc: "CTI 指標即時比對" },
  { key: "baseline_anomaly", label: "Baseline Anomaly", desc: "基線偏移偵測" },
  { key: "protocol_command", label: "Protocol Command Policy", desc: "Modbus/MMS 寫入命令控管" },
  { key: "response_action", label: "Response Action", desc: "自動回應 / SOC 轉送" },
];
export const POLICY_ACTIONS = ["Observe", "Alert", "Block", "Quarantine", "Forward to SOC"];

// ---- Evidence chain + MITRE ATT&CK for ICS ---------------------------------
// MITRE is now a curated rule_id table (see mitreMap.js); only the evidence
// chain timeline remains illustrative.
export function mockMitre(event) {
  return mitreForEvent(event);
}

export function mockEvidenceChain(event) {
  const ts = event.timestamp;
  const sev = String(event.severity || "medium").toLowerCase();
  const risk = sev === "critical" ? 95 : sev === "high" ? 78 : sev === "medium" ? 52 : 25;
  const action = risk >= 90 ? "Quarantine" : risk >= 70 ? "Alert" : risk >= 40 ? "Alert" : "Observe";
  return {
    chain: [
      { step: "Packet", detail: `${event.proto || event.event_type || "frame"} @ ${event.src_ip || event.src_mac || "—"}`, state: "green" },
      { step: "Parsed Event", detail: event.event_type || "normalized", state: "green" },
      { step: "Detection Rule", detail: `${event.rule_id || "—"}`, state: "green" },
      { step: "Risk Score", detail: `${risk}/100`, state: risk >= 70 ? "red" : risk >= 40 ? "yellow" : "green" },
      { step: "Policy Decision", detail: action, state: action === "Observe" ? "blue" : "yellow" },
      { step: "Control Plane Sync", detail: "已發布 MQTT", state: "blue" },
    ],
    risk,
    recommended_action: action,
    mitre: mockMitre(event),
  };
}
