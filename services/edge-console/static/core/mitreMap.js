// Curated MITRE ATT&CK for ICS mapping keyed by SenseL OT detection rule id.
// This is reference data (not live), so it is treated as real rather than mock.
// Each entry is an ordered list of techniques most relevant to that rule.

export const MITRE_ICS = {
  "OT-001": [{ id: "T0840", technique: "Network Connection Enumeration", tactic: "Discovery" }],
  "OT-002": [{ id: "T0840", technique: "Network Connection Enumeration", tactic: "Discovery" }],
  "OT-003": [{ id: "T0830", technique: "Adversary-in-the-Middle", tactic: "Collection" }],
  "OT-004": [{ id: "T0840", technique: "Network Connection Enumeration", tactic: "Discovery" }],
  "OT-005": [{ id: "T0846", technique: "Remote System Discovery", tactic: "Discovery" }],
  "OT-006": [{ id: "T0846", technique: "Remote System Discovery", tactic: "Discovery" }],
  "OT-007": [
    { id: "T0855", technique: "Unauthorized Command Message", tactic: "Impair Process Control" },
    { id: "T0836", technique: "Modify Parameter", tactic: "Impair Process Control" },
  ],
  "OT-008": [{ id: "T0814", technique: "Denial of Service", tactic: "Inhibit Response Function" }],
  "OT-009": [{ id: "T0816", technique: "Device Restart/Shutdown", tactic: "Inhibit Response Function" }],
  "OT-010": [
    { id: "T0859", technique: "Valid Accounts", tactic: "Lateral Movement" },
    { id: "T0855", technique: "Unauthorized Command Message", tactic: "Impair Process Control" },
  ],
  "OT-011": [{ id: "T0856", technique: "Spoof Reporting Message", tactic: "Impair Process Control" }],
  "OT-012": [
    { id: "T0855", technique: "Unauthorized Command Message", tactic: "Impair Process Control" },
    { id: "T0856", technique: "Spoof Reporting Message", tactic: "Impair Process Control" },
  ],
  "OT-013": [{ id: "T0856", technique: "Spoof Reporting Message", tactic: "Impair Process Control" }],
  "OT-014": [
    { id: "T0859", technique: "Valid Accounts", tactic: "Lateral Movement" },
    { id: "T0855", technique: "Unauthorized Command Message", tactic: "Impair Process Control" },
  ],
  "OT-015": [{ id: "T0814", technique: "Denial of Service", tactic: "Inhibit Response Function" }],
  "OT-016": [
    { id: "T0855", technique: "Unauthorized Command Message", tactic: "Impair Process Control" },
    { id: "T0836", technique: "Modify Parameter", tactic: "Impair Process Control" },
  ],
  "OT-017": [
    { id: "T0813", technique: "Denial of Control", tactic: "Inhibit Response Function" },
    { id: "T0815", technique: "Denial of View", tactic: "Inhibit Response Function" },
  ],
  "OT-018": [
    { id: "T0859", technique: "Valid Accounts", tactic: "Lateral Movement" },
    { id: "T0855", technique: "Unauthorized Command Message", tactic: "Impair Process Control" },
  ],
  "OT-019": [{ id: "T0885", technique: "Commonly Used Port", tactic: "Command and Control" }],
};

// Keyword fallback for events without a known rule id.
const KEYWORD_FALLBACK = {
  GOOSE: [{ id: "T0856", technique: "Spoof Reporting Message", tactic: "Impair Process Control" }],
  MMS: [{ id: "T0855", technique: "Unauthorized Command Message", tactic: "Impair Process Control" }],
  MODBUS: [{ id: "T0836", technique: "Modify Parameter", tactic: "Impair Process Control" }],
  IOC: [{ id: "T0885", technique: "Commonly Used Port", tactic: "Command and Control" }],
  SCAN: [{ id: "T0846", technique: "Remote System Discovery", tactic: "Discovery" }],
  DEFAULT: [{ id: "T0840", technique: "Network Connection Enumeration", tactic: "Discovery" }],
};

export function mitreForEvent(event) {
  const rid = String(event?.rule_id || "").trim().toUpperCase();
  if (MITRE_ICS[rid]) return MITRE_ICS[rid];
  const blob = `${event?.rule_id || ""} ${event?.event_type || ""} ${event?.description || ""}`.toUpperCase();
  for (const key of ["GOOSE", "MMS", "MODBUS", "IOC", "SCAN"]) {
    if (blob.includes(key)) return KEYWORD_FALLBACK[key];
  }
  return KEYWORD_FALLBACK.DEFAULT;
}
