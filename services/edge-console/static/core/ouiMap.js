// Offline OUI → vendor lookup for common industrial / OT equipment makers.
// Best-effort (not the full IEEE registry); unknown prefixes return null and
// the caller falls back to a placeholder. Keys are the first 3 MAC octets,
// uppercase, colon-separated.

const OUI = {
  // Siemens
  "00:0E:8C": "Siemens", "00:1B:1B": "Siemens", "00:1F:F8": "Siemens",
  "28:63:36": "Siemens", "20:87:56": "Siemens", "8C:F3:19": "Siemens", "AC:64:17": "Siemens",
  // Schneider Electric / Telemecanique / Modicon
  "00:00:54": "Schneider Electric", "00:80:F4": "Schneider Electric", "00:0B:BF": "Schneider Electric",
  // Rockwell / Allen-Bradley
  "00:00:BC": "Rockwell", "00:1D:9C": "Rockwell", "5C:88:16": "Rockwell",
  // ABB
  "00:24:59": "ABB", "AC:D3:64": "ABB",
  // Schweitzer Engineering Labs (SEL)
  "00:30:A7": "SEL",
  // Moxa
  "00:90:E8": "Moxa", "00:23:7B": "Moxa",
  // Hirschmann / Belden
  "00:80:63": "Hirschmann",
  // Phoenix Contact
  "00:A0:45": "Phoenix Contact", "A8:74:1D": "Phoenix Contact",
  // Beckhoff
  "00:01:05": "Beckhoff",
  // WAGO
  "00:30:DE": "WAGO",
  // Mitsubishi Electric
  "00:1F:75": "Mitsubishi Electric",
  // Emerson / Rosemount
  "00:0A:DD": "Emerson",
  // Honeywell
  "00:40:84": "Honeywell",
  // Yokogawa
  "00:00:64": "Yokogawa",
};

export function ouiVendor(mac) {
  if (!mac) return null;
  const m = String(mac).toUpperCase().replace(/-/g, ":").trim();
  const parts = m.split(":");
  if (parts.length < 3) return null;
  const prefix = `${parts[0]}:${parts[1]}:${parts[2]}`;
  return OUI[prefix] || null;
}
