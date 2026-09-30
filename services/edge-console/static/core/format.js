// Time / number formatting. All timestamps render in GMT+8 (Asia/Taipei),
// independent of the browser or host timezone.

const TW_TZ = "Asia/Taipei";
const _fmt = new Intl.DateTimeFormat("zh-TW", {
  timeZone: TW_TZ, hour12: false,
  year: "numeric", month: "2-digit", day: "2-digit",
  hour: "2-digit", minute: "2-digit", second: "2-digit",
});

export function fmtTime(value) {
  if (value === null || value === undefined || value === "") return "—";
  let d;
  if (typeof value === "number") {
    d = new Date(value < 1e12 ? value * 1000 : value);
  } else {
    const s = String(value).trim();
    if (/^\d+$/.test(s)) {
      const n = Number(s);
      d = new Date(n < 1e12 ? n * 1000 : n);
    } else {
      d = new Date(s);
    }
  }
  if (Number.isNaN(d.getTime())) return String(value);
  return _fmt.format(d).replace(/\//g, "-");
}

export function relTime(value) {
  if (!value) return "—";
  let ts;
  if (typeof value === "number") ts = value < 1e12 ? value * 1000 : value;
  else {
    const s = String(value).trim();
    ts = /^\d+$/.test(s) ? (Number(s) < 1e12 ? Number(s) * 1000 : Number(s)) : Date.parse(s);
  }
  if (Number.isNaN(ts)) return String(value);
  const diff = Math.max(0, Date.now() - ts);
  const sec = Math.floor(diff / 1000);
  if (sec < 60) return `${sec}s 前`;
  if (sec < 3600) return `${Math.floor(sec / 60)}m 前`;
  if (sec < 86400) return `${Math.floor(sec / 3600)}h 前`;
  return `${Math.floor(sec / 86400)}d 前`;
}

export function startClock(elId = "#headerClock") {
  const clockFmt = new Intl.DateTimeFormat("zh-TW", {
    timeZone: TW_TZ, hour12: false,
    year: "numeric", month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
  const tick = () => {
    const node = document.querySelector(elId);
    if (node) node.textContent = clockFmt.format(new Date()).replace(/\//g, "-") + " GMT+8";
  };
  tick();
  setInterval(tick, 1000);
}

export function formatRate(n) {
  const v = Number(n) || 0;
  if (v >= 1000) return `${(v / 1000).toFixed(1)}k`;
  return v.toFixed(v >= 10 ? 0 : 1);
}

export function truncate(s, max = 28) {
  const str = String(s ?? "");
  return str.length > max ? str.slice(0, max - 1) + "…" : str;
}

export async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(String(text));
    return true;
  } catch {
    return false;
  }
}
