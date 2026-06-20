const els = {
  dot: document.getElementById("state-dot"),
  state: document.getElementById("state-text"),
  fanRpm: document.getElementById("fan-rpm"),
  needle: document.getElementById("rpm-needle"),
  voltage: document.getElementById("voltage"),
  voltageBar: document.getElementById("voltage-bar"),
  breaker: document.getElementById("breaker"),
  alarm: document.getElementById("alarm"),
  device: document.getElementById("device"),
  profile: document.getElementById("profile"),
  updated: document.getElementById("updated"),
};

function setState(ok, label) {
  els.dot.classList.toggle("ok", ok);
  els.state.textContent = label;
}

function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}

function render(payload) {
  const readings = payload.readings || {};
  const rpm = Number(readings.FanRPM || 0);
  const voltage = Number(readings.Voltage || 0);
  const alarm = Number(readings.AlarmStatus || 0);
  const breaker = Boolean(readings.BreakerClosed);
  const rpmRatio = clamp(rpm / 3600, 0, 1);
  const voltageRatio = clamp(voltage / 30, 0, 1);

  els.fanRpm.textContent = String(Math.round(rpm));
  els.needle.style.transform = `rotate(${Math.round(-140 + rpmRatio * 280)}deg)`;
  els.voltage.textContent = voltage.toFixed(2);
  els.voltageBar.style.width = `${Math.round(voltageRatio * 100)}%`;
  els.breaker.textContent = breaker ? "closed" : "open";
  els.alarm.textContent = String(alarm);
  els.device.textContent = `device: ${payload.device || "-"}`;
  els.profile.textContent = `profile: ${payload.profile || "-"}`;
  els.updated.textContent = `updated: ${new Date().toLocaleTimeString()}`;
}

async function refresh() {
  try {
    const response = await fetch("/api/edgex/latest", { cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    render(await response.json());
    setState(true, "Live");
  } catch (error) {
    setState(false, "Offline");
    els.updated.textContent = `error: ${error.message}`;
  }
}

refresh();
setInterval(refresh, 3000);
