// Thin fetch wrapper. On 401 it dispatches an "edge:unauthorized" event so the
// shell can show the login view without this module importing the router.

export async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(opts.headers || {}) },
    credentials: "same-origin",
    ...opts,
  });
  if (res.status === 401) {
    window.dispatchEvent(new CustomEvent("edge:unauthorized"));
    throw new Error("未登入");
  }
  const text = await res.text();
  let data = {};
  try { data = text ? JSON.parse(text) : {}; } catch { data = { detail: text }; }
  if (!res.ok) throw new Error(data.detail || data.error || res.statusText);
  return data;
}

export const get = (path) => api(path);
export const post = (path, body) => api(path, { method: "POST", body: body == null ? undefined : JSON.stringify(body) });
export const put = (path, body) => api(path, { method: "PUT", body: JSON.stringify(body) });
export const del = (path) => api(path, { method: "DELETE" });
