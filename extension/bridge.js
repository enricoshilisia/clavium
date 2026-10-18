// The extension's only line of communication with the outside world: the
// local bridge the desktop app runs on 127.0.0.1. No other network calls
// exist in this extension — see manifest.json's own host_permissions,
// which names exactly this and nothing else.

const BRIDGE_ORIGIN = "http://127.0.0.1:37849";

async function getToken() {
  const { clavium_token } = await chrome.storage.local.get("clavium_token");
  return clavium_token || null;
}

async function setToken(token) {
  await chrome.storage.local.set({ clavium_token: token });
}

async function clearToken() {
  await chrome.storage.local.remove("clavium_token");
}

async function bridgeFetch(path, options = {}) {
  const token = await getToken();
  const headers = { ...(options.headers || {}) };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  let response;
  try {
    response = await fetch(`${BRIDGE_ORIGIN}${path}`, { ...options, headers });
  } catch {
    throw new Error("not-running");
  }

  if (response.status === 401) {
    await clearToken();
    throw new Error("not-paired");
  }
  if (response.status === 423) {
    throw new Error("locked");
  }
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.error || `request failed (${response.status})`);
  }
  return response.status === 204 ? null : response.json();
}

async function pair(code, label) {
  const response = await fetch(`${BRIDGE_ORIGIN}/pair`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ code, label }),
  }).catch(() => {
    throw new Error("not-running");
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.error || "pairing failed");
  }
  const { token } = await response.json();
  await setToken(token);
}

async function status() {
  return bridgeFetch("/status");
}

async function search(host) {
  return bridgeFetch(`/search?host=${encodeURIComponent(host)}`);
}

async function reveal(id) {
  return bridgeFetch(`/reveal?id=${encodeURIComponent(id)}`);
}
