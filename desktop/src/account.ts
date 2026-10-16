// The Clavium account layer — entirely separate from the vault's own
// master password (see PLAN.md's security model). This never touches
// vault contents in cleartext: `backupVault` uploads exactly the sealed
// bytes `vault_export_sealed` reads off disk, and the control plane only
// ever stores and returns that same opaque blob.

import { CONTROL_PLANE_URL } from "./config";

const STORAGE_KEYS = {
  token: "clavium.account.token",
  serverDeviceId: "clavium.account.serverDeviceId",
  clientDeviceId: "clavium.account.clientDeviceId",
  email: "clavium.account.email",
};

export interface AccountSession {
  token: string;
  email: string;
  serverDeviceId: string;
}

export interface SnapshotMeta {
  id: string;
  version: number;
  sha256: string;
  size_bytes: number;
  uploaded_by_device: string | null;
  created_at: string;
}

function getOrCreateClientDeviceId(): string {
  let id = localStorage.getItem(STORAGE_KEYS.clientDeviceId);
  if (!id) {
    id = crypto.randomUUID();
    localStorage.setItem(STORAGE_KEYS.clientDeviceId, id);
  }
  return id;
}

export function loadSession(): AccountSession | null {
  const token = localStorage.getItem(STORAGE_KEYS.token);
  const email = localStorage.getItem(STORAGE_KEYS.email);
  const serverDeviceId = localStorage.getItem(STORAGE_KEYS.serverDeviceId);
  if (!token || !email || !serverDeviceId) return null;
  return { token, email, serverDeviceId };
}

function saveSession(session: AccountSession) {
  localStorage.setItem(STORAGE_KEYS.token, session.token);
  localStorage.setItem(STORAGE_KEYS.email, session.email);
  localStorage.setItem(STORAGE_KEYS.serverDeviceId, session.serverDeviceId);
}

function clearSession() {
  localStorage.removeItem(STORAGE_KEYS.token);
  localStorage.removeItem(STORAGE_KEYS.email);
  localStorage.removeItem(STORAGE_KEYS.serverDeviceId);
  // clientDeviceId is kept deliberately — it identifies this install, and
  // re-logging in should reuse (and rotate the token on) the same device
  // row rather than silently accumulating a new one every time.
}

async function apiFetch(path: string, options: RequestInit = {}) {
  const response = await fetch(`${CONTROL_PLANE_URL}${path}`, {
    ...options,
    headers: { "Content-Type": "application/json", ...options.headers },
  });
  if (!response.ok) {
    let detail = `request failed (HTTP ${response.status})`;
    try {
      const body = await response.json();
      detail = body.detail ?? JSON.stringify(body);
    } catch {
      // body wasn't JSON; keep the generic message
    }
    throw new Error(detail);
  }
  if (response.status === 204) return null;
  return response.json();
}

function authHeader(session: AccountSession): HeadersInit {
  return { Authorization: `Bearer ${session.token}` };
}

export async function registerAccount(email: string, password: string): Promise<void> {
  await apiFetch("/api/accounts/register/", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });
}

export async function login(email: string, password: string): Promise<AccountSession> {
  const clientDeviceId = getOrCreateClientDeviceId();
  const data = await apiFetch("/api/accounts/devices/register/", {
    method: "POST",
    body: JSON.stringify({
      email,
      password,
      client_device_id: clientDeviceId,
      name: "Clavium Desktop",
      platform: navigator.platform || "desktop",
    }),
  });
  const session: AccountSession = {
    token: data.token,
    email: data.account.email,
    serverDeviceId: data.device_id,
  };
  saveSession(session);
  return session;
}

export async function logout(session: AccountSession): Promise<void> {
  try {
    await apiFetch(`/api/accounts/devices/${session.serverDeviceId}/revoke/`, {
      method: "POST",
      headers: authHeader(session),
    });
  } finally {
    // Clearing local state is what actually matters to the person using
    // the app — a revoke call that failed to reach the server (offline,
    // server down) shouldn't trap them signed in on this device.
    clearSession();
  }
}

export async function backupVault(session: AccountSession, sealedBase64: string): Promise<SnapshotMeta> {
  return apiFetch("/api/vaults/snapshots/", {
    method: "POST",
    headers: authHeader(session),
    body: JSON.stringify({ blob: sealedBase64 }),
  });
}

export async function listBackups(session: AccountSession): Promise<SnapshotMeta[]> {
  return apiFetch("/api/vaults/snapshots/", { headers: authHeader(session) });
}
