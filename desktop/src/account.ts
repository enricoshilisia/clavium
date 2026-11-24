// The Clavium account layer, separate from the vault's master password.
// Everything sent to the control plane is either account credentials or
// ciphertext produced by the Rust core.

import { controlPlaneUrl } from "./config";
import { emailNotAllowed, managed } from "./managed";
export type { AccountSession as Session };

const STORAGE_KEYS = {
  token: "clavium.account.token",
  serverDeviceId: "clavium.account.serverDeviceId",
  clientDeviceId: "clavium.account.clientDeviceId",
  email: "clavium.account.email",
  server: "clavium.account.server",
  accountId: "clavium.account.id",
};

export interface AccountSession {
  token: string;
  email: string;
  serverDeviceId: string;
  /** Missing for sessions saved before team vaults; see ensureAccountId. */
  accountId?: string;
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
  // A session belongs to the server that issued it. If IT has since
  // pointed this computer at another server, sign in again there.
  // (Sessions saved before this was recorded belong to the default.)
  const server = localStorage.getItem(STORAGE_KEYS.server);
  if (server && server !== controlPlaneUrl()) return null;
  return { token, email, serverDeviceId, accountId: localStorage.getItem(STORAGE_KEYS.accountId) ?? undefined };
}

function saveSession(session: AccountSession) {
  localStorage.setItem(STORAGE_KEYS.token, session.token);
  localStorage.setItem(STORAGE_KEYS.email, session.email);
  localStorage.setItem(STORAGE_KEYS.serverDeviceId, session.serverDeviceId);
  localStorage.setItem(STORAGE_KEYS.server, controlPlaneUrl());
  if (session.accountId) localStorage.setItem(STORAGE_KEYS.accountId, session.accountId);
}

function clearSession() {
  localStorage.removeItem(STORAGE_KEYS.token);
  localStorage.removeItem(STORAGE_KEYS.email);
  localStorage.removeItem(STORAGE_KEYS.serverDeviceId);
  localStorage.removeItem(STORAGE_KEYS.server);
  localStorage.removeItem(STORAGE_KEYS.accountId);
  // clientDeviceId is kept deliberately — it identifies this install, and
  // re-logging in should reuse (and rotate the token on) the same device
  // row rather than silently accumulating a new one every time.
}

async function apiFetch(path: string, options: RequestInit = {}) {
  const response = await fetch(`${controlPlaneUrl()}${path}`, {
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
  if (managed().disable_account_creation) throw new Error("Your organization manages Clavium accounts. Use the invite you were sent.");
  await apiFetch("/api/accounts/register/", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });
}

export async function login(email: string, password: string): Promise<AccountSession> {
  const blocked = emailNotAllowed(email);
  if (blocked) throw new Error(blocked);
  const clientDeviceId = getOrCreateClientDeviceId();
  const data = await apiFetch("/api/accounts/devices/register/", {
    method: "POST",
    body: JSON.stringify({
      email,
      password,
      client_device_id: clientDeviceId,
      name: `Clavium Desktop (${navigator.platform || "computer"})`,
      platform: navigator.platform || "desktop",
    }),
  });
  const session: AccountSession = {
    token: data.token,
    email: data.account.email,
    serverDeviceId: data.device_id,
    accountId: data.account.id,
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

// ---- per-record sync ----

export interface KeyringResponse {
  vault_id: string;
  header: unknown;
  revision: number;
  counter: number;
}

export class ApiError extends Error {
  constructor(public status: number, message: string, public body?: unknown) {
    super(message);
  }
}

async function apiCall(session: AccountSession, method: string, path: string, body?: unknown) {
  let response: Response;
  try {
    response = await fetch(`${controlPlaneUrl()}${path}`, {
      method,
      headers: { "Content-Type": "application/json", ...authHeader(session) },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new ApiError(0, "Could not reach the server. Check your connection.");
  }
  let data: any = null;
  try {
    data = await response.json();
  } catch {
    // empty or non-JSON body
  }
  if (!response.ok) {
    let msg = data?.detail ?? `Request failed (HTTP ${response.status})`;
    if (response.status === 401) msg = "This computer was signed out. Sign in again.";
    if (response.status === 429) msg = "Too many attempts. Wait a minute and try again.";
    if (response.status === 404 && !data?.detail) {
      msg = "The Clavium server has not been updated for sync yet. Your vault is safe on this computer; sync starts once the server is updated.";
    }
    throw new ApiError(response.status, msg, data);
  }
  return data;
}

/** Any authenticated call; used by the team vault client. */
export function api(session: AccountSession, method: string, path: string, body?: unknown) {
  return apiCall(session, method, path, body);
}

/** Older sessions did not store the account id; fetch it once. */
export async function ensureAccountId(session: AccountSession): Promise<string> {
  if (session.accountId) return session.accountId;
  const me = await apiCall(session, "GET", "/api/accounts/me/");
  session.accountId = me.id as string;
  localStorage.setItem(STORAGE_KEYS.accountId, session.accountId);
  return session.accountId;
}

export async function getKeyring(session: AccountSession): Promise<KeyringResponse | null> {
  try {
    return await apiCall(session, "GET", "/api/sync/keyring/");
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) return null;
    throw e;
  }
}

export function putKeyring(session: AccountSession, vaultId: string, header: unknown, baseRevision: number): Promise<KeyringResponse> {
  return apiCall(session, "PUT", "/api/sync/keyring/", { vault_id: vaultId, header, base_revision: baseRevision });
}

export function pullItems(session: AccountSession, since: number, wait = false) {
  return apiCall(session, "GET", `/api/sync/items/?since=${since}${wait ? "&wait=1" : ""}`);
}

export function pushItems(session: AccountSession, vaultId: string, items: unknown[]) {
  return apiCall(session, "POST", "/api/sync/items/", { vault_id: vaultId, items });
}

export interface Policy {
  min_master_password_length: number;
  max_auto_lock_minutes: number;
  allow_export: boolean;
  require_recovery_key: boolean;
  organizations: string[];
}

export function getPolicy(session: AccountSession): Promise<Policy> {
  return apiCall(session, "GET", "/api/orgs/policy/mine/");
}

/** Aggregate counts only: never which items or passwords. */
export function reportHealth(session: AccountSession, counts: Record<string, number | boolean>) {
  return apiCall(session, "POST", "/api/orgs/health/", counts);
}

export { controlPlaneUrl };
