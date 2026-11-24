// Breached-password check. Only the first 5 characters of each password's
// SHA-1 go to Have I Been Pwned; matching happens in Rust on this computer.

import { invoke } from "@tauri-apps/api/core";

import { api, type AccountSession } from "./account";

export interface BreachHit {
  id: string;
  title: string;
  count: number;
  team_id: string | null;
}

const AUTO_KEY = "clavium.breach.auto";
const LAST_KEY = "clavium.breach.last";
const DAY = 24 * 60 * 60_000;

export const breachState: { checkedAt: number | null; hits: BreachHit[] } = { checkedAt: null, hits: [] };
const listeners = new Set<() => void>();
export function onBreachChange(fn: () => void) {
  listeners.add(fn);
  return () => void listeners.delete(fn);
}

export function autoCheckEnabled(): boolean {
  try {
    return localStorage.getItem(AUTO_KEY) !== "off";
  } catch {
    return true;
  }
}

export function setAutoCheck(on: boolean) {
  try {
    localStorage.setItem(AUTO_KEY, on ? "on" : "off");
  } catch {
    // per-device convenience only
  }
}

async function fetchRange(prefix: string): Promise<string> {
  const r = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, { headers: { "Add-Padding": "true" } });
  if (!r.ok) throw new Error(`The breach service answered ${r.status}. Try again later.`);
  return r.text();
}

/** Check every saved password (personal and team vaults). */
export async function checkBreaches(): Promise<BreachHit[]> {
  const prefixes = await invoke<string[]>("breach_prefixes");
  const ranges: Record<string, string> = {};
  // A few at a time: polite to the free service, quick enough for a vault.
  for (let i = 0; i < prefixes.length; i += 6) {
    const batch = prefixes.slice(i, i + 6);
    const bodies = await Promise.all(batch.map(fetchRange));
    batch.forEach((p, j) => (ranges[p] = bodies[j]));
  }
  const hits = await invoke<BreachHit[]>("breach_apply", { ranges });
  breachState.hits = hits;
  breachState.checkedAt = Date.now();
  try {
    localStorage.setItem(LAST_KEY, String(breachState.checkedAt));
  } catch {
    // fine
  }
  listeners.forEach((fn) => fn());
  return hits;
}

/** Run once a day while unlocked, unless turned off. */
export async function maybeAutoCheck() {
  if (!autoCheckEnabled()) return;
  if (breachState.checkedAt && Date.now() - breachState.checkedAt < DAY) return;
  try {
    await checkBreaches();
  } catch {
    // offline: try again later
  }
}

export function forgetBreaches() {
  breachState.hits = [];
  breachState.checkedAt = null;
}

export const breachedPersonalCount = () => breachState.hits.filter((h) => !h.team_id).length;

export interface EmailBreaches {
  available: boolean;
  monitored: boolean;
  opted_in: boolean;
  checked_at: string | null;
  breaches: { name: string; title: string; domain: string; date: string; data: string[] }[];
}

export const getEmailBreaches = (s: AccountSession): Promise<EmailBreaches> => api(s, "GET", "/api/breaches/mine/");
export const setEmailBreachCheck = (s: AccountSession, enabled: boolean): Promise<EmailBreaches> => api(s, "POST", "/api/breaches/mine/", { enabled });
