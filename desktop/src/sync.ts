// Desktop sync: the same protocol as the mobile app. The browser side only
// moves ciphertext; Rust (via Tauri) decrypts, merges and decides.
import { breachedPersonalCount } from "./breach";
import { getKeyring, getPolicy, pullItems, pushItems, putKeyring, reportHealth, type AccountSession, type Policy } from "./account";
import { syncApplyPull, syncKeyringHeader, syncMarkPushed, syncState, vaultHealth } from "./api";
import type { EncryptedItem } from "./types";

const KEYRING_REV = "clavium.sync.keyringRevision";

function canonical(v: unknown): string {
  const norm = (x: unknown): unknown => {
    if (Array.isArray(x)) return x.map(norm);
    if (x && typeof x === "object") {
      return Object.fromEntries(
        Object.keys(x as object)
          .sort()
          .map((k) => [k, norm((x as Record<string, unknown>)[k])]),
      );
    }
    return x;
  };
  return JSON.stringify(norm(v));
}

export interface SyncOutcome {
  changed: number;
  pushed: number;
  notice: string | null;
}

export async function pull(session: AccountSession, wait = false): Promise<number> {
  let changed = 0;
  for (;;) {
    const { cursor } = await syncState();
    const page = await pullItems(session, cursor, wait);
    wait = false;
    if (page.items.length === 0 && page.cursor === cursor) return changed;
    const r = await syncApplyPull(page.items, page.cursor);
    changed += r.added + r.updated + r.deleted + r.conflicts;
    if (!page.has_more) return changed;
  }
}

async function syncKeyring(session: AccountSession, vaultId: string): Promise<string | null> {
  const local = JSON.parse(await syncKeyringHeader());
  const known = Number(localStorage.getItem(KEYRING_REV) ?? "NaN");
  const remote = await getKeyring(session);
  if (!remote) {
    const r = await putKeyring(session, vaultId, local, 0);
    localStorage.setItem(KEYRING_REV, String(r.revision));
    return null;
  }
  if (remote.vault_id !== vaultId) {
    throw new Error(
      "This account already syncs a different vault. Use “Restore from account” on the unlock screen to get it on this computer.",
    );
  }
  if (canonical(remote.header) === canonical(local)) {
    localStorage.setItem(KEYRING_REV, String(remote.revision));
    return null;
  }
  if (known === remote.revision) {
    const r = await putKeyring(session, vaultId, local, known);
    localStorage.setItem(KEYRING_REV, String(r.revision));
    return null;
  }
  return "Your master password or unlock methods were changed on another device. This computer still unlocks the old way until you restore from your account again.";
}

export async function syncNow(session: AccountSession): Promise<SyncOutcome> {
  const st = await syncState();
  const notice = await syncKeyring(session, st.vaultId);
  let changed = await pull(session);
  let pushed = 0;
  for (let attempt = 0; attempt < 3; attempt++) {
    const { vaultId, pending } = await syncState();
    if (pending.length === 0) break;
    let conflict = false;
    for (let i = 0; i < pending.length; i += 500) {
      const chunk = pending.slice(i, i + 500);
      const byId = new Map<string, EncryptedItem>(chunk.map((p) => [p.id, p]));
      const res = await pushItems(session, vaultId, chunk);
      const accepted: { item: EncryptedItem; revision: number }[] = [];
      for (const r of res.results) {
        if (r.status === "accepted") accepted.push({ item: byId.get(r.id)!, revision: r.revision });
        else if (r.status === "conflict") conflict = true;
      }
      if (accepted.length) {
        await syncMarkPushed(accepted);
        pushed += accepted.length;
      }
    }
    if (!conflict) break;
    changed += await pull(session);
  }
  return { changed, pushed, notice };
}

export function forgetKeyringRevision() {
  localStorage.removeItem(KEYRING_REV);
}

// ---- organization policy (cached so auto-lock can read it) ----

const POLICY_KEY = "clavium.policy";
let lastHealthReport = 0;

/** Length of the master password used at the last unlock (never the password). */
export const unlockInfo = { passwordLength: 0 };

export function cachedPolicy(): Policy | null {
  try {
    return JSON.parse(localStorage.getItem(POLICY_KEY) ?? "null");
  } catch {
    return null;
  }
}

export async function afterSync(session: AccountSession, hasRecoveryKey: boolean): Promise<Policy | null> {
  try {
    localStorage.setItem(POLICY_KEY, JSON.stringify(await getPolicy(session)));
  } catch {
    // offline: keep the last known policy
  }
  if (Date.now() - lastHealthReport > 30 * 60_000) {
    try {
      const h = await vaultHealth();
      await reportHealth(session, {
        score: h.score,
        total: h.with_password,
        weak: h.weak.length,
        reused: h.reused.reduce((n, g) => n + g.length, 0),
        old: h.old.length,
        without_totp: h.without_totp.length,
        breached: breachedPersonalCount(),
        has_recovery_key: hasRecoveryKey,
      });
      lastHealthReport = Date.now();
    } catch {
      // reported next time
    }
  }
  return cachedPolicy();
}

export function policyNotices(policy: Policy | null, hasRecoveryKey: boolean): string[] {
  if (!policy || policy.organizations.length === 0) return [];
  const orgs = policy.organizations.join(", ");
  const out: string[] = [];
  if (unlockInfo.passwordLength && unlockInfo.passwordLength < policy.min_master_password_length) {
    out.push(`${orgs} requires a master password of at least ${policy.min_master_password_length} characters. Change it under Security.`);
  }
  if (policy.require_recovery_key && !hasRecoveryKey) out.push(`${orgs} asks you to create a recovery key under Security.`);
  return out;
}
