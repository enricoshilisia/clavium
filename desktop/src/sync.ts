// Desktop sync: the same protocol as the mobile app. The browser side only
// moves ciphertext; Rust (via Tauri) decrypts, merges and decides.
import { getKeyring, pullItems, pushItems, putKeyring, type AccountSession } from "./account";
import { syncApplyPull, syncKeyringHeader, syncMarkPushed, syncState } from "./api";
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
