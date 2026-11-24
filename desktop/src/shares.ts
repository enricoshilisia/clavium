// Share links and the phishing guard. Encryption happens in Rust; the key
// goes only into the link's #fragment, never to the server.

import { invoke } from "@tauri-apps/api/core";

import { api, type AccountSession } from "./account";

export interface LinkCheck {
  verdict: "trusted" | "unknown" | "suspicious" | "dangerous";
  host: string;
  domain: string;
  reasons: string[];
  imitates: string | null;
  official: string | null;
}

export const checkLink = (url: string) => invoke<LinkCheck>("check_link", { url });

export interface ShareOptions {
  recordId?: string;
  teamId?: string;
  text?: string;
  title: string;
  passphrase?: string;
  includeTotp?: boolean;
  hours: number;
  views: number;
}

export interface SentLink {
  id: string;
  created_at: string;
  expires_at: string;
  views: number;
  max_views: number;
  has_passphrase: boolean;
  status: "active" | "used" | "expired" | "revoked" | "locked";
  last_opened_at: string | null;
  title?: string;
}

const TITLES = "clavium.share.titles";

function titles(): Record<string, string> {
  try {
    return JSON.parse(localStorage.getItem(TITLES) || "{}");
  } catch {
    return {};
  }
}

export async function createShare(session: AccountSession, o: ShareOptions): Promise<{ url: string; expires_at: string }> {
  const made = await invoke<{ draft: any; rounds: number }>("share_create", {
    id: o.recordId ?? null,
    teamId: o.teamId ?? null,
    text: o.text ?? null,
    title: o.title,
    passphrase: o.passphrase?.trim() || null,
    includeTotp: o.includeTotp ?? false,
  });
  const { link_key, ...draft } = made.draft;
  const out = await api(session, "POST", "/api/shares/", { ...draft, rounds: made.rounds, expires_in_hours: o.hours, max_views: o.views });
  // Only the title is remembered here, so the sender recognises the link.
  const t = titles();
  t[out.id] = o.title;
  localStorage.setItem(TITLES, JSON.stringify(t));
  return { url: `${out.url}#${link_key}`, expires_at: out.expires_at };
}

export async function listShares(session: AccountSession): Promise<SentLink[]> {
  const rows: SentLink[] = await api(session, "GET", "/api/shares/");
  const t = titles();
  return rows.map((r) => ({ ...r, title: t[r.id] }));
}

export const revokeShare = (session: AccountSession, id: string) => api(session, "DELETE", `/api/shares/${id}/`);

export const STATUS_LABELS: Record<SentLink["status"], string> = {
  active: "Waiting to be opened",
  used: "Opened",
  expired: "Expired",
  revoked: "Cancelled",
  locked: "Locked after wrong passphrases",
};
