// Team vaults on the desktop. HTTP happens here; every key and every bit
// of encryption happens in Rust (`team_invoke` -> clavium-api teams).

import { invoke } from "@tauri-apps/api/core";

import { api, ApiError, ensureAccountId, type AccountSession } from "./account";
import type { RecordInput, VaultRecord } from "./types";

export type TeamRole = "manager" | "editor" | "viewer";

export interface TeamInfo {
  id: string;
  name: string;
  organization: { id: string; name: string };
  role: TeamRole | null;
  can_manage: boolean;
  key_version: number;
  needs_rotation: boolean;
  wrapped_key: unknown | null;
  pending: boolean;
}

export interface OrgInfo {
  id: string;
  name: string;
  can_create: boolean;
}

export interface TeamMember {
  account_id: string;
  email: string;
  name: string;
  role: TeamRole;
  source: "manual" | "group";
  has_key: boolean;
  public_key: string | null;
}

export interface MembersView {
  members: TeamMember[];
  can_manage: boolean;
  key_version: number;
  needs_rotation: boolean;
  candidates?: { account_id: string; email: string; name: string; public_key: string | null }[];
  group_rules?: { group_id: string; group_name: string; role: TeamRole }[];
}

export const ROLE_LABELS: Record<TeamRole, string> = { manager: "Manager", editor: "Can edit", viewer: "Can view" };

function core<T = any>(cmd: string, args: Record<string, unknown> = {}): Promise<T> {
  return invoke<T>("team_invoke", { cmd, args });
}

let ready: Promise<void> | null = null;
let readyFor = "";

/** Load (or create and upload) this account's team key. Once per unlock. */
export function ensureTeamKey(session: AccountSession): Promise<void> {
  if (ready && readyFor === session.token) return ready;
  readyFor = session.token;
  ready = (async () => {
    const accountId = await ensureAccountId(session);
    let stored: unknown = null;
    try {
      stored = await api(session, "GET", "/api/teams/key/");
    } catch (e) {
      if (!(e instanceof ApiError && e.status === 404)) throw e;
    }
    const out = await core<{ status: string; stored: unknown }>("team_account_key", { account_id: accountId, stored });
    if (out.status === "created") await api(session, "PUT", "/api/teams/key/", out.stored);
  })().catch((e) => {
    ready = null;
    throw e;
  });
  return ready;
}

/** Call after locking: the Rust side has already forgotten the keys. */
export function forgetTeamKey() {
  ready = null;
  readyFor = "";
}

export async function listTeams(session: AccountSession): Promise<{ teams: TeamInfo[]; organizations: OrgInfo[] }> {
  await ensureTeamKey(session);
  const out = await api(session, "GET", "/api/teams/");
  for (const t of out.teams as TeamInfo[]) {
    if (t.wrapped_key && t.role) {
      await core("team_open", { team_id: t.id, key_version: t.key_version, wrapped_key: t.wrapped_key, role: t.role });
    }
  }
  return out;
}

export function teamRecords(teamId: string): Promise<VaultRecord[]> {
  return core("team_list", { team_id: teamId });
}

/** The form's camelCase input in the shared command layer's shape. */
function toCore(i: RecordInput) {
  return {
    kind: i.kind,
    title: i.title,
    username: i.username,
    password: i.password,
    url: i.url,
    notes: i.notes,
    totp_secret: i.totpSecret,
    fields: i.fields,
    custom_fields: i.customFields,
    category: i.category,
    folder: i.folder,
    tags: i.tags,
    favorite: i.favorite,
  };
}

export const teamAdd = (teamId: string, record: RecordInput) => core<{ record: VaultRecord }>("team_add", { team_id: teamId, record: toCore(record) });
export const teamUpdate = (teamId: string, id: string, record: RecordInput) => core("team_update", { team_id: teamId, id, record: toCore(record) });
export const teamDelete = (teamId: string, id: string) => core("team_delete", { team_id: teamId, id });

/** Push local changes, pull everyone else's. Returns how many arrived. */
export async function syncTeam(session: AccountSession, team: TeamInfo): Promise<number> {
  if (!team.wrapped_key || !team.role) return 0;
  const st = await core<{ cursor: number; pending: any[]; key_version: number }>("team_sync_state", { team_id: team.id });
  if (st.pending.length) {
    try {
      const res = await api(session, "POST", `/api/teams/${team.id}/items/`, { key_version: st.key_version, items: st.pending });
      const byId = new Map(st.pending.map((i) => [i.id, i]));
      const accepted = (res.results as any[]).filter((r) => r.status === "ok").map((r) => ({ item: byId.get(r.id), revision: r.revision }));
      if (accepted.length) await core("team_mark_pushed", { team_id: team.id, accepted });
    } catch (e) {
      if (!(e instanceof ApiError && e.status === 409)) throw e;
      // The key was replaced meanwhile: the next list/open fetches it.
    }
  }
  let cursor = st.cursor;
  let arrived = 0;
  for (;;) {
    const page = await api(session, "GET", `/api/teams/${team.id}/items/?since=${cursor}`);
    if (page.key_version !== st.key_version) break;
    if (page.items.length || page.cursor !== cursor) {
      await core("team_apply_pull", { team_id: team.id, items: page.items, cursor: page.cursor });
      arrived += page.items.length;
    }
    cursor = page.cursor;
    if (!page.has_more) break;
  }
  if (team.role === "manager") await managerDuties(session, team);
  return arrived;
}

export interface KeyWarning {
  team: string;
  email: string;
  account_id: string;
  public_key: string;
  fingerprint: string;
}

/** Warnings about members whose key changed, waiting for a person to check. */
export const keyWarnings: KeyWarning[] = [];

async function wrapFor(teamId: string, m: { account_id: string; public_key: string; email: string }, teamName: string, forRotation = false) {
  try {
    const w = await core<{ wrapped_key: unknown }>("team_wrap_for", { team_id: teamId, account_id: m.account_id, public_key: m.public_key, for_rotation: forRotation });
    return w.wrapped_key;
  } catch (e) {
    const msg = String(e);
    if (msg.startsWith("key_changed")) {
      const fp = await core<string>("team_fingerprint", { public_key: m.public_key });
      if (!keyWarnings.some((k) => k.account_id === m.account_id && k.public_key === m.public_key)) {
        keyWarnings.push({ team: teamName, email: m.email, account_id: m.account_id, public_key: m.public_key, fingerprint: fp });
      }
      return null;
    }
    throw e;
  }
}

/** A manager's app seals keys for pending people and replaces the key
 * after someone who had it left. */
async function managerDuties(session: AccountSession, team: TeamInfo) {
  if (team.needs_rotation) {
    await rotate(session, team);
    return;
  }
  const view: MembersView = await api(session, "GET", `/api/teams/${team.id}/members/`);
  const grants = [];
  for (const m of view.members) {
    if (m.has_key || !m.public_key) continue;
    const wrapped = await wrapFor(team.id, { account_id: m.account_id, public_key: m.public_key, email: m.email }, team.name);
    if (wrapped) grants.push({ account_id: m.account_id, public_key: m.public_key, wrapped_key: wrapped });
  }
  if (grants.length) await api(session, "POST", `/api/teams/${team.id}/grants/`, { key_version: team.key_version, grants });
}

export async function rotate(session: AccountSession, team: TeamInfo) {
  const prep = await core<{ key_version: number; items: unknown[] }>("team_rotate_prepare", { team_id: team.id });
  try {
    const view: MembersView = await api(session, "GET", `/api/teams/${team.id}/members/`);
    const grants = [];
    for (const m of view.members) {
      if (!m.public_key) continue; // no key pair yet: stays pending
      const wrapped = await wrapFor(team.id, { account_id: m.account_id, public_key: m.public_key, email: m.email }, team.name, true);
      if (wrapped) grants.push({ account_id: m.account_id, public_key: m.public_key, wrapped_key: wrapped });
    }
    await api(session, "POST", `/api/teams/${team.id}/rotate/`, { key_version: prep.key_version, items: prep.items, grants });
  } catch (e) {
    await core("team_rotate_cancel", { team_id: team.id });
    throw e;
  }
  await core("team_rotate_commit", { team_id: team.id });
  team.key_version = prep.key_version;
  team.needs_rotation = false;
  // Everything was stored afresh under the new key: pull it all again.
  let cursor = 0;
  for (;;) {
    const page = await api(session, "GET", `/api/teams/${team.id}/items/?since=${cursor}`);
    await core("team_apply_pull", { team_id: team.id, items: page.items, cursor: page.cursor });
    cursor = page.cursor;
    if (!page.has_more) break;
  }
}

export async function createTeam(session: AccountSession, organizationId: string, name: string): Promise<TeamInfo> {
  await ensureTeamKey(session);
  const made = await core<{ team_id: string; wrapped_key: unknown }>("team_create", {});
  try {
    return await api(session, "POST", "/api/teams/", { id: made.team_id, organization_id: organizationId, name, wrapped_key: made.wrapped_key });
  } catch (e) {
    await core("team_close_and_forget", { team_id: made.team_id });
    throw e;
  }
}

export const getMembers = (session: AccountSession, teamId: string): Promise<MembersView> => api(session, "GET", `/api/teams/${teamId}/members/`);

/** Add someone. If they already have a key pair, seal the key for them
 * straight away; otherwise they are pending until they first sign in. */
export async function addMember(session: AccountSession, team: TeamInfo, person: { account_id: string; email: string; public_key: string | null }, role: TeamRole) {
  const body: Record<string, unknown> = { account_id: person.account_id, role };
  if (person.public_key && team.wrapped_key) {
    const wrapped = await wrapFor(team.id, { ...person, public_key: person.public_key }, team.name);
    if (wrapped) Object.assign(body, { public_key: person.public_key, wrapped_key: wrapped, key_version: team.key_version });
  }
  return api(session, "POST", `/api/teams/${team.id}/members/`, body);
}

/** After comparing fingerprints with the person, accept their new key. */
export async function trustNewKey(session: AccountSession, team: TeamInfo, w: KeyWarning) {
  const out = await core<{ wrapped_key: unknown }>("team_wrap_for", { team_id: team.id, account_id: w.account_id, public_key: w.public_key, trust_new: true });
  await api(session, "POST", `/api/teams/${team.id}/grants/`, {
    key_version: team.key_version,
    grants: [{ account_id: w.account_id, public_key: w.public_key, wrapped_key: out.wrapped_key }],
  });
  keyWarnings.splice(keyWarnings.indexOf(w), 1);
}

export const fingerprintOf = (publicKey: string) => core<string>("team_fingerprint", { public_key: publicKey });
export const changeRole = (s: AccountSession, teamId: string, accountId: string, role: TeamRole) => api(s, "PATCH", `/api/teams/${teamId}/members/${accountId}/`, { role });
export const removeMember = (s: AccountSession, teamId: string, accountId: string) => api(s, "DELETE", `/api/teams/${teamId}/members/${accountId}/`);
export const renameTeam = (s: AccountSession, teamId: string, name: string) => api(s, "PATCH", `/api/teams/${teamId}/`, { name });
export const deleteTeam = async (s: AccountSession, teamId: string) => {
  await api(s, "DELETE", `/api/teams/${teamId}/`);
  await core("team_close_and_forget", { team_id: teamId });
};
export const searchGroups = (s: AccountSession, teamId: string, q: string): Promise<{ connected: boolean; groups: { id: string; name: string }[] }> =>
  api(s, "GET", `/api/teams/${teamId}/groups/?q=${encodeURIComponent(q)}`);
export const addGroupRule = (s: AccountSession, teamId: string, groupId: string, role: TeamRole) => api(s, "POST", `/api/teams/${teamId}/groups/`, { group_id: groupId, role });
export const removeGroupRule = (s: AccountSession, teamId: string, groupId: string) => api(s, "DELETE", `/api/teams/${teamId}/groups/?group_id=${encodeURIComponent(groupId)}`);
