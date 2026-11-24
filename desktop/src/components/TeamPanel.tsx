import { useCallback, useEffect, useState } from "react";

import type { AccountSession } from "../account";
import {
  addGroupRule,
  addMember,
  changeRole,
  createTeam,
  deleteTeam,
  fingerprintOf,
  getMembers,
  keyWarnings,
  removeGroupRule,
  removeMember,
  renameTeam,
  ROLE_LABELS,
  searchGroups,
  trustNewKey,
  type MembersView,
  type OrgInfo,
  type TeamInfo,
  type TeamRole,
} from "../teams";

const ROLES: TeamRole[] = ["manager", "editor", "viewer"];

function message(e: unknown) {
  return e instanceof Error ? e.message : String(e);
}

/** Create a team vault. */
export function NewTeamPanel({ session, orgs, onClose, onCreated }: { session: AccountSession; orgs: OrgInfo[]; onClose: () => void; onCreated: (t: TeamInfo) => void }) {
  const creatable = orgs.filter((o) => o.can_create);
  const [org, setOrg] = useState(creatable[0]?.id ?? "");
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      onCreated(await createTeam(session, org, name.trim()));
    } catch (err) {
      setError(message(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="modal-backdrop" onMouseDown={onClose}>
      <form className="clv-card account-card" onMouseDown={(e) => e.stopPropagation()} onSubmit={submit}>
        <div className="generator-header">
          <h2>New team vault</h2>
          <button type="button" className="clv-btn clv-btn-ghost" onClick={onClose} aria-label="Close">
            ✕
          </button>
        </div>
        <p className="account-intro">
          A shared vault for a team, for example Finance or IT. Everything in it is encrypted so only the people you add can read it.
          Not even the Clavium server or your organization's admins can, unless they are added.
        </p>
        {creatable.length > 1 && (
          <div>
            <label className="clv-label" htmlFor="team-org">
              Organization
            </label>
            <select id="team-org" className="clv-input" value={org} onChange={(e) => setOrg(e.currentTarget.value)}>
              {creatable.map((o) => (
                <option key={o.id} value={o.id}>
                  {o.name}
                </option>
              ))}
            </select>
          </div>
        )}
        <div>
          <label className="clv-label" htmlFor="team-name">
            Name
          </label>
          <input id="team-name" className="clv-input" value={name} onChange={(e) => setName(e.currentTarget.value)} placeholder="e.g. Finance" required autoFocus />
        </div>
        {error && <div className="clv-notice clv-notice-danger">{error}</div>}
        <button type="submit" className="clv-btn clv-btn-primary" disabled={busy || !org || !name.trim()}>
          {busy ? "Creating…" : "Create team vault"}
        </button>
      </form>
    </div>
  );
}

/** Members, roles, Microsoft 365 groups and key checks for one team vault. */
export default function TeamPanel({ session, team, onClose, onChanged }: { session: AccountSession; team: TeamInfo; onClose: () => void; onChanged: (gone?: boolean) => void }) {
  const [view, setView] = useState<MembersView | null>(null);
  const [fingerprints, setFingerprints] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [addWho, setAddWho] = useState("");
  const [addRole, setAddRole] = useState<TeamRole>("editor");
  const [groupQuery, setGroupQuery] = useState("");
  const [groups, setGroups] = useState<{ id: string; name: string }[] | null>(null);
  const [groupsConnected, setGroupsConnected] = useState(true);
  const [groupRole, setGroupRole] = useState<TeamRole>("editor");
  const [name, setName] = useState(team.name);
  const manage = view?.can_manage ?? team.can_manage;
  const warnings = keyWarnings.filter((w) => w.team === team.name);

  const load = useCallback(async () => {
    try {
      const v = await getMembers(session, team.id);
      setView(v);
      const fps: Record<string, string> = {};
      for (const m of v.members) if (m.public_key) fps[m.account_id] = await fingerprintOf(m.public_key);
      setFingerprints(fps);
    } catch (e) {
      setError(message(e));
    }
  }, [session, team.id]);

  useEffect(() => {
    load();
  }, [load]);

  async function act(fn: () => Promise<unknown>, gone = false) {
    setBusy(true);
    setError(null);
    try {
      await fn();
      if (gone) {
        onChanged(true);
        onClose();
        return;
      }
      await load();
      onChanged();
    } catch (e) {
      setError(message(e));
    } finally {
      setBusy(false);
    }
  }

  const candidate = view?.candidates?.find((c) => c.account_id === addWho);

  return (
    <div className="modal-backdrop" onMouseDown={onClose}>
      <div className="clv-card account-card team-card" onMouseDown={(e) => e.stopPropagation()}>
        <div className="generator-header">
          <h2>{team.name}</h2>
          <button className="clv-btn clv-btn-ghost" onClick={onClose} aria-label="Close">
            ✕
          </button>
        </div>
        <p className="account-intro">
          {team.organization.name} team vault. Only the people below can read it. {team.role ? `You: ${ROLE_LABELS[team.role]}.` : "You manage it as an organization admin but cannot read it."}
        </p>
        {error && <div className="clv-notice clv-notice-danger">{error}</div>}
        {team.needs_rotation && (
          <div className="clv-notice">Someone who had access left. A manager's app replaces the key automatically the next time it syncs.</div>
        )}
        {warnings.map((w) => (
          <div key={w.account_id + w.public_key} className="clv-notice clv-notice-danger">
            {w.email}'s key changed (new fingerprint <code>{w.fingerprint}</code>). This happens when they reset their vault, but could also mean
            someone is trying to intercept. Ask them to read out the fingerprint shown in their Account panel before trusting it.{" "}
            <button className="clv-btn clv-btn-ghost clv-btn-sm" disabled={busy} onClick={() => act(() => trustNewKey(session, team, w))}>
              It matches, trust it
            </button>
          </div>
        ))}

        <div className="clv-label">People</div>
        <div className="team-members">
          {!view && <div className="faint">Loading…</div>}
          {view?.members.map((m) => (
            <div key={m.account_id} className="team-member">
              <div className="team-member-who">
                <div>{m.name || m.email}</div>
                <div className="faint team-member-sub">
                  {m.name ? `${m.email} · ` : ""}
                  {m.has_key ? "has access" : "waiting for access"}
                  {m.source === "group" ? " · from a Microsoft 365 group" : ""}
                  {fingerprints[m.account_id] ? (
                    <>
                      {" · key "}
                      <code>{fingerprints[m.account_id]}</code>
                    </>
                  ) : null}
                </div>
              </div>
              {manage ? (
                <>
                  <select className="clv-input team-role" value={m.role} disabled={busy} onChange={(e) => act(() => changeRole(session, team.id, m.account_id, e.currentTarget.value as TeamRole))}>
                    {ROLES.map((r) => (
                      <option key={r} value={r}>
                        {ROLE_LABELS[r]}
                      </option>
                    ))}
                  </select>
                  <button
                    className="clv-btn clv-btn-ghost clv-btn-sm"
                    disabled={busy}
                    title="Remove"
                    onClick={() => window.confirm(`Remove ${m.email} from ${team.name}?`) && act(() => removeMember(session, team.id, m.account_id))}
                  >
                    Remove
                  </button>
                </>
              ) : (
                <span className="pill">{ROLE_LABELS[m.role]}</span>
              )}
            </div>
          ))}
        </div>

        {manage && view?.candidates && (
          <div className="team-add">
            <select className="clv-input" value={addWho} onChange={(e) => setAddWho(e.currentTarget.value)}>
              <option value="">Add someone from {team.organization.name}…</option>
              {view.candidates.map((c) => (
                <option key={c.account_id} value={c.account_id}>
                  {c.name ? `${c.name} (${c.email})` : c.email}
                  {c.public_key ? "" : " · not signed in yet"}
                </option>
              ))}
            </select>
            <select className="clv-input team-role" value={addRole} onChange={(e) => setAddRole(e.currentTarget.value as TeamRole)}>
              {ROLES.map((r) => (
                <option key={r} value={r}>
                  {ROLE_LABELS[r]}
                </option>
              ))}
            </select>
            <button
              className="clv-btn clv-btn-primary"
              disabled={busy || !candidate}
              onClick={() =>
                candidate &&
                act(async () => {
                  await addMember(session, team, candidate, addRole);
                  setAddWho("");
                })
              }
            >
              Add
            </button>
          </div>
        )}

        {manage && (
          <>
            <div className="clv-label" style={{ marginTop: 16 }}>
              Microsoft 365 groups
            </div>
            <p className="faint team-help">Everyone in a chosen group gets access, and loses it when they leave the group or the company.</p>
            {view?.group_rules?.map((g) => (
              <div key={g.group_id} className="team-member">
                <div className="team-member-who">{g.group_name}</div>
                <span className="pill">{ROLE_LABELS[g.role]}</span>
                <button className="clv-btn clv-btn-ghost clv-btn-sm" disabled={busy} onClick={() => act(() => removeGroupRule(session, team.id, g.group_id))}>
                  Remove
                </button>
              </div>
            ))}
            {groupsConnected ? (
              <form
                className="team-add"
                onSubmit={(e) => {
                  e.preventDefault();
                  act(async () => {
                    const r = await searchGroups(session, team.id, groupQuery);
                    setGroupsConnected(r.connected);
                    setGroups(r.groups);
                  });
                }}
              >
                <input className="clv-input" placeholder="Search groups, e.g. Finance" value={groupQuery} onChange={(e) => setGroupQuery(e.currentTarget.value)} />
                <select className="clv-input team-role" value={groupRole} onChange={(e) => setGroupRole(e.currentTarget.value as TeamRole)}>
                  {ROLES.map((r) => (
                    <option key={r} value={r}>
                      {ROLE_LABELS[r]}
                    </option>
                  ))}
                </select>
                <button className="clv-btn" type="submit" disabled={busy}>
                  Search
                </button>
              </form>
            ) : (
              <p className="faint team-help">Your organization has not connected Microsoft 365 in the Clavium console.</p>
            )}
            {groups?.map((g) => (
              <div key={g.id} className="team-member">
                <div className="team-member-who">{g.name}</div>
                <button
                  className="clv-btn clv-btn-sm"
                  disabled={busy}
                  onClick={() =>
                    act(async () => {
                      await addGroupRule(session, team.id, g.id, groupRole);
                      setGroups(null);
                    })
                  }
                >
                  Give {ROLE_LABELS[groupRole].toLowerCase()} access
                </button>
              </div>
            ))}
            {groups?.length === 0 && <p className="faint team-help">No groups match.</p>}

            <div className="clv-label" style={{ marginTop: 16 }}>
              Settings
            </div>
            <div className="team-add">
              <input className="clv-input" value={name} onChange={(e) => setName(e.currentTarget.value)} />
              <button className="clv-btn" disabled={busy || !name.trim() || name === team.name} onClick={() => act(() => renameTeam(session, team.id, name.trim()))}>
                Rename
              </button>
            </div>
            <button
              className="clv-btn clv-btn-danger"
              style={{ marginTop: 8 }}
              disabled={busy}
              onClick={() =>
                window.confirm(`Delete ${team.name} and everything in it for everyone? This cannot be undone.`) && act(() => deleteTeam(session, team.id), true)
              }
            >
              Delete team vault
            </button>
          </>
        )}
        {!manage && team.role && (
          <button
            className="clv-btn clv-btn-ghost"
            style={{ marginTop: 12 }}
            disabled={busy}
            onClick={() => window.confirm(`Leave ${team.name}? You will need a manager to add you back.`) && act(() => removeMember(session, team.id, session.accountId ?? ""), true)}
          >
            Leave this team vault
          </button>
        )}
      </div>
    </div>
  );
}
