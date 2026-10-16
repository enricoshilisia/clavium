import { useEffect, useState } from "react";

import {
  backupVault,
  listBackups,
  loadSession,
  login,
  logout,
  registerAccount,
  type AccountSession,
  type SnapshotMeta,
} from "../account";
import { vaultExportSealed } from "../api";

interface Props {
  onClose: () => void;
}

type Mode = "login" | "register";

export default function AccountPanel({ onClose }: Props) {
  const [session, setSession] = useState<AccountSession | null>(() => loadSession());

  return (
    <div className="modal-backdrop" onMouseDown={onClose}>
      <div className="clv-card account-card" onMouseDown={(e) => e.stopPropagation()}>
        <div className="generator-header">
          <h2>Account</h2>
          <button className="clv-btn clv-btn-ghost" onClick={onClose} aria-label="Close">
            ✕
          </button>
        </div>

        {session ? (
          <LoggedIn session={session} onLoggedOut={() => setSession(null)} />
        ) : (
          <LoggedOut onLoggedIn={setSession} />
        )}
      </div>
    </div>
  );
}

function LoggedOut({ onLoggedIn }: { onLoggedIn: (session: AccountSession) => void }) {
  const [mode, setMode] = useState<Mode>("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      if (mode === "register") {
        await registerAccount(email, password);
        setNotice("Account created. Signing you in…");
      }
      const session = await login(email, password);
      onLoggedIn(session);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="unlock-form">
      <p className="account-intro">
        An account enables encrypted backup of this vault — a separate secret from
        your master password, which the account server never sees.
      </p>

      <div>
        <label className="clv-label" htmlFor="acc-email">
          Email
        </label>
        <input
          id="acc-email"
          className="clv-input"
          type="email"
          value={email}
          onChange={(e) => setEmail(e.currentTarget.value)}
          required
          autoFocus
        />
      </div>

      <div>
        <label className="clv-label" htmlFor="acc-password">
          Account password
        </label>
        <input
          id="acc-password"
          className="clv-input"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.currentTarget.value)}
          required
          minLength={10}
        />
      </div>

      {notice && <div className="clv-notice clv-notice-success">{notice}</div>}
      {error && <div className="clv-notice clv-notice-danger">{error}</div>}

      <button type="submit" className="clv-btn clv-btn-primary" disabled={busy}>
        {busy ? "Working…" : mode === "login" ? "Sign in" : "Create account"}
      </button>

      <button
        type="button"
        className="clv-btn clv-btn-ghost"
        onClick={() => {
          setMode(mode === "login" ? "register" : "login");
          setError(null);
          setNotice(null);
        }}
      >
        {mode === "login" ? "Need an account? Create one" : "Already have an account? Sign in"}
      </button>
    </form>
  );
}

function LoggedIn({ session, onLoggedOut }: { session: AccountSession; onLoggedOut: () => void }) {
  const [backups, setBackups] = useState<SnapshotMeta[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  async function refresh() {
    try {
      setBackups(await listBackups(session));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  useEffect(() => {
    refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function doBackup() {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const sealed = await vaultExportSealed();
      const snapshot = await backupVault(session, sealed);
      setNotice(`Backed up as version ${snapshot.version}.`);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  async function doLogout() {
    setBusy(true);
    try {
      await logout(session);
      onLoggedOut();
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <p className="account-intro">
        Signed in as <strong>{session.email}</strong>
      </p>

      {error && <div className="clv-notice clv-notice-danger">{error}</div>}
      {notice && <div className="clv-notice clv-notice-success">{notice}</div>}

      <div className="account-actions">
        <button className="clv-btn clv-btn-primary" onClick={doBackup} disabled={busy}>
          {busy ? "Working…" : "Back up vault now"}
        </button>
        <button className="clv-btn" onClick={doLogout} disabled={busy}>
          Sign out
        </button>
      </div>

      <div className="clv-label account-backups-label">Backup history</div>
      <div className="account-backups">
        {backups === null && <div className="vault-empty">Loading…</div>}
        {backups?.length === 0 && <div className="vault-empty">No backups yet.</div>}
        {backups?.map((b) => (
          <div key={b.id} className="account-backup-row">
            <span>v{b.version}</span>
            <span className="account-backup-meta">
              {(b.size_bytes / 1024).toFixed(1)} KB · {b.uploaded_by_device ?? "unknown device"}
            </span>
            <span className="account-backup-meta">{new Date(b.created_at).toLocaleString()}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
