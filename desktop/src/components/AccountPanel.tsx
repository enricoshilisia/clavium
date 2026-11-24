import { useEffect, useState } from "react";

import { api, loadSession, login, logout, registerAccount, type AccountSession } from "../account";
import { fingerprintOf } from "../teams";
import { emailNotAllowed, managed } from "../managed";
import { forgetKeyringRevision } from "../sync";

interface Props {
  onClose: () => void;
  onSessionChange: (session: AccountSession | null) => void;
  syncError: string | null;
}

export default function AccountPanel({ onClose, onSessionChange, syncError }: Props) {
  const [session, setSession] = useState<AccountSession | null>(() => loadSession());
  const change = (s: AccountSession | null) => {
    setSession(s);
    onSessionChange(s);
  };

  return (
    <div className="modal-backdrop" onMouseDown={onClose}>
      <div className="clv-card account-card" onMouseDown={(e) => e.stopPropagation()}>
        <div className="generator-header">
          <h2>Account and sync</h2>
          <button className="clv-btn clv-btn-ghost" onClick={onClose} aria-label="Close">
            ✕
          </button>
        </div>
        {session ? (
          <LoggedIn session={session} syncError={syncError} onLoggedOut={() => change(null)} />
        ) : (
          <LoggedOut onLoggedIn={change} />
        )}
      </div>
    </div>
  );
}

export function LoggedOut({ onLoggedIn, submitLabel }: { onLoggedIn: (session: AccountSession) => void; submitLabel?: string }) {
  const policy = managed();
  const workDomains = policy.allowed_email_domains.map((d) => `@${d}`).join(" or ");
  const [mode, setMode] = useState<"login" | "register">("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    const blocked = emailNotAllowed(email);
    if (blocked) {
      setError(blocked);
      return;
    }
    setBusy(true);
    setError(null);
    try {
      if (mode === "register") await registerAccount(email, password);
      onLoggedIn(await login(email, password));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="unlock-form">
      <p className="account-intro">
        Sign in to keep this vault in step across your computers and phone. Everything is encrypted on this device first;
        your account password only signs you in and is not your master password.
      </p>
      {policy.managed && (
        <div className="clv-notice">
          Managed by your organization{workDomains ? `. Sign in with your work email (${workDomains})` : ""}
          {policy.disable_account_creation ? ". New accounts come from your IT team's invite." : "."}
        </div>
      )}
      <div>
        <label className="clv-label" htmlFor="acc-email">
          Email
        </label>
        <input id="acc-email" className="clv-input" type="email" placeholder={policy.allowed_email_domains[0] ? `name@${policy.allowed_email_domains[0]}` : undefined} value={email} onChange={(e) => setEmail(e.currentTarget.value)} required autoFocus />
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
      {error && <div className="clv-notice clv-notice-danger">{error}</div>}
      <button type="submit" className="clv-btn clv-btn-primary" disabled={busy}>
        {busy ? "Working…" : submitLabel ?? (mode === "login" ? "Sign in and sync" : "Create account and sync")}
      </button>
      {!policy.disable_account_creation && (
        <button type="button" className="clv-btn clv-btn-ghost" onClick={() => setMode(mode === "login" ? "register" : "login")}>
          {mode === "login" ? "Need an account? Create one" : "Already have an account? Sign in"}
        </button>
      )}
    </form>
  );
}

function LoggedIn({ session, syncError, onLoggedOut }: { session: AccountSession; syncError: string | null; onLoggedOut: () => void }) {
  const [busy, setBusy] = useState(false);
  const [fingerprint, setFingerprint] = useState<string | null>(null);
  useEffect(() => {
    api(session, "GET", "/api/teams/key/")
      .then((k) => fingerprintOf(k.public_key))
      .then(setFingerprint)
      .catch(() => setFingerprint(null));
  }, [session]);
  async function doLogout() {
    setBusy(true);
    try {
      await logout(session);
      forgetKeyringRevision();
      onLoggedOut();
    } finally {
      setBusy(false);
    }
  }
  return (
    <div>
      <p className="account-intro">
        Signed in as <strong>{session.email}</strong>. Changes sync automatically and appear on your other devices within seconds.
      </p>
      {syncError && <div className="clv-notice clv-notice-danger">{syncError}</div>}
      <div className="account-actions">
        <button className="clv-btn" onClick={doLogout} disabled={busy}>
          Sign out on this computer
        </button>
      </div>
      <p className="faint">Signing out stops syncing. Your vault stays on this computer.</p>
      {fingerprint && (
        <p className="faint">
          Your team vault key fingerprint: <code>{fingerprint}</code>. If a manager asks, read this out so they know your key is really yours.
        </p>
      )}
    </div>
  );
}
