import { useEffect, useState } from "react";

import { getKeyring, type AccountSession } from "../account";
import { defaultVaultPath, errorMessage, vaultCreate, vaultExists, vaultListRecords, vaultRestoreFromKeyring, vaultUnlock } from "../api";
import { pull } from "../sync";
import { LoggedOut } from "./AccountPanel";
import type { VaultRecord } from "../types";
import logo from "../assets/clavium-logo.png";

interface Props {
  onUnlocked: (records: VaultRecord[]) => void;
}

/**
 * The only screen shown before a vault is open. Resolves to the same,
 * single on-disk vault every launch (the app-data directory's `vault.clv`)
 * rather than asking the person to browse for a file — a vault is created
 * once and then always unlocked, never "found" again by accident.
 */
export default function UnlockScreen({ onUnlocked }: Props) {
  const [path, setPath] = useState<string | null>(null);
  const [exists, setExists] = useState<boolean | null>(null);
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [restoring, setRestoring] = useState(false);
  const [restoreSession, setRestoreSession] = useState<AccountSession | null>(null);

  useEffect(() => {
    (async () => {
      const resolved = await defaultVaultPath();
      setPath(resolved);
      setExists(await vaultExists(resolved));
    })();
  }, []);

  async function handleUnlock(e: React.FormEvent) {
    e.preventDefault();
    if (!path) return;
    setError(null);
    setBusy(true);
    try {
      const records = await vaultUnlock(path, password);
      onUnlocked(records);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    if (!path) return;
    setError(null);
    if (password.length < 10) {
      setError("Use at least 10 characters for the master password.");
      return;
    }
    if (password !== confirmPassword) {
      setError("The two master passwords do not match.");
      return;
    }
    setBusy(true);
    try {
      await vaultCreate(path, password);
      onUnlocked([]);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  async function handleRestore(e: React.FormEvent) {
    e.preventDefault();
    if (!path || !restoreSession) return;
    setError(null);
    setBusy(true);
    try {
      const ring = await getKeyring(restoreSession);
      if (!ring) throw new Error("This account has no synced vault yet. Create a vault instead, then turn on sync.");
      await vaultRestoreFromKeyring(path, JSON.stringify(ring.header), password);
      localStorage.setItem("clavium.sync.keyringRevision", String(ring.revision));
      await pull(restoreSession);
      onUnlocked(await vaultListRecords());
    } catch (err) {
      setError(errorMessage(err instanceof Error ? err.message : err));
    } finally {
      setBusy(false);
    }
  }

  if (restoring) {
    return (
      <div className="unlock-wrap">
        <div className="clv-card unlock-card">
          <div className="unlock-brand">
            <img src={logo} alt="" width="34" height="34" className="unlock-brand-mark" />
            <div>
              <div className="unlock-brand-name">Clavium</div>
              <div className="unlock-brand-sub">Restore from your account</div>
            </div>
          </div>
          {!restoreSession ? (
            <LoggedOut onLoggedIn={setRestoreSession} submitLabel="Sign in" />
          ) : (
            <form onSubmit={handleRestore} className="unlock-form">
              <p className="account-intro">Signed in as {restoreSession.email}. Now unlock with your master password.</p>
              <input
                className="clv-input"
                type="password"
                autoFocus
                placeholder="Master password"
                value={password}
                onChange={(e) => setPassword(e.currentTarget.value)}
              />
              {exists && <p className="faint">The vault already on this computer will be kept aside as a backup file.</p>}
              {error && <div className="clv-notice clv-notice-danger">{error}</div>}
              <button type="submit" className="clv-btn clv-btn-primary" disabled={busy || !password}>
                {busy ? "Restoring…" : "Restore vault"}
              </button>
            </form>
          )}
          <button className="clv-btn clv-btn-ghost" onClick={() => setRestoring(false)}>
            Back
          </button>
        </div>
      </div>
    );
  }

  if (exists === null) {
    return (
      <div className="unlock-wrap">
        <div className="unlock-mark" />
      </div>
    );
  }

  return (
    <div className="unlock-wrap">
      <div className="clv-card unlock-card">
        <div className="unlock-brand">
          <img src={logo} alt="" width="34" height="34" className="unlock-brand-mark" />
          <div>
            <div className="unlock-brand-name">Clavium</div>
            <div className="unlock-brand-sub">
              {exists ? "Unlock your vault" : "Create your vault"}
            </div>
          </div>
        </div>

        <form onSubmit={exists ? handleUnlock : handleCreate} className="unlock-form">
          <div>
            <label className="clv-label" htmlFor="master-password">
              Master password
            </label>
            <input
              id="master-password"
              className="clv-input"
              type="password"
              autoFocus
              value={password}
              onChange={(e) => setPassword(e.currentTarget.value)}
              placeholder="••••••••••••"
            />
          </div>

          {!exists && (
            <div>
              <label className="clv-label" htmlFor="confirm-password">
                Confirm master password
              </label>
              <input
                id="confirm-password"
                className="clv-input"
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.currentTarget.value)}
                placeholder="••••••••••••"
              />
            </div>
          )}

          {error && <div className="clv-notice clv-notice-danger">{error}</div>}

          <button type="submit" className="clv-btn clv-btn-primary" disabled={busy || !password}>
            {busy ? "Working…" : exists ? "Unlock" : "Create vault"}
          </button>
        </form>

        <button className="clv-btn clv-btn-ghost" onClick={() => setRestoring(true)}>
          {exists ? "Use the vault from my account instead" : "I already use Clavium: restore from my account"}
        </button>

        {!exists && (
          <p className="unlock-warning">
            If this master password is lost, the vault cannot be opened, unless
            you create a recovery key later under Security.
          </p>
        )}
      </div>
    </div>
  );
}
