import { useEffect, useState } from "react";

import { defaultVaultPath, errorMessage, vaultCreate, vaultExists, vaultUnlock } from "../api";
import type { VaultRecord } from "../types";

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
    if (password.length < 8) {
      setError("Use at least 8 characters for the master password.");
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
          <ClaviumMark />
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

        {!exists && (
          <p className="unlock-warning">
            There is no account recovery. If this master password is lost, the
            vault's contents are lost with it — that is what makes them
            unreadable to anyone else, too.
          </p>
        )}
      </div>
    </div>
  );
}

function ClaviumMark() {
  return (
    <svg width="34" height="34" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <circle cx="12" cy="12" r="11" stroke="var(--clv-gold-400)" strokeWidth="1.2" />
      <path
        d="M9 12.5a3 3 0 1 1 1.2 2.4M9 12.5a3 3 0 1 1 1.2-2.4"
        stroke="var(--clv-blue-300)"
        strokeWidth="1.4"
      />
      <path
        d="M10.5 12.5H17M14.5 12.5V15M17 12.5V15"
        stroke="var(--clv-gold-400)"
        strokeWidth="1.6"
        strokeLinecap="round"
      />
    </svg>
  );
}
