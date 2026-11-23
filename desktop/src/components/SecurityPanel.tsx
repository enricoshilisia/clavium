import { useEffect, useState } from "react";

import { errorMessage, vaultChangeMasterPassword, vaultCreateRecoveryKey, vaultHealth } from "../api";
import type { HealthReport, VaultRecord } from "../types";

interface Props {
  records: VaultRecord[];
  onClose: () => void;
  onOpen: (id: string) => void;
  onChanged: () => void;
}

export default function SecurityPanel({ records, onClose, onOpen, onChanged }: Props) {
  const [health, setHealth] = useState<HealthReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [recoveryKey, setRecoveryKey] = useState<string | null>(null);
  const [pw1, setPw1] = useState("");
  const [pw2, setPw2] = useState("");

  useEffect(() => {
    vaultHealth().then(setHealth).catch((e) => setError(errorMessage(e)));
  }, [records]);

  const title = (id: string) => records.find((r) => r.id === id)?.title ?? "(deleted)";
  const scoreClass = !health ? "" : health.score >= 80 ? "score-good" : health.score >= 50 ? "score-ok" : "score-bad";

  async function changePassword(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setNotice(null);
    if (pw1 !== pw2) return setError("The two passwords do not match.");
    try {
      await vaultChangeMasterPassword(pw1);
      setPw1("");
      setPw2("");
      setNotice("Master password changed.");
      onChanged();
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  async function makeRecoveryKey() {
    setError(null);
    try {
      setRecoveryKey(await vaultCreateRecoveryKey());
      onChanged();
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  const section = (label: string, help: string, ids: string[]) => (
    <details className="health-section">
      <summary>
        {label} <span className="nav-count">{ids.length}</span> <span className="faint">{help}</span>
      </summary>
      {ids.map((id) => (
        <button key={id} className="health-item" onClick={() => onOpen(id)}>
          {title(id)}
        </button>
      ))}
    </details>
  );

  return (
    <div className="modal-backdrop" onMouseDown={onClose}>
      <div className="clv-card account-card security-card clv-scrollbar" onMouseDown={(e) => e.stopPropagation()}>
        <div className="generator-header">
          <h2>Security</h2>
          <button className="clv-btn clv-btn-ghost" onClick={onClose} aria-label="Close">
            ✕
          </button>
        </div>
        {health && (
          <>
            <div className={`health-score ${scoreClass}`}>
              {health.score}
              <span className="faint"> / 100 password health, checked on this computer only</span>
            </div>
            {section("Weak", "short, common or predictable", health.weak)}
            {section("Reused", "same password on several sites", health.reused.flat())}
            {section("Old", "not changed in a year", health.old)}
            {section("No two-factor code", "logins without an authenticator", health.without_totp)}
          </>
        )}

        <h3>Master password</h3>
        <form className="unlock-form" onSubmit={changePassword}>
          <input className="clv-input" type="password" placeholder="New master password" value={pw1} onChange={(e) => setPw1(e.currentTarget.value)} minLength={10} required />
          <input className="clv-input" type="password" placeholder="Type it again" value={pw2} onChange={(e) => setPw2(e.currentTarget.value)} required />
          <button className="clv-btn" type="submit">
            Change master password
          </button>
        </form>

        <h3>Recovery key</h3>
        <p className="faint">Opens your vault if you forget the master password. Shown once; keep it offline.</p>
        {recoveryKey ? (
          <div className="pairing-code-box">
            <code className="pairing-code recovery-code">{recoveryKey}</code>
          </div>
        ) : (
          <button className="clv-btn" onClick={makeRecoveryKey}>
            Create a recovery key
          </button>
        )}
        {notice && <div className="clv-notice clv-notice-success">{notice}</div>}
        {error && <div className="clv-notice clv-notice-danger">{error}</div>}
      </div>
    </div>
  );
}
