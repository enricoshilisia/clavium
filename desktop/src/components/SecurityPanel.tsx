import { useEffect, useState } from "react";

import { errorMessage, vaultChangeMasterPassword, vaultCreateRecoveryKey, vaultHealth } from "../api";
import { loadSession } from "../account";
import {
  autoCheckEnabled,
  breachState,
  checkBreaches,
  getEmailBreaches,
  onBreachChange,
  setAutoCheck,
  setEmailBreachCheck,
  type EmailBreaches,
} from "../breach";
import { unlockInfo } from "../sync";
import type { HealthReport, VaultRecord } from "../types";

interface Props {
  records: VaultRecord[];
  onClose: () => void;
  onOpen: (id: string) => void;
  onChanged: () => void;
  minPasswordLength: number;
}

export default function SecurityPanel({ records, onClose, onOpen, onChanged, minPasswordLength }: Props) {
  const [health, setHealth] = useState<HealthReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [recoveryKey, setRecoveryKey] = useState<string | null>(null);
  const [pw1, setPw1] = useState("");
  const [pw2, setPw2] = useState("");

  useEffect(() => {
    vaultHealth().then(setHealth).catch((e) => setError(errorMessage(e)));
  }, [records]);

  // ---- breaches ----
  const [, rerender] = useState(0);
  const [checking, setChecking] = useState(false);
  const [auto, setAuto] = useState(autoCheckEnabled);
  const [emailStatus, setEmailStatus] = useState<EmailBreaches | null>(null);
  const session = loadSession();
  useEffect(() => onBreachChange(() => rerender((n) => n + 1)), []);
  useEffect(() => {
    if (session) getEmailBreaches(session).then(setEmailStatus).catch(() => setEmailStatus(null));
  }, [session?.token]);
  async function runCheck() {
    setChecking(true);
    setError(null);
    try {
      await checkBreaches();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setChecking(false);
    }
  }
  const personalHits = breachState.hits.filter((h) => !h.team_id && records.some((r) => r.id === h.id));
  const teamHits = breachState.hits.filter((h) => h.team_id);

  const title = (id: string) => records.find((r) => r.id === id)?.title ?? "(deleted)";
  const scoreClass = !health ? "" : health.score >= 80 ? "score-good" : health.score >= 50 ? "score-ok" : "score-bad";

  async function changePassword(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setNotice(null);
    if (pw1 !== pw2) return setError("The two passwords do not match.");
    if (pw1.length < minPasswordLength) return setError(`Use at least ${minPasswordLength} characters.`);
    try {
      await vaultChangeMasterPassword(pw1);
      unlockInfo.passwordLength = pw1.length;
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
            <details className="health-section" open={personalHits.length > 0}>
              <summary>
                Breached <span className={`nav-count ${personalHits.length ? "score-bad" : ""}`}>{breachState.checkedAt ? personalHits.length : "?"}</span>{" "}
                <span className="faint">found in leaked password lists: change these first</span>
              </summary>
              {personalHits.map((h) => (
                <button key={h.id} className="health-item" onClick={() => onOpen(h.id)}>
                  {h.title} <span className="faint">seen {h.count.toLocaleString()} times</span>
                </button>
              ))}
              {teamHits.length > 0 && <div className="faint health-note">Also {teamHits.length} in team vaults (open the team vault to see them).</div>}
              <div className="breach-actions">
                <button className="clv-btn clv-btn-sm" onClick={runCheck} disabled={checking}>
                  {checking ? "Checking…" : "Check now"}
                </button>
                <span className="faint">
                  {breachState.checkedAt ? `Last checked ${new Date(breachState.checkedAt).toLocaleString()}.` : "Not checked yet."} Only a 5-character fingerprint of each
                  password is sent to Have I Been Pwned; the password never leaves this computer.
                </span>
              </div>
              <label className="share-check">
                <input
                  type="checkbox"
                  checked={auto}
                  onChange={(e) => {
                    setAuto(e.currentTarget.checked);
                    setAutoCheck(e.currentTarget.checked);
                  }}
                />{" "}
                Check automatically once a day
              </label>
            </details>
            {section("Weak", "short, common or predictable", health.weak)}
            {section("Reused", "same password on several sites", health.reused.flat())}
            {section("Old", "not changed in a year", health.old)}
            {section("No two-factor code", "logins without an authenticator", health.without_totp)}
          </>
        )}

        {session && emailStatus?.available && (
          <>
            <h3>Your email in data breaches</h3>
            {emailStatus.monitored ? (
              emailStatus.breaches.length === 0 ? (
                <p className="faint">{session.email} was not found in any known breach{emailStatus.checked_at ? ` (checked ${new Date(emailStatus.checked_at).toLocaleDateString()})` : ""}.</p>
              ) : (
                <div className="clv-notice clv-notice-danger">
                  {session.email} appeared in {emailStatus.breaches.length} known breach{emailStatus.breaches.length === 1 ? "" : "es"}:
                  <ul className="breach-list">
                    {emailStatus.breaches.slice(0, 8).map((b) => (
                      <li key={b.name}>
                        <strong>{b.title}</strong> ({b.date}): {b.data.slice(0, 4).join(", ")}
                      </li>
                    ))}
                  </ul>
                  Change your password on those sites and anywhere you reused it.
                </div>
              )
            ) : (
              <p className="faint">Find out if your email address shows up in known data breaches. Only your email address is sent to Have I Been Pwned.</p>
            )}
            {!emailStatus.monitored || emailStatus.opted_in ? (
              <button
                className="clv-btn clv-btn-sm"
                onClick={() =>
                  setEmailBreachCheck(session, !emailStatus.opted_in)
                    .then(setEmailStatus)
                    .catch((e) => setError(errorMessage(e)))
                }
              >
                {emailStatus.opted_in ? "Stop checking my email" : "Check my email"}
              </button>
            ) : (
              <p className="faint">Your organization checks this address every week.</p>
            )}
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
