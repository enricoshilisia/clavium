import { useEffect, useState } from "react";

import {
  bridgeGeneratePairingCode,
  bridgeListPaired,
  bridgeRevokePaired,
  errorMessage,
} from "../api";
import type { PairedExtension } from "../types";

interface Props {
  onClose: () => void;
}

export default function BrowserPanel({ onClose }: Props) {
  const [code, setCode] = useState<string | null>(null);
  const [secondsLeft, setSecondsLeft] = useState(0);
  const [paired, setPaired] = useState<PairedExtension[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function refreshPaired() {
    try {
      setPaired(await bridgeListPaired());
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  useEffect(() => {
    refreshPaired();
  }, []);

  useEffect(() => {
    if (secondsLeft <= 0) return;
    const interval = setInterval(() => setSecondsLeft((s) => Math.max(0, s - 1)), 1000);
    return () => clearInterval(interval);
  }, [secondsLeft]);

  async function generate() {
    setError(null);
    try {
      const newCode = await bridgeGeneratePairingCode();
      setCode(newCode);
      setSecondsLeft(120);
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  async function revoke(id: string) {
    try {
      await bridgeRevokePaired(id);
      await refreshPaired();
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  return (
    <div className="modal-backdrop" onMouseDown={onClose}>
      <div className="clv-card account-card" onMouseDown={(e) => e.stopPropagation()}>
        <div className="generator-header">
          <h2>Browser extension</h2>
          <button className="clv-btn clv-btn-ghost" onClick={onClose} aria-label="Close">
            ✕
          </button>
        </div>

        <p className="account-intro">
          Install the Clavium extension in your browser, then pair it here to fill
          saved passwords on websites. The extension only ever reaches this app on
          your own computer — nothing it does touches the network.
        </p>

        {error && <div className="clv-notice clv-notice-danger">{error}</div>}

        {code ? (
          <div className="pairing-code-box">
            <div className="pairing-code">{code}</div>
            <div className="faint">
              {secondsLeft > 0 ? `Expires in ${secondsLeft}s` : "Expired — generate a new one"}
            </div>
          </div>
        ) : null}

        <button className="clv-btn clv-btn-primary" onClick={generate}>
          {code ? "Generate a new code" : "Generate pairing code"}
        </button>

        <div className="clv-label account-backups-label">Connected browsers</div>
        <div className="account-backups">
          {paired === null && <div className="vault-empty">Loading…</div>}
          {paired?.length === 0 && <div className="vault-empty">None yet.</div>}
          {paired?.map((p) => (
            <div key={p.id} className="account-backup-row">
              <span>{p.label}</span>
              <span className="account-backup-meta">
                {new Date(p.paired_at * 1000).toLocaleString()}
              </span>
              <button className="clv-btn clv-btn-ghost clv-btn-sm" onClick={() => revoke(p.id)}>
                Revoke
              </button>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
