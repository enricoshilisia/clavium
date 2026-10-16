import { useState } from "react";

import type { RecordInput, VaultRecord } from "../types";
import PasswordGenerator from "./PasswordGenerator";

interface Props {
  initial: VaultRecord | null;
  onSave: (input: RecordInput) => Promise<void>;
  onDelete?: () => void;
  onCancel: () => void;
  busy: boolean;
  error: string | null;
}

export default function RecordForm({ initial, onSave, onDelete, onCancel, busy, error }: Props) {
  const [title, setTitle] = useState(initial?.title ?? "");
  const [username, setUsername] = useState(initial?.username ?? "");
  const [password, setPassword] = useState(initial?.password ?? "");
  const [url, setUrl] = useState(initial?.url ?? "");
  const [notes, setNotes] = useState(initial?.notes ?? "");
  const [showPassword, setShowPassword] = useState(false);
  const [showGenerator, setShowGenerator] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    await onSave({ title, username, password, url, notes });
  }

  return (
    <form className="record-form" onSubmit={submit}>
      <div>
        <label className="clv-label" htmlFor="rf-title">
          Title
        </label>
        <input
          id="rf-title"
          className="clv-input"
          value={title}
          onChange={(e) => setTitle(e.currentTarget.value)}
          placeholder="e.g. Company email"
          autoFocus
          required
        />
      </div>

      <div>
        <label className="clv-label" htmlFor="rf-username">
          Username / email
        </label>
        <input
          id="rf-username"
          className="clv-input"
          value={username}
          onChange={(e) => setUsername(e.currentTarget.value)}
        />
      </div>

      <div>
        <label className="clv-label" htmlFor="rf-password">
          Password
        </label>
        <div className="password-row">
          <input
            id="rf-password"
            className="clv-input"
            type={showPassword ? "text" : "password"}
            value={password}
            onChange={(e) => setPassword(e.currentTarget.value)}
          />
          <button
            type="button"
            className="clv-btn clv-btn-ghost"
            onClick={() => setShowPassword((v) => !v)}
          >
            {showPassword ? "Hide" : "Show"}
          </button>
          <button type="button" className="clv-btn clv-btn-ghost" onClick={() => setShowGenerator(true)}>
            Generate
          </button>
        </div>
      </div>

      <div>
        <label className="clv-label" htmlFor="rf-url">
          Website
        </label>
        <input
          id="rf-url"
          className="clv-input"
          value={url}
          onChange={(e) => setUrl(e.currentTarget.value)}
          placeholder="https://"
        />
      </div>

      <div>
        <label className="clv-label" htmlFor="rf-notes">
          Notes
        </label>
        <textarea
          id="rf-notes"
          className="clv-input"
          rows={4}
          value={notes}
          onChange={(e) => setNotes(e.currentTarget.value)}
        />
      </div>

      {error && <div className="clv-notice clv-notice-danger">{error}</div>}

      <div className="record-form-actions">
        <button type="submit" className="clv-btn clv-btn-primary" disabled={busy}>
          {busy ? "Saving…" : "Save"}
        </button>
        <button type="button" className="clv-btn" onClick={onCancel}>
          Cancel
        </button>
        {onDelete && (
          <button type="button" className="clv-btn clv-btn-danger" onClick={onDelete}>
            Delete
          </button>
        )}
      </div>

      {showGenerator && (
        <PasswordGenerator
          onClose={() => setShowGenerator(false)}
          onUse={(generated) => {
            setPassword(generated);
            setShowPassword(true);
            setShowGenerator(false);
          }}
        />
      )}
    </form>
  );
}
