import { useMemo, useState } from "react";

import { errorMessage, vaultAddRecord, vaultDeleteRecord, vaultUpdateRecord } from "../api";
import type { RecordInput, VaultRecord } from "../types";
import logo from "../assets/clavium-logo.png";
import RecordForm from "./RecordForm";

interface Props {
  records: VaultRecord[];
  onRecordsChange: (records: VaultRecord[]) => void;
  onLock: () => void;
  autoLockMinutes: number;
}

type Mode = "view" | "edit" | "add";

export default function VaultView({ records, onRecordsChange, onLock, autoLockMinutes }: Props) {
  const [search, setSearch] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [mode, setMode] = useState<Mode>("view");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [revealPassword, setRevealPassword] = useState(false);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    const sorted = [...records].sort((a, b) => a.title.localeCompare(b.title));
    if (!q) return sorted;
    return sorted.filter(
      (r) =>
        r.title.toLowerCase().includes(q) ||
        r.username.toLowerCase().includes(q) ||
        r.url.toLowerCase().includes(q),
    );
  }, [records, search]);

  const selected = records.find((r) => r.id === selectedId) ?? null;

  function selectRecord(record: VaultRecord) {
    setSelectedId(record.id);
    setMode("view");
    setRevealPassword(false);
    setError(null);
  }

  function startAdd() {
    setSelectedId(null);
    setMode("add");
    setError(null);
  }

  async function saveNew(input: RecordInput) {
    setBusy(true);
    setError(null);
    try {
      const created = await vaultAddRecord(input);
      onRecordsChange([...records, created]);
      setSelectedId(created.id);
      setMode("view");
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  async function saveEdit(input: RecordInput) {
    if (!selected) return;
    setBusy(true);
    setError(null);
    try {
      const updated = await vaultUpdateRecord(selected.id, input);
      onRecordsChange(records.map((r) => (r.id === updated.id ? updated : r)));
      setMode("view");
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  async function deleteSelected() {
    if (!selected) return;
    if (!window.confirm(`Delete "${selected.title}"? This cannot be undone.`)) return;
    setBusy(true);
    setError(null);
    try {
      await vaultDeleteRecord(selected.id);
      onRecordsChange(records.filter((r) => r.id !== selected.id));
      setSelectedId(null);
      setMode("view");
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  async function copy(text: string) {
    if (!text) return;
    await navigator.clipboard.writeText(text);
  }

  return (
    <div className="vault-shell">
      <aside className="vault-sidebar">
        <div className="vault-sidebar-top">
          <div className="vault-brand">
            <img src={logo} alt="" width="18" height="18" />
            Clavium
          </div>
          <button className="clv-btn clv-btn-ghost" onClick={onLock} title={`Auto-locks after ${autoLockMinutes} min idle`}>
            Lock
          </button>
        </div>

        <input
          className="clv-input"
          placeholder="Search records…"
          value={search}
          onChange={(e) => setSearch(e.currentTarget.value)}
        />

        <button className="clv-btn clv-btn-gold vault-add-btn" onClick={startAdd}>
          + New record
        </button>

        <div className="vault-list clv-scrollbar">
          {filtered.length === 0 && <div className="vault-empty">No records found.</div>}
          {filtered.map((record) => (
            <button
              key={record.id}
              className={`vault-list-item ${record.id === selectedId ? "vault-list-item-active" : ""}`}
              onClick={() => selectRecord(record)}
            >
              <div className="vault-list-item-title">{record.title || "(untitled)"}</div>
              <div className="vault-list-item-sub">{record.username || record.url || "—"}</div>
            </button>
          ))}
        </div>
      </aside>

      <main className="vault-main">
        {mode === "add" && (
          <div className="clv-card detail-card">
            <h2>New record</h2>
            <RecordForm
              initial={null}
              onSave={saveNew}
              onCancel={() => setMode("view")}
              busy={busy}
              error={error}
            />
          </div>
        )}

        {mode === "edit" && selected && (
          <div className="clv-card detail-card">
            <h2>Edit record</h2>
            <RecordForm
              initial={selected}
              onSave={saveEdit}
              onCancel={() => setMode("view")}
              busy={busy}
              error={error}
            />
          </div>
        )}

        {mode === "view" && selected && (
          <div className="clv-card detail-card">
            <div className="detail-header">
              <h2>{selected.title || "(untitled)"}</h2>
              <div className="detail-header-actions">
                <button className="clv-btn" onClick={() => setMode("edit")}>
                  Edit
                </button>
                <button className="clv-btn clv-btn-danger" onClick={deleteSelected}>
                  Delete
                </button>
              </div>
            </div>

            <DetailField label="Username" value={selected.username} onCopy={() => copy(selected.username)} />
            <DetailField
              label="Password"
              value={revealPassword ? selected.password : "•".repeat(Math.max(selected.password.length, 8))}
              onCopy={() => copy(selected.password)}
              extra={
                <button className="clv-btn clv-btn-ghost" onClick={() => setRevealPassword((v) => !v)}>
                  {revealPassword ? "Hide" : "Show"}
                </button>
              }
              mono
            />
            <DetailField label="Website" value={selected.url} onCopy={() => copy(selected.url)} link />
            {selected.notes && (
              <div className="detail-field">
                <div className="clv-label">Notes</div>
                <div className="detail-notes">{selected.notes}</div>
              </div>
            )}

            <div className="detail-meta">
              Updated {new Date(selected.updated_at).toLocaleString()}
            </div>
          </div>
        )}

        {mode === "view" && !selected && (
          <div className="vault-placeholder">
            <p>Select a record, or create a new one.</p>
          </div>
        )}
      </main>
    </div>
  );
}

function DetailField({
  label,
  value,
  onCopy,
  extra,
  mono,
  link,
}: {
  label: string;
  value: string;
  onCopy: () => void;
  extra?: React.ReactNode;
  mono?: boolean;
  link?: boolean;
}) {
  return (
    <div className="detail-field">
      <div className="clv-label">{label}</div>
      <div className="detail-field-row">
        {link && value ? (
          <a href={value} target="_blank" rel="noreferrer" className="detail-field-value">
            {value}
          </a>
        ) : (
          <span className={`detail-field-value ${mono ? "detail-field-mono" : ""}`}>
            {value || "—"}
          </span>
        )}
        {extra}
        <button className="clv-btn clv-btn-ghost" onClick={onCopy} disabled={!value}>
          Copy
        </button>
      </div>
    </div>
  );
}
