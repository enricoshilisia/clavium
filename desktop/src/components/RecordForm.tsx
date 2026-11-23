import { useState } from "react";

import { fieldLabel, KIND_LABELS, kindUses, MULTILINE_FIELDS, SECRET_FIELDS } from "../labels";
import type { CategoryInfo, KindInfo, RecordInput, RecordKind, VaultRecord } from "../types";
import PasswordGenerator from "./PasswordGenerator";

interface Props {
  initial: VaultRecord | null;
  kinds: KindInfo[];
  categories: CategoryInfo[];
  folders: string[];
  onSave: (input: RecordInput) => Promise<void>;
  onCancel: () => void;
  busy: boolean;
  error: string | null;
}

export default function RecordForm({ initial, kinds, categories, folders, onSave, onCancel, busy, error }: Props) {
  const [kind, setKind] = useState<RecordKind>(initial?.kind ?? "login");
  const [title, setTitle] = useState(initial?.title ?? "");
  const [username, setUsername] = useState(initial?.username ?? "");
  const [password, setPassword] = useState(initial?.password ?? "");
  const [url, setUrl] = useState(initial?.url ?? "");
  const [notes, setNotes] = useState(initial?.notes ?? "");
  const [totpSecret, setTotpSecret] = useState(initial?.totp_secret ?? "");
  const [fields, setFields] = useState<Record<string, string>>(initial?.fields ?? {});
  const [category, setCategory] = useState<string>(initial?.category_source === "user" ? (initial.category ?? "") : "");
  const [folder, setFolder] = useState(initial?.folder ?? "");
  const [tags, setTags] = useState((initial?.tags ?? []).join(", "));
  const [favorite, setFavorite] = useState(initial?.favorite ?? false);
  const [showPassword, setShowPassword] = useState(false);
  const [showGenerator, setShowGenerator] = useState(false);

  const uses = kindUses(kind);
  const kindFields = kinds.find((k) => k.kind === kind)?.fields ?? [];

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    await onSave({
      kind,
      title,
      username: uses.username ? username : "",
      password: uses.password ? password : "",
      url: uses.url ? url : "",
      notes,
      totpSecret: uses.totp && totpSecret.trim() ? totpSecret.trim() : null,
      fields: Object.fromEntries(kindFields.filter((f) => fields[f]).map((f) => [f, fields[f]])),
      customFields: initial?.custom_fields ?? [],
      category: category || null,
      folder: folder.trim() || null,
      tags: tags
        .split(",")
        .map((t) => t.trim())
        .filter(Boolean),
      favorite,
    });
  }

  return (
    <form className="record-form" onSubmit={submit}>
      {!initial && (
        <div>
          <label className="clv-label" htmlFor="rf-kind">
            Type
          </label>
          <select id="rf-kind" className="clv-input" value={kind} onChange={(e) => setKind(e.currentTarget.value as RecordKind)}>
            {kinds
              .filter((k) => k.kind !== "passkey")
              .map((k) => (
                <option key={k.kind} value={k.kind}>
                  {KIND_LABELS[k.kind]}
                </option>
              ))}
          </select>
        </div>
      )}

      <div>
        <label className="clv-label" htmlFor="rf-title">
          Title
        </label>
        <input id="rf-title" className="clv-input" value={title} onChange={(e) => setTitle(e.currentTarget.value)} autoFocus required />
      </div>

      {uses.username && (
        <div>
          <label className="clv-label" htmlFor="rf-username">
            Username / email
          </label>
          <input id="rf-username" className="clv-input" value={username} onChange={(e) => setUsername(e.currentTarget.value)} />
        </div>
      )}

      {uses.password && (
        <div>
          <label className="clv-label" htmlFor="rf-password">
            {kind === "wifi" ? "Wi-Fi password" : "Password"}
          </label>
          <div className="password-row">
            <input
              id="rf-password"
              className="clv-input"
              type={showPassword ? "text" : "password"}
              value={password}
              onChange={(e) => setPassword(e.currentTarget.value)}
            />
            <button type="button" className="clv-btn clv-btn-ghost" onClick={() => setShowPassword((v) => !v)}>
              {showPassword ? "Hide" : "Show"}
            </button>
            <button type="button" className="clv-btn clv-btn-ghost" onClick={() => setShowGenerator(true)}>
              Generate
            </button>
          </div>
        </div>
      )}

      {uses.url && (
        <div>
          <label className="clv-label" htmlFor="rf-url">
            Website
          </label>
          <input id="rf-url" className="clv-input" value={url} onChange={(e) => setUrl(e.currentTarget.value)} placeholder="https://" />
        </div>
      )}

      {kindFields.map((f) => (
        <div key={f}>
          <label className="clv-label" htmlFor={`rf-f-${f}`}>
            {fieldLabel(f)}
          </label>
          {MULTILINE_FIELDS.has(f) ? (
            <textarea
              id={`rf-f-${f}`}
              className="clv-input detail-field-mono"
              rows={4}
              value={fields[f] ?? ""}
              onChange={(e) => setFields({ ...fields, [f]: e.currentTarget.value })}
            />
          ) : (
            <input
              id={`rf-f-${f}`}
              className="clv-input"
              type={SECRET_FIELDS.has(f) ? "password" : "text"}
              value={fields[f] ?? ""}
              onChange={(e) => setFields({ ...fields, [f]: e.currentTarget.value })}
            />
          )}
        </div>
      ))}

      {uses.totp && (
        <div>
          <label className="clv-label" htmlFor="rf-totp">
            Authenticator secret (optional)
          </label>
          <input
            id="rf-totp"
            className="clv-input"
            value={totpSecret}
            onChange={(e) => setTotpSecret(e.currentTarget.value)}
            placeholder="Setup key or otpauth:// link from the site's two-factor screen"
          />
        </div>
      )}

      <div>
        <label className="clv-label" htmlFor="rf-notes">
          Notes
        </label>
        <textarea id="rf-notes" className="clv-input" rows={3} value={notes} onChange={(e) => setNotes(e.currentTarget.value)} />
      </div>

      <div className="form-grid-2">
        <div>
          <label className="clv-label" htmlFor="rf-cat">
            Category
          </label>
          <select id="rf-cat" className="clv-input" value={category} onChange={(e) => setCategory(e.currentTarget.value)}>
            <option value="">Automatic</option>
            {categories.map((c) => (
              <option key={c.slug} value={c.slug}>
                {c.label}
              </option>
            ))}
          </select>
        </div>
        <div>
          <label className="clv-label" htmlFor="rf-folder">
            Folder
          </label>
          <input id="rf-folder" className="clv-input" list="rf-folders" value={folder} onChange={(e) => setFolder(e.currentTarget.value)} />
          <datalist id="rf-folders">
            {folders.map((f) => (
              <option key={f} value={f} />
            ))}
          </datalist>
        </div>
      </div>

      <div>
        <label className="clv-label" htmlFor="rf-tags">
          Tags (comma separated)
        </label>
        <input id="rf-tags" className="clv-input" value={tags} onChange={(e) => setTags(e.currentTarget.value)} />
      </div>

      <label className="generator-toggle">
        <input type="checkbox" checked={favorite} onChange={(e) => setFavorite(e.currentTarget.checked)} /> Favourite
      </label>

      {error && <div className="clv-notice clv-notice-danger">{error}</div>}

      <div className="record-form-actions">
        <button type="submit" className="clv-btn clv-btn-primary" disabled={busy}>
          {busy ? "Saving…" : "Save"}
        </button>
        <button type="button" className="clv-btn" onClick={onCancel}>
          Cancel
        </button>
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
