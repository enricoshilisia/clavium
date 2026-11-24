import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { loadSession, type AccountSession } from "../account";
import {
  categoriesList,
  errorMessage,
  recordKinds,
  totpCode,
  vaultAddRecord,
  vaultDeleteRecord,
  vaultListRecords,
  vaultSetCategory,
  vaultUpdateRecord,
} from "../api";
import { fieldLabel, KIND_BADGE, KIND_LABELS, SECRET_FIELDS } from "../labels";
import { afterSync, cachedPolicy, policyNotices, pull, syncNow } from "../sync";
import { vaultHasRecoveryKey } from "../api";
import type { Policy } from "../account";
import type { CategoryInfo, KindInfo, RecordInput, VaultRecord } from "../types";
import logo from "../assets/clavium-logo.png";
import AccountPanel from "./AccountPanel";
import { managed } from "../managed";
import BrowserPanel from "./BrowserPanel";
import RecordForm from "./RecordForm";
import SecurityPanel from "./SecurityPanel";

interface Props {
  records: VaultRecord[];
  onRecordsChange: (records: VaultRecord[]) => void;
  onLock: () => void;
  autoLockMinutes: number;
}

type Mode = "view" | "edit" | "add";
type Filter = { type: "all" } | { type: "favorites" } | { type: "category"; slug: string } | { type: "folder"; name: string };

export default function VaultView({ records, onRecordsChange, onLock, autoLockMinutes }: Props) {
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState<Filter>({ type: "all" });
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [mode, setMode] = useState<Mode>("view");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [panel, setPanel] = useState<"account" | "browser" | "security" | null>(null);
  const [kinds, setKinds] = useState<KindInfo[]>([]);
  const [categories, setCategories] = useState<CategoryInfo[]>([]);

  // ---- sync ----
  const [session, setSession] = useState<AccountSession | null>(() => loadSession());
  const [syncing, setSyncing] = useState(false);
  const [syncError, setSyncError] = useState<string | null>(null);
  const [syncNotice, setSyncNotice] = useState<string | null>(null);
  const [lastSync, setLastSync] = useState<Date | null>(null);
  const inFlight = useRef<Promise<void> | null>(null);
  const again = useRef(false);
  const alive = useRef(true);

  const [policy, setPolicy] = useState<Policy | null>(() => cachedPolicy());
  const [hasRecovery, setHasRecovery] = useState(true);
  const refreshRecovery = useCallback(() => vaultHasRecoveryKey().then(setHasRecovery).catch(() => {}), []);
  useEffect(() => {
    refreshRecovery();
  }, [refreshRecovery]);

  const reload = useCallback(async () => onRecordsChange(await vaultListRecords()), [onRecordsChange]);

  const runSync = useCallback(async () => {
    const s = loadSession();
    if (!s) return;
    if (inFlight.current) {
      again.current = true;
      return inFlight.current;
    }
    const task = (async () => {
      do {
        again.current = false;
        setSyncing(true);
        try {
          const out = await syncNow(s);
          setSyncError(null);
          setSyncNotice(out.notice);
          setLastSync(new Date());
          if (out.changed > 0) await reload();
          setPolicy(await afterSync(s, await vaultHasRecoveryKey().catch(() => false)));
        } catch (e) {
          setSyncError(e instanceof Error ? e.message : String(e));
        } finally {
          setSyncing(false);
        }
      } while (again.current);
    })();
    inFlight.current = task;
    try {
      await task;
    } finally {
      inFlight.current = null;
    }
  }, [reload]);

  useEffect(() => {
    alive.current = true;
    recordKinds().then(setKinds);
    categoriesList().then(setCategories);
    return () => {
      alive.current = false;
    };
  }, []);

  // Initial sync, then a long-poll loop so other devices' changes appear live.
  useEffect(() => {
    if (!session) return;
    let stop = false;
    (async () => {
      // The first sync creates the account's keyring if needed; only then
      // can the live long-poll succeed.
      await runSync();
      while (!stop && alive.current) {
        try {
          const changed = await pull(session, true);
          if (changed > 0 && !stop) {
            setLastSync(new Date());
            await reload();
          }
        } catch {
          await new Promise((r) => setTimeout(r, 5000));
        }
      }
    })();
    return () => {
      stop = true;
    };
  }, [session, runSync, reload]);

  const debounce = useRef<number | null>(null);
  function changed() {
    if (!loadSession()) return;
    if (debounce.current) window.clearTimeout(debounce.current);
    debounce.current = window.setTimeout(() => runSync(), 1500);
  }

  // ---- filtering ----
  const counts = useMemo(() => {
    const m = new Map<string, number>();
    for (const r of records) m.set(r.category ?? "uncategorized", (m.get(r.category ?? "uncategorized") ?? 0) + 1);
    return m;
  }, [records]);

  const folders = useMemo(() => [...new Set(records.map((r) => r.folder).filter((f): f is string => !!f))].sort(), [records]);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return [...records]
      .filter((r) => {
        if (filter.type === "favorites" && !r.favorite) return false;
        if (filter.type === "category" && (r.category ?? "uncategorized") !== filter.slug) return false;
        if (filter.type === "folder" && r.folder !== filter.name) return false;
        if (!q) return true;
        return (
          r.title.toLowerCase().includes(q) ||
          r.username.toLowerCase().includes(q) ||
          r.url.toLowerCase().includes(q) ||
          r.notes.toLowerCase().includes(q) ||
          r.tags.some((t) => t.includes(q))
        );
      })
      .sort((a, b) => Number(b.favorite) - Number(a.favorite) || a.title.localeCompare(b.title));
  }, [records, search, filter]);

  const selected = records.find((r) => r.id === selectedId) ?? null;
  const catLabel = (slug: string | null) => categories.find((c) => c.slug === slug)?.label ?? "Uncategorised";

  // ---- mutations ----
  async function guarded(fn: () => Promise<void>) {
    setBusy(true);
    setError(null);
    try {
      await fn();
      changed();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  const saveNew = (input: RecordInput) =>
    guarded(async () => {
      const created = await vaultAddRecord(input);
      await reload();
      setSelectedId(created.id);
      setMode("view");
    });

  const saveEdit = (input: RecordInput) =>
    guarded(async () => {
      if (!selected) return;
      await vaultUpdateRecord(selected.id, input);
      await reload();
      setMode("view");
    });

  async function deleteSelected() {
    if (!selected) return;
    if (!window.confirm(`Delete "${selected.title}"? It is removed from every device this vault syncs to.`)) return;
    await guarded(async () => {
      await vaultDeleteRecord(selected.id);
      await reload();
      setSelectedId(null);
    });
  }

  const toggleFavorite = (r: VaultRecord) =>
    guarded(async () => {
      await vaultUpdateRecord(r.id, toInput(r, { favorite: !r.favorite }));
      await reload();
    });

  const recategorize = (r: VaultRecord, slug: string) =>
    guarded(async () => {
      onRecordsChange(await vaultSetCategory(r.id, slug || null, true));
    });

  async function copy(text: string) {
    if (!text) return;
    await navigator.clipboard.writeText(text);
    // Clear after 30 s unless something else was copied meanwhile.
    setTimeout(async () => {
      try {
        if ((await navigator.clipboard.readText()) === text) await navigator.clipboard.writeText("");
      } catch {
        // clipboard read not permitted; leave it
      }
    }, 30_000);
  }

  const navItem = (label: string, f: Filter, count?: number) => {
    const active = JSON.stringify(f) === JSON.stringify(filter);
    return (
      <button key={label} className={`nav-item ${active ? "nav-item-active" : ""}`} onClick={() => setFilter(f)}>
        <span>{label}</span>
        {count !== undefined && <span className="nav-count">{count}</span>}
      </button>
    );
  };

  return (
    <div className="vault-shell vault-shell-3">
      <nav className="vault-nav clv-scrollbar">
        <div className="vault-brand">
          <img src={logo} alt="" width="18" height="18" />
          Clavium
        </div>
        {navItem("All items", { type: "all" }, records.length)}
        {navItem("Favourites", { type: "favorites" }, records.filter((r) => r.favorite).length)}
        <div className="nav-heading">Categories</div>
        {[...categories, { slug: "uncategorized", label: "Uncategorised" }]
          .filter((c) => (counts.get(c.slug) ?? 0) > 0)
          .map((c) => navItem(c.label, { type: "category", slug: c.slug }, counts.get(c.slug)))}
        {folders.length > 0 && <div className="nav-heading">Folders</div>}
        {folders.map((f) => navItem(f, { type: "folder", name: f }, records.filter((r) => r.folder === f).length))}

        <div className="nav-spacer" />
        <div className="sync-status" title={syncError ?? undefined}>
          {!session ? (
            <button className="clv-btn clv-btn-ghost clv-btn-sm" onClick={() => setPanel("account")}>
              Turn on sync
            </button>
          ) : (
            <>
              <span className={`sync-dot ${syncError ? "sync-dot-bad" : syncing ? "sync-dot-busy" : ""}`} />
              <span className="faint">
                {syncError ? "Sync problem" : syncing ? "Syncing…" : lastSync ? `Synced ${lastSync.toLocaleTimeString()}` : "Not synced yet"}
              </span>
              <button className="clv-btn clv-btn-ghost clv-btn-sm" onClick={() => runSync()} disabled={syncing}>
                Sync
              </button>
            </>
          )}
        </div>
        <div className="nav-actions">
          <button className="clv-btn clv-btn-ghost" onClick={() => setPanel("security")}>
            Security
          </button>
          <button className="clv-btn clv-btn-ghost" onClick={() => setPanel("account")}>
            Account
          </button>
          <button className="clv-btn clv-btn-ghost" onClick={() => setPanel("browser")}>
            Browser
          </button>
          <button className="clv-btn clv-btn-ghost" onClick={onLock} title={`Auto-locks after ${autoLockMinutes} min idle`}>
            Lock
          </button>
        </div>
      </nav>

      {panel === "account" && (
        <AccountPanel
          onClose={() => setPanel(null)}
          onSessionChange={(s) => {
            setSession(s);
            if (s) runSync();
          }}
          syncError={syncError}
        />
      )}
      {panel === "browser" && <BrowserPanel onClose={() => setPanel(null)} />}
      {panel === "security" && (
        <SecurityPanel
          records={records}
          onClose={() => setPanel(null)}
          onOpen={(id) => {
            setSelectedId(id);
            setMode("view");
            setPanel(null);
          }}
          onChanged={() => {
            changed();
            refreshRecovery();
          }}
          minPasswordLength={policy?.min_master_password_length ?? 10}
        />
      )}

      <aside className="vault-sidebar">
        <input className="clv-input" placeholder="Search…" value={search} onChange={(e) => setSearch(e.currentTarget.value)} />
        <button
          className="clv-btn clv-btn-gold vault-add-btn"
          onClick={() => {
            setSelectedId(null);
            setMode("add");
            setError(null);
          }}
        >
          + New item
        </button>
        {syncNotice && <div className="clv-notice">{syncNotice}</div>}
        {managed().require_sign_in && !session && (
          <div className="clv-notice">
            Your organization asks you to sign in to your work account so this vault is backed up and synced.{" "}
            <button className="clv-btn clv-btn-ghost clv-btn-sm" onClick={() => setPanel("account")}>
              Sign in
            </button>
          </div>
        )}
        {policyNotices(policy, hasRecovery).map((n) => (
          <div key={n} className="clv-notice">
            {n}
          </div>
        ))}
        <div className="vault-list clv-scrollbar">
          {filtered.length === 0 && <div className="vault-empty">Nothing here.</div>}
          {filtered.map((record) => (
            <button
              key={record.id}
              className={`vault-list-item ${record.id === selectedId ? "vault-list-item-active" : ""}`}
              onClick={() => {
                setSelectedId(record.id);
                setMode("view");
                setError(null);
              }}
            >
              <span className="kind-badge">{KIND_BADGE[record.kind] ?? "?"}</span>
              <span className="vault-list-text">
                <span className="vault-list-item-title">
                  {record.title || "(untitled)"} {record.favorite && <span className="fav-star">★</span>}
                </span>
                <span className="vault-list-item-sub">{subtitle(record)}</span>
              </span>
            </button>
          ))}
        </div>
      </aside>

      <main className="vault-main">
        {mode === "add" && (
          <div className="clv-card detail-card">
            <h2>New item</h2>
            <RecordForm
              initial={null}
              kinds={kinds}
              categories={categories}
              folders={folders}
              onSave={saveNew}
              onCancel={() => setMode("view")}
              busy={busy}
              error={error}
            />
          </div>
        )}

        {mode === "edit" && selected && (
          <div className="clv-card detail-card">
            <h2>Edit</h2>
            <RecordForm
              key={selected.id}
              initial={selected}
              kinds={kinds}
              categories={categories}
              folders={folders}
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
              <h2>
                {selected.title || "(untitled)"}{" "}
                <button className="fav-toggle" onClick={() => toggleFavorite(selected)} title="Favourite">
                  {selected.favorite ? "★" : "☆"}
                </button>
              </h2>
              <div className="detail-header-actions">
                <button className="clv-btn" onClick={() => setMode("edit")}>
                  Edit
                </button>
                <button className="clv-btn clv-btn-danger" onClick={deleteSelected}>
                  Delete
                </button>
              </div>
            </div>
            <div className="detail-meta-row">
              <span className="pill">{KIND_LABELS[selected.kind]}</span>
              <select className="clv-input pill-select" value={selected.category ?? ""} onChange={(e) => recategorize(selected, e.currentTarget.value)}>
                <option value="">{selected.category_source === "auto" ? `${catLabel(selected.category)} (auto)` : "Automatic"}</option>
                {categories.map((c) => (
                  <option key={c.slug} value={c.slug}>
                    {c.label}
                  </option>
                ))}
              </select>
              {selected.folder && <span className="pill">{selected.folder}</span>}
              {selected.tags.map((t) => (
                <span key={t} className="pill pill-tag">
                  #{t}
                </span>
              ))}
            </div>
            {error && <div className="clv-notice clv-notice-danger">{error}</div>}

            {selected.username && <DetailField label="Username" value={selected.username} onCopy={copy} />}
            {selected.password && <DetailField label="Password" value={selected.password} onCopy={copy} secret />}
            {selected.url && <DetailField label="Website" value={selected.url} onCopy={copy} link />}
            {selected.totp_secret && <TotpField secret={selected.totp_secret} onCopy={copy} />}
            {Object.entries(selected.fields).map(([k, v]) => (
              <DetailField key={k} label={fieldLabel(k)} value={v} onCopy={copy} secret={SECRET_FIELDS.has(k)} />
            ))}
            {selected.custom_fields.map((f) => (
              <DetailField key={f.name} label={f.name} value={f.value} onCopy={copy} secret={f.hidden} />
            ))}
            {selected.notes && (
              <div className="detail-field">
                <div className="clv-label">Notes</div>
                <div className="detail-notes">{selected.notes}</div>
              </div>
            )}
            <div className="detail-meta">Updated {new Date(selected.updated_at).toLocaleString()}</div>
          </div>
        )}

        {mode === "view" && !selected && (
          <div className="vault-placeholder">
            <p>Select an item, or create a new one.</p>
          </div>
        )}
      </main>
    </div>
  );
}

function subtitle(r: VaultRecord): string {
  switch (r.kind) {
    case "card": {
      const d = (r.fields.number ?? "").replace(/\D/g, "");
      return d.length >= 4 ? `•••• ${d.slice(-4)}` : r.fields.brand ?? "Card";
    }
    case "bank_account":
      return [r.fields.bank_name, r.fields.account_number].filter(Boolean).join(" · ");
    case "wifi":
      return r.fields.ssid ?? "Wi-Fi";
    case "server":
    case "database":
      return r.fields.hostname ?? "";
    default:
      return r.username || r.url || "—";
  }
}

export function toInput(r: VaultRecord, patch: Partial<RecordInput> = {}): RecordInput {
  return {
    kind: r.kind,
    title: r.title,
    username: r.username,
    password: r.password,
    url: r.url,
    notes: r.notes,
    totpSecret: r.totp_secret,
    fields: r.fields,
    customFields: r.custom_fields,
    category: r.category_source === "user" ? r.category : null,
    folder: r.folder,
    tags: r.tags,
    favorite: r.favorite,
    ...patch,
  };
}

function TotpField({ secret, onCopy }: { secret: string; onCopy: (text: string) => void }) {
  const [code, setCode] = useState("");
  const [secondsRemaining, setSecondsRemaining] = useState(0);
  const [periodSeconds, setPeriodSeconds] = useState(30);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    async function refresh() {
      try {
        const result = await totpCode(secret);
        if (cancelled) return;
        setCode(result.code);
        setSecondsRemaining(result.secondsRemaining);
        setPeriodSeconds(result.periodSeconds);
        setError(null);
      } catch (err) {
        if (!cancelled) setError(errorMessage(err));
      }
    }
    refresh();
    const interval = setInterval(refresh, 1000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [secret]);

  if (error) {
    return (
      <div className="detail-field">
        <div className="clv-label">Authenticator code</div>
        <div className="clv-notice clv-notice-danger">{error}</div>
      </div>
    );
  }
  const fraction = periodSeconds > 0 ? secondsRemaining / periodSeconds : 0;
  return (
    <div className="detail-field">
      <div className="clv-label">Authenticator code</div>
      <div className="detail-field-row">
        <span className="totp-code">{code.replace(/(.{3})(?=.)/, "$1 ")}</span>
        <div className="totp-ring" style={{ "--totp-fraction": fraction } as React.CSSProperties} />
        <button className="clv-btn clv-btn-ghost" onClick={() => onCopy(code)} disabled={!code}>
          Copy
        </button>
      </div>
    </div>
  );
}

function DetailField({
  label,
  value,
  onCopy,
  secret,
  link,
}: {
  label: string;
  value: string;
  onCopy: (v: string) => void;
  secret?: boolean;
  link?: boolean;
}) {
  const [reveal, setReveal] = useState(false);
  const shown = secret && !reveal ? "•".repeat(Math.min(Math.max(value.length, 8), 16)) : value;
  return (
    <div className="detail-field">
      <div className="clv-label">{label}</div>
      <div className="detail-field-row">
        {link && value ? (
          <a href={/^https?:\/\//.test(value) ? value : `https://${value}`} target="_blank" rel="noreferrer" className="detail-field-value">
            {value}
          </a>
        ) : (
          <span className={`detail-field-value ${secret ? "detail-field-mono" : ""}`}>{shown || "—"}</span>
        )}
        {secret && (
          <button className="clv-btn clv-btn-ghost" onClick={() => setReveal((v) => !v)}>
            {reveal ? "Hide" : "Show"}
          </button>
        )}
        <button className="clv-btn clv-btn-ghost" onClick={() => onCopy(value)} disabled={!value}>
          Copy
        </button>
      </div>
    </div>
  );
}
