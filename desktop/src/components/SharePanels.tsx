import { useEffect, useState } from "react";

import type { AccountSession } from "../account";
import { checkLink, createShare, listShares, revokeShare, STATUS_LABELS, type LinkCheck, type SentLink } from "../shares";

function message(e: unknown) {
  return e instanceof Error ? e.message : String(e);
}

const EXPIRY = [
  { hours: 1, label: "1 hour" },
  { hours: 24, label: "1 day" },
  { hours: 24 * 7, label: "7 days" },
  { hours: 24 * 30, label: "30 days" },
];

function randomPassphrase() {
  const words = ["simba", "jua", "mvua", "mlima", "ziwa", "nyota", "pwani", "bahari", "kahawa", "chai", "mango", "baobab", "safari", "tembo", "twiga", "kiboko", "duma", "mto", "upepo", "mwezi"];
  const pick = () => words[crypto.getRandomValues(new Uint32Array(1))[0] % words.length];
  return `${pick()}-${pick()}-${pick()}-${crypto.getRandomValues(new Uint32Array(1))[0] % 100}`;
}

function Modal({ title, onClose, children, wide }: { title: string; onClose: () => void; children: React.ReactNode; wide?: boolean }) {
  return (
    <div className="modal-backdrop" onMouseDown={onClose}>
      <div className={`clv-card account-card ${wide ? "team-card" : ""}`} onMouseDown={(e) => e.stopPropagation()}>
        <div className="generator-header">
          <h2>{title}</h2>
          <button className="clv-btn clv-btn-ghost" onClick={onClose} aria-label="Close">
            ✕
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}

/** Share one item, or a free-text note when no item is given. */
export function ShareDialog({
  session,
  item,
  onClose,
}: {
  session: AccountSession;
  item: { id: string; title: string; teamId?: string; hasTotp: boolean } | null;
  onClose: () => void;
}) {
  const [hours, setHours] = useState(24);
  const [views, setViews] = useState(1);
  const [usePass, setUsePass] = useState(false);
  const [passphrase, setPassphrase] = useState(randomPassphrase);
  const [includeTotp, setIncludeTotp] = useState(false);
  const [noteTitle, setNoteTitle] = useState("");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [link, setLink] = useState<{ url: string; expires_at: string } | null>(null);
  const [copied, setCopied] = useState(false);

  async function create() {
    setBusy(true);
    setError(null);
    try {
      setLink(
        await createShare(session, {
          recordId: item?.id,
          teamId: item?.teamId,
          text: item ? undefined : note,
          title: item?.title || noteTitle.trim() || "Shared note",
          passphrase: usePass ? passphrase : undefined,
          includeTotp,
          hours,
          views,
        }),
      );
    } catch (e) {
      setError(message(e));
    } finally {
      setBusy(false);
    }
  }

  async function copy() {
    if (!link) return;
    await navigator.clipboard.writeText(link.url);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  return (
    <Modal title={item ? `Share "${item.title || "item"}"` : "Share a note"} onClose={onClose}>
      {!link ? (
        <>
          <p className="account-intro">
            Makes a link that shows this {item ? "item" : "note"} to whoever opens it, then stops working. It is encrypted on this computer and the key
            is only in the link, so Clavium's server cannot read it. Safer than sending a password on WhatsApp or email.
          </p>
          {!item && (
            <>
              <label className="clv-label" htmlFor="share-note-title">
                Title
              </label>
              <input id="share-note-title" className="clv-input" value={noteTitle} onChange={(e) => setNoteTitle(e.currentTarget.value)} placeholder="e.g. Office Wi-Fi" />
              <label className="clv-label" htmlFor="share-note">
                Text to share
              </label>
              <textarea id="share-note" className="clv-input" rows={4} value={note} onChange={(e) => setNote(e.currentTarget.value)} />
            </>
          )}
          <div className="share-row">
            <label className="clv-label">
              Expires after
              <select className="clv-input" value={hours} onChange={(e) => setHours(Number(e.currentTarget.value))}>
                {EXPIRY.map((x) => (
                  <option key={x.hours} value={x.hours}>
                    {x.label}
                  </option>
                ))}
              </select>
            </label>
            <label className="clv-label">
              Can be opened
              <select className="clv-input" value={views} onChange={(e) => setViews(Number(e.currentTarget.value))}>
                {[1, 2, 3, 5, 10].map((n) => (
                  <option key={n} value={n}>
                    {n === 1 ? "once" : `${n} times`}
                  </option>
                ))}
              </select>
            </label>
          </div>
          <label className="share-check">
            <input type="checkbox" checked={usePass} onChange={(e) => setUsePass(e.currentTarget.checked)} /> Also require a passphrase
          </label>
          {usePass && (
            <div className="share-pass">
              <input className="clv-input" id="share-passphrase" value={passphrase} onChange={(e) => setPassphrase(e.currentTarget.value)} />
              <span className="faint">Tell them this another way, for example by phone. The link alone will not open.</span>
            </div>
          )}
          {item?.hasTotp && (
            <label className="share-check">
              <input type="checkbox" checked={includeTotp} onChange={(e) => setIncludeTotp(e.currentTarget.checked)} /> Include the 2FA secret (usually better
              to set up 2FA again)
            </label>
          )}
          {error && <div className="clv-notice clv-notice-danger">{error}</div>}
          <button className="clv-btn clv-btn-primary" onClick={create} disabled={busy || (!item && !note.trim()) || (usePass && !passphrase.trim())}>
            {busy ? "Encrypting…" : "Create link"}
          </button>
        </>
      ) : (
        <>
          <p className="account-intro">Send this link. It works {views === 1 ? "once" : `${views} times`} and expires {new Date(link.expires_at).toLocaleString()}.</p>
          <div className="share-link" id="share-link">
            {link.url}
          </div>
          <button className="clv-btn clv-btn-primary" onClick={copy}>
            {copied ? "Copied" : "Copy link"}
          </button>
          {usePass && (
            <div className="clv-notice">
              Passphrase: <strong className="mono">{passphrase}</strong>. Give it to them separately, not in the same message.
            </div>
          )}
          <p className="faint">You can cancel it any time under Shared links.</p>
        </>
      )}
    </Modal>
  );
}

export function SharedLinksPanel({ session, onClose, onNewNote }: { session: AccountSession; onClose: () => void; onNewNote: () => void }) {
  const [rows, setRows] = useState<SentLink[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const load = () =>
    listShares(session)
      .then(setRows)
      .catch((e) => setError(message(e)));
  useEffect(() => {
    load();
  }, []);
  return (
    <Modal title="Shared links" onClose={onClose} wide>
      <p className="account-intro">Links you sent. Cancel one to make it stop working at once.</p>
      <button className="clv-btn" onClick={onNewNote}>
        + Share a note
      </button>
      {error && <div className="clv-notice clv-notice-danger">{error}</div>}
      <div className="team-members" style={{ marginTop: 12 }}>
        {rows?.length === 0 && <div className="faint">Nothing shared yet. Use Share on any item.</div>}
        {rows?.map((r) => (
          <div key={r.id} className="team-member">
            <div className="team-member-who">
              <div>{r.title || "Shared item"}</div>
              <div className="faint team-member-sub">
                {STATUS_LABELS[r.status]} · opened {r.views} of {r.max_views} · {r.status === "active" ? `expires ${new Date(r.expires_at).toLocaleString()}` : `sent ${new Date(r.created_at).toLocaleDateString()}`}
                {r.has_passphrase ? " · passphrase" : ""}
              </div>
            </div>
            {r.status === "active" && (
              <button className="clv-btn clv-btn-ghost clv-btn-sm" onClick={() => revokeShare(session, r.id).then(load).catch((e) => setError(message(e)))}>
                Cancel
              </button>
            )}
          </div>
        ))}
      </div>
    </Modal>
  );
}

export function VerdictCard({ check }: { check: LinkCheck }) {
  const title = {
    trusted: "Looks genuine",
    unknown: "Not known to Clavium",
    suspicious: "Be careful",
    dangerous: check.imitates ? `Fake: pretends to be ${check.imitates}` : "Looks like a fake site",
  }[check.verdict];
  return (
    <div className={`verdict-card verdict-${check.verdict}`}>
      <div className="verdict-title">{title}</div>
      <div className="faint verdict-host">{check.host}</div>
      {check.reasons.map((r) => (
        <div key={r}>{r}</div>
      ))}
      {check.official && <div>Go to the real site by typing {check.official} yourself, not by tapping a link.</div>}
    </div>
  );
}

export function LinkCheckPanel({ onClose }: { onClose: () => void }) {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState<LinkCheck | null>(null);
  return (
    <Modal title="Check a link" onClose={onClose}>
      <p className="account-intro">
        Got a link by SMS, WhatsApp or email asking you to log in, verify, or claim a refund? Paste it here before opening it. Checked on this computer;
        the link is not sent anywhere.
      </p>
      <form
        className="team-add"
        onSubmit={async (e) => {
          e.preventDefault();
          if (url.trim()) setResult(await checkLink(url.trim()));
        }}
      >
        <input className="clv-input" id="check-url" value={url} onChange={(e) => setUrl(e.currentTarget.value)} placeholder="https://…" autoFocus />
        <button className="clv-btn clv-btn-primary" type="submit">
          Check
        </button>
      </form>
      {result && <VerdictCard check={result} />}
    </Modal>
  );
}
