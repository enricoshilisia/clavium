import { useEffect, useState } from "react";

import { errorMessage, generatePassword } from "../api";

interface Props {
  onClose: () => void;
  onUse: (password: string) => void;
}

export default function PasswordGenerator({ onClose, onUse }: Props) {
  const [length, setLength] = useState(20);
  const [includeUpper, setIncludeUpper] = useState(true);
  const [includeLower, setIncludeLower] = useState(true);
  const [includeDigits, setIncludeDigits] = useState(true);
  const [includeSymbols, setIncludeSymbols] = useState(true);
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  async function roll() {
    setError(null);
    setCopied(false);
    try {
      const generated = await generatePassword({
        length,
        includeUpper,
        includeLower,
        includeDigits,
        includeSymbols,
      });
      setPassword(generated);
    } catch (err) {
      setError(errorMessage(err));
      setPassword("");
    }
  }

  useEffect(() => {
    roll();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [length, includeUpper, includeLower, includeDigits, includeSymbols]);

  async function copy() {
    if (!password) return;
    await navigator.clipboard.writeText(password);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  return (
    <div className="modal-backdrop" onMouseDown={onClose}>
      <div className="clv-card generator-card" onMouseDown={(e) => e.stopPropagation()}>
        <div className="generator-header">
          <h2>Generate a password</h2>
          <button className="clv-btn clv-btn-ghost" onClick={onClose} aria-label="Close">
            ✕
          </button>
        </div>

        <div className="generator-output">
          <code>{password || " "}</code>
          <button className="clv-btn clv-btn-ghost" onClick={roll} title="Generate another">
            ↻
          </button>
        </div>
        {copied && <div className="generator-copied">Copied</div>}
        {error && <div className="clv-notice clv-notice-danger">{error}</div>}

        <div className="generator-row">
          <label className="clv-label" htmlFor="length">
            Length — {length}
          </label>
          <input
            id="length"
            type="range"
            min={8}
            max={64}
            value={length}
            onChange={(e) => setLength(Number(e.currentTarget.value))}
          />
        </div>

        <div className="generator-toggles">
          <Toggle label="A–Z" checked={includeUpper} onChange={setIncludeUpper} />
          <Toggle label="a–z" checked={includeLower} onChange={setIncludeLower} />
          <Toggle label="0–9" checked={includeDigits} onChange={setIncludeDigits} />
          <Toggle label="!@#$" checked={includeSymbols} onChange={setIncludeSymbols} />
        </div>

        <div className="generator-actions">
          <button className="clv-btn" onClick={copy} disabled={!password}>
            Copy
          </button>
          <button
            className="clv-btn clv-btn-gold"
            onClick={() => password && onUse(password)}
            disabled={!password}
          >
            Use this password
          </button>
        </div>
      </div>
    </div>
  );
}

function Toggle({
  label,
  checked,
  onChange,
}: {
  label: string;
  checked: boolean;
  onChange: (value: boolean) => void;
}) {
  return (
    <label className={`generator-toggle ${checked ? "generator-toggle-on" : ""}`}>
      <input type="checkbox" checked={checked} onChange={(e) => onChange(e.currentTarget.checked)} />
      {label}
    </label>
  );
}
