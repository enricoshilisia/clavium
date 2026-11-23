import type { RecordKind } from "./types";

export const KIND_LABELS: Record<RecordKind, string> = {
  login: "Login",
  bank_account: "Bank account",
  card: "Payment card",
  identity: "Identity",
  secure_note: "Secure note",
  wifi: "Wi-Fi",
  ssh_key: "SSH key",
  api_key: "API key",
  server: "Server",
  database: "Database",
  software_license: "Software licence",
  passkey: "Passkey",
};

/** Two-letter badge shown in the list, by kind. */
export const KIND_BADGE: Record<RecordKind, string> = {
  login: "Lg",
  bank_account: "Bk",
  card: "Cd",
  identity: "Id",
  secure_note: "Nt",
  wifi: "Wf",
  ssh_key: "Sh",
  api_key: "Ap",
  server: "Sv",
  database: "Db",
  software_license: "Lc",
  passkey: "Pk",
};

const SPECIAL: Record<string, string> = {
  swift_bic: "SWIFT / BIC",
  iban: "IBAN",
  cvv: "CVV",
  pin: "PIN",
  kra_pin: "KRA PIN",
  id_number: "ID number",
  ssid: "Network name (SSID)",
  rp_id: "Website",
};

export function fieldLabel(name: string): string {
  if (SPECIAL[name]) return SPECIAL[name];
  const s = name.replace(/_/g, " ");
  return s.charAt(0).toUpperCase() + s.slice(1);
}

export const SECRET_FIELDS = new Set(["cvv", "pin", "private_key", "passphrase", "secret", "key", "license_key", "connection_string"]);
export const MULTILINE_FIELDS = new Set(["private_key", "public_key", "address", "connection_string"]);

/** Which common fields each kind uses. */
export function kindUses(kind: RecordKind) {
  return {
    username: ["login", "server", "database"].includes(kind),
    password: ["login", "server", "database", "api_key", "wifi", "software_license"].includes(kind),
    url: ["login", "api_key", "software_license"].includes(kind),
    totp: kind === "login",
  };
}
