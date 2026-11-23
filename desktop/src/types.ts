// Matches `clavium_security_core::Record` field names exactly (snake_case):
// the same JSON is the vault's on-disk format.
export type RecordKind =
  | "login"
  | "bank_account"
  | "card"
  | "identity"
  | "secure_note"
  | "wifi"
  | "ssh_key"
  | "api_key"
  | "server"
  | "database"
  | "software_license"
  | "passkey";

export interface CustomField {
  name: string;
  value: string;
  hidden: boolean;
}

export interface VaultRecord {
  id: string;
  kind: RecordKind;
  title: string;
  username: string;
  password: string;
  url: string;
  notes: string;
  totp_secret: string | null;
  fields: Record<string, string>;
  custom_fields: CustomField[];
  category: string | null;
  category_source: "auto" | "user";
  folder: string | null;
  tags: string[];
  favorite: boolean;
  created_at: string;
  updated_at: string;
}

/** Tauri's RecordInput (camelCase). `category: null` = automatic. */
export interface RecordInput {
  kind: RecordKind;
  title: string;
  username: string;
  password: string;
  url: string;
  notes: string;
  totpSecret: string | null;
  fields: Record<string, string>;
  customFields: CustomField[];
  category: string | null;
  folder: string | null;
  tags: string[];
  favorite: boolean;
}

export interface CategoryInfo {
  slug: string;
  label: string;
}

export interface KindInfo {
  kind: RecordKind;
  fields: string[];
}

export interface HealthReport {
  with_password: number;
  weak: string[];
  reused: string[][];
  old: string[];
  without_totp: string[];
  score: number;
}

export interface EncryptedItem {
  id: string;
  revision: number;
  deleted: boolean;
  nonce: string;
  ciphertext: string;
}

export interface SyncState {
  vaultId: string;
  cursor: number;
  pending: EncryptedItem[];
}

export interface MergeReport {
  added: number;
  updated: number;
  deleted: number;
  conflicts: number;
  unchanged: number;
}

export interface TotpCode {
  code: string;
  secondsRemaining: number;
  periodSeconds: number;
}

export interface VaultSummary {
  recordCount: number;
}

export interface GenerateInput {
  length: number;
  includeUpper: boolean;
  includeLower: boolean;
  includeDigits: boolean;
  includeSymbols: boolean;
}

export interface PairedExtension {
  id: string;
  label: string;
  paired_at: number;
}
