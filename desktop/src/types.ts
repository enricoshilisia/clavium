// Matches `clavium_security_core::Record`'s own field names exactly — that
// struct has no `rename_all` attribute (its JSON shape is also the vault's
// on-disk format, so it is not renamed just to suit this IPC boundary).
export interface VaultRecord {
  id: string;
  title: string;
  username: string;
  password: string;
  url: string;
  notes: string;
  created_at: string;
  updated_at: string;
}

export interface RecordInput {
  title: string;
  username: string;
  password: string;
  url: string;
  notes: string;
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
