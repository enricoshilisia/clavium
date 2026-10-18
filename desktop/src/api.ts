import { invoke } from "@tauri-apps/api/core";
import { appDataDir, join } from "@tauri-apps/api/path";

import type { GenerateInput, PairedExtension, RecordInput, TotpCode, VaultRecord, VaultSummary } from "./types";

/** Where a vault lives if the person never chooses a different location. */
export async function defaultVaultPath(): Promise<string> {
  const dir = await appDataDir();
  return join(dir, "vault.clv");
}

export function vaultExists(path: string): Promise<boolean> {
  return invoke("vault_exists", { path });
}

export function vaultCreate(path: string, masterPassword: string): Promise<VaultSummary> {
  return invoke("vault_create", { path, masterPassword });
}

export function vaultUnlock(path: string, masterPassword: string): Promise<VaultRecord[]> {
  return invoke("vault_unlock", { path, masterPassword });
}

export function vaultLock(): Promise<void> {
  return invoke("vault_lock");
}

export function vaultIsUnlocked(): Promise<boolean> {
  return invoke("vault_is_unlocked");
}

export function vaultListRecords(): Promise<VaultRecord[]> {
  return invoke("vault_list_records");
}

export function vaultAddRecord(input: RecordInput): Promise<VaultRecord> {
  return invoke("vault_add_record", { input });
}

export function vaultUpdateRecord(id: string, input: RecordInput): Promise<VaultRecord> {
  return invoke("vault_update_record", { id, input });
}

export function vaultDeleteRecord(id: string): Promise<void> {
  return invoke("vault_delete_record", { id });
}

export function generatePassword(input: GenerateInput): Promise<string> {
  return invoke("generate_password", { input });
}

export function totpCode(secret: string): Promise<TotpCode> {
  return invoke("totp_code", { secret });
}

/** Base64 of the vault's current sealed bytes, read straight off disk. */
export function vaultExportSealed(): Promise<string> {
  return invoke("vault_export_sealed");
}

/** A fresh 6-character pairing code, valid for 2 minutes, for a browser
 * extension to redeem. */
export function bridgeGeneratePairingCode(): Promise<string> {
  return invoke("bridge_generate_pairing_code");
}

export function bridgeListPaired(): Promise<PairedExtension[]> {
  return invoke("bridge_list_paired");
}

export function bridgeRevokePaired(id: string): Promise<void> {
  return invoke("bridge_revoke_paired", { id });
}

/** The friendly half of whatever string a failed command rejected with. */
export function errorMessage(err: unknown): string {
  return typeof err === "string" ? err : String(err);
}
