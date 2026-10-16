import AsyncStorage from "@react-native-async-storage/async-storage";

export interface SavedAccount {
  id: string;
  label: string;
  // The raw pasted value (otpauth:// URI or bare Base32 secret) — kept
  // as-is and re-parsed on demand, the same choice the desktop vault's
  // Record.totp_secret makes, for the same reason: no information is
  // lost by not decomposing it up front.
  secretOrUri: string;
}

const STORAGE_KEY = "clavium.authenticator.accounts";

export async function loadAccounts(): Promise<SavedAccount[]> {
  const raw = await AsyncStorage.getItem(STORAGE_KEY);
  if (!raw) return [];
  try {
    return JSON.parse(raw) as SavedAccount[];
  } catch {
    return [];
  }
}

export async function saveAccounts(accounts: SavedAccount[]): Promise<void> {
  await AsyncStorage.setItem(STORAGE_KEY, JSON.stringify(accounts));
}
