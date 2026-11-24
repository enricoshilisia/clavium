// Settings an organization pushes to its computers (Intune or Group
// Policy). Read by the Rust side from the Windows policy registry keys,
// which ordinary users cannot change. See src-tauri/src/managed.rs.

import { invoke } from "@tauri-apps/api/core";

import { setControlPlaneUrl } from "./config";

export interface ManagedSettings {
  managed: boolean;
  server_url: string | null;
  allowed_email_domains: string[];
  disable_account_creation: boolean;
  require_sign_in: boolean;
  max_auto_lock_minutes: number | null;
  ignored: string[];
}

const NONE: ManagedSettings = {
  managed: false,
  server_url: null,
  allowed_email_domains: [],
  disable_account_creation: false,
  require_sign_in: false,
  max_auto_lock_minutes: null,
  ignored: [],
};

let current: ManagedSettings = NONE;

export async function loadManagedSettings(): Promise<ManagedSettings> {
  try {
    current = { ...NONE, ...(await invoke<ManagedSettings>("managed_settings")) };
  } catch {
    current = NONE; // not running inside the desktop shell
  }
  setControlPlaneUrl(current.server_url);
  if (current.ignored.length) console.warn("Clavium managed settings ignored:", current.ignored);
  return current;
}

export function managed(): ManagedSettings {
  return current;
}

/** Null when the email may be used, otherwise the reason it may not. */
export function emailNotAllowed(email: string): string | null {
  const domains = current.allowed_email_domains;
  if (!domains.length) return null;
  const domain = email.trim().toLowerCase().split("@").pop() ?? "";
  if (domains.includes(domain)) return null;
  const list = domains.map((d) => `@${d}`).join(" or ");
  return `Your organization requires your work email (${list}).`;
}
