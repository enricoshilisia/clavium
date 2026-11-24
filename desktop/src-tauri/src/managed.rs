//! Settings an organization pushes to its computers (Intune, Group Policy,
//! or any tool that writes the registry), read once at startup.
//!
//! Windows: `HKLM\SOFTWARE\Policies\Clavium`, then
//! `HKCU\SOFTWARE\Policies\Clavium` for anything the machine key does not
//! set. These are the standard policy locations, which ordinary users
//! cannot write, so a setting placed there by IT cannot be undone by the
//! person at the keyboard. The ADMX template is in `deploy/intune/`.
//!
//! Other systems: a JSON file at `/etc/clavium/policy.json` (or
//! `CLAVIUM_POLICY_FILE`) with the same value names.
//!
//! Values (all optional):
//!   ServerUrl               REG_SZ     company Clavium server (https)
//!   AllowedEmailDomains     REG_SZ     e.g. "contoso.com, contoso.co.ke"
//!   DisableAccountCreation  REG_DWORD  1 = sign in only, no new accounts
//!   RequireSignIn           REG_DWORD  1 = keep asking until signed in
//!   MaxAutoLockMinutes      REG_DWORD  cap on the idle auto-lock

use serde::Serialize;

#[derive(Debug, Default, Clone, PartialEq, Serialize)]
pub struct ManagedSettings {
    pub managed: bool,
    pub server_url: Option<String>,
    pub allowed_email_domains: Vec<String>,
    pub disable_account_creation: bool,
    pub require_sign_in: bool,
    pub max_auto_lock_minutes: Option<u32>,
    /// Values that were present but rejected, so IT can see why.
    pub ignored: Vec<String>,
}

fn valid_server(url: &str) -> bool {
    let Ok(u) = url::Url::parse(url) else { return false };
    let local = matches!(u.host_str(), Some("localhost") | Some("127.0.0.1"));
    (u.scheme() == "https" || (u.scheme() == "http" && local)) && u.host_str().is_some() && u.query().is_none()
}

fn valid_domain(d: &str) -> bool {
    !d.is_empty()
        && d.len() <= 253
        && d.contains('.')
        && d.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        && !d.starts_with('.')
        && !d.ends_with('.')
}

/// Build settings from two lookups (text and number values).
pub fn from_lookup(text: impl Fn(&str) -> Option<String>, number: impl Fn(&str) -> Option<u32>) -> ManagedSettings {
    let mut s = ManagedSettings::default();
    if let Some(v) = text("ServerUrl").map(|v| v.trim().trim_end_matches('/').to_string()).filter(|v| !v.is_empty()) {
        s.managed = true;
        if valid_server(&v) {
            s.server_url = Some(v);
        } else {
            s.ignored.push(format!("ServerUrl \"{v}\" must be an https address"));
        }
    }
    if let Some(v) = text("AllowedEmailDomains") {
        for d in v.split([',', ';', ' ']).map(|d| d.trim().trim_start_matches('@').to_ascii_lowercase()).filter(|d| !d.is_empty()) {
            s.managed = true;
            if valid_domain(&d) {
                if !s.allowed_email_domains.contains(&d) {
                    s.allowed_email_domains.push(d);
                }
            } else {
                s.ignored.push(format!("AllowedEmailDomains entry \"{d}\" is not a domain"));
            }
        }
    }
    if let Some(v) = number("DisableAccountCreation") {
        s.managed = true;
        s.disable_account_creation = v != 0;
    }
    if let Some(v) = number("RequireSignIn") {
        s.managed = true;
        s.require_sign_in = v != 0;
    }
    if let Some(v) = number("MaxAutoLockMinutes") {
        s.managed = true;
        if (1..=1440).contains(&v) {
            s.max_auto_lock_minutes = Some(v);
        } else if v != 0 {
            s.ignored.push(format!("MaxAutoLockMinutes {v} must be between 1 and 1440"));
        }
    }
    s
}

#[cfg(windows)]
pub fn read() -> ManagedSettings {
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ};
    use winreg::RegKey;
    const PATH: &str = "SOFTWARE\\Policies\\Clavium";
    let keys: Vec<RegKey> = [HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER]
        .into_iter()
        .filter_map(|hive| RegKey::predef(hive).open_subkey_with_flags(PATH, KEY_READ).ok())
        .collect();
    // Machine policy wins: it is listed first and the first hit is used.
    from_lookup(
        |name| keys.iter().find_map(|k| k.get_value::<String, _>(name).ok()),
        |name| {
            keys.iter().find_map(|k| {
                k.get_value::<u32, _>(name)
                    .ok()
                    .or_else(|| k.get_value::<String, _>(name).ok().and_then(|s| s.trim().parse().ok()))
            })
        },
    )
}

#[cfg(not(windows))]
pub fn read() -> ManagedSettings {
    let path = std::env::var("CLAVIUM_POLICY_FILE").unwrap_or_else(|_| "/etc/clavium/policy.json".into());
    let Ok(text) = std::fs::read_to_string(path) else { return ManagedSettings::default() };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) else {
        return ManagedSettings { managed: true, ignored: vec!["policy file is not valid JSON".into()], ..Default::default() };
    };
    from_lookup(
        |name| json.get(name).and_then(|v| v.as_str()).map(str::to_string),
        |name| json.get(name).and_then(|v| v.as_u64().map(|n| n.min(u32::MAX as u64) as u32).or_else(|| v.as_bool().map(u32::from))),
    )
}

#[tauri::command]
pub fn managed_settings() -> ManagedSettings {
    read()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn build(text: &[(&str, &str)], nums: &[(&str, u32)]) -> ManagedSettings {
        let t: HashMap<_, _> = text.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        let n: HashMap<_, _> = nums.iter().map(|(k, v)| (k.to_string(), *v)).collect();
        from_lookup(|k| t.get(k).cloned(), |k| n.get(k).copied())
    }

    #[test]
    fn nothing_set_is_unmanaged() {
        assert_eq!(build(&[], &[]), ManagedSettings::default());
    }

    #[test]
    fn reads_every_value() {
        let s = build(
            &[("ServerUrl", "https://vault.contoso.com/"), ("AllowedEmailDomains", "@Contoso.com; contoso.co.ke, contoso.com")],
            &[("DisableAccountCreation", 1), ("RequireSignIn", 1), ("MaxAutoLockMinutes", 10)],
        );
        assert!(s.managed);
        assert_eq!(s.server_url.as_deref(), Some("https://vault.contoso.com"));
        assert_eq!(s.allowed_email_domains, vec!["contoso.com", "contoso.co.ke"]);
        assert!(s.disable_account_creation && s.require_sign_in);
        assert_eq!(s.max_auto_lock_minutes, Some(10));
        assert!(s.ignored.is_empty());
    }

    #[test]
    fn rejects_unsafe_values() {
        let s = build(
            &[("ServerUrl", "http://evil.example.com"), ("AllowedEmailDomains", "contoso.com, not a domain, .bad")],
            &[("MaxAutoLockMinutes", 99999)],
        );
        assert_eq!(s.server_url, None);
        assert_eq!(s.allowed_email_domains, vec!["contoso.com"]);
        assert_eq!(s.max_auto_lock_minutes, None);
        assert_eq!(s.ignored.len(), 6); // server, "not", "a", "domain", ".bad", minutes
        assert_eq!(build(&[("ServerUrl", "http://localhost:8000")], &[]).server_url.as_deref(), Some("http://localhost:8000"));
    }
}
