//! Which saved logins fit a login form on Android (or anywhere else that
//! tells us a web domain or an app package).
//!
//! - Websites: same registrable domain as the saved address
//!   (`online.equitybank.co.ke` fits a login saved for `equitybank.co.ke`),
//!   never a mere look-alike. The phishing guard runs separately.
//! - Apps: logins the person already used in that app (remembered in the
//!   record's `android_apps` field), then suggestions whose name or website
//!   shares a word with the package name (`com.kcb.mobilebanking` -> KCB).

use crate::phishing::registrable_domain;
use crate::record::Record;

pub const APPS_FIELD: &str = "android_apps";

const NOISE: &[&str] = &[
    "com", "org", "net", "co", "ke", "android", "app", "apps", "mobile", "mobilebanking", "banking", "bank", "client", "android",
    "prod", "release", "official", "lite", "go", "ltd", "inc", "group", "plus", "pro", "www", "m", "online", "my",
];

fn host(url: &str) -> Option<String> {
    let u = url.trim();
    if u.is_empty() {
        return None;
    }
    let with = if u.contains("://") { u.to_string() } else { format!("https://{u}") };
    url::Url::parse(&with).ok()?.host_str().map(|h| h.trim_end_matches('.').to_ascii_lowercase())
}

/// Does a login saved for `record_url` belong on a page at `web_domain`?
pub fn fits_domain(record_url: &str, web_domain: &str) -> bool {
    match (host(record_url), host(web_domain)) {
        (Some(a), Some(b)) => registrable_domain(&a) == registrable_domain(&b),
        _ => false,
    }
}

pub fn remembered_apps(r: &Record) -> Vec<String> {
    r.fields.get(APPS_FIELD).map(|v| v.split([',', ' ']).filter(|s| !s.is_empty()).map(str::to_string).collect()).unwrap_or_default()
}

pub fn fits_app(r: &Record, package: &str) -> bool {
    remembered_apps(r).iter().any(|p| p == package)
}

/// Meaningful words in a package name: `com.kcb.mobilebanking` -> ["kcb"].
pub fn app_words(package: &str) -> Vec<String> {
    package
        .to_ascii_lowercase()
        .split(['.', '_', '-'])
        .filter(|w| w.len() >= 3 && !NOISE.contains(w))
        .map(str::to_string)
        .collect()
}

/// A loose guess for an app nobody has used Clavium in yet.
pub fn suggests_app(r: &Record, package: &str) -> bool {
    let words = app_words(package);
    if words.is_empty() {
        return false;
    }
    let title = r.title.to_ascii_lowercase();
    let site = host(&r.url).map(|h| registrable_domain(&h)).unwrap_or_default();
    let site_label = site.split('.').next().unwrap_or("");
    words.iter().any(|w| {
        title.split(|c: char| !c.is_ascii_alphanumeric()).any(|t| t == w)
            || (!site_label.is_empty() && (site_label == w || (w.len() >= 4 && site_label.starts_with(w.as_str()))))
    })
}

/// Remember that this login is used in this app.
pub fn remember_app(r: &mut Record, package: &str) -> bool {
    let mut apps = remembered_apps(r);
    if apps.iter().any(|p| p == package) {
        return false;
    }
    apps.push(package.to_string());
    r.fields.insert(APPS_FIELD.to_string(), apps.join(", "));
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn login(title: &str, url: &str) -> Record {
        let mut r = Record::new(title);
        r.url = url.into();
        r.password = "x".into();
        r
    }

    #[test]
    fn websites_match_by_owner_not_by_resemblance() {
        assert!(fits_domain("https://equitybank.co.ke", "online.equitybank.co.ke"));
        assert!(fits_domain("ke.kcbgroup.com/login", "https://kcbgroup.com"));
        assert!(!fits_domain("https://equitybank.co.ke", "equitybnak.co.ke"));
        assert!(!fits_domain("https://kcbgroup.com", "kcbgroup.com.evil.io"));
        assert!(!fits_domain("", "kcbgroup.com"));
    }

    #[test]
    fn apps_are_remembered_and_guessed() {
        let mut kcb = login("KCB corporate", "https://kcbgroup.com");
        assert_eq!(app_words("com.kcb.mobilebanking.android"), vec!["kcb"]);
        assert!(suggests_app(&kcb, "com.kcb.mobilebanking.android"));
        assert!(suggests_app(&login("Equity", "https://equitybank.co.ke"), "ke.co.equitybank.equitymobile"));
        assert!(!suggests_app(&login("Gmail", "https://gmail.com"), "com.kcb.mobilebanking"));
        assert!(!fits_app(&kcb, "com.kcb.mobilebanking.android"));
        assert!(remember_app(&mut kcb, "com.kcb.mobilebanking.android"));
        assert!(!remember_app(&mut kcb, "com.kcb.mobilebanking.android"));
        assert!(remember_app(&mut kcb, "com.kcb.vooma"));
        assert!(fits_app(&kcb, "com.kcb.vooma"));
        assert_eq!(kcb.fields[APPS_FIELD], "com.kcb.mobilebanking.android, com.kcb.vooma");
    }
}
