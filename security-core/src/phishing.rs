//! Phishing guard: is this web address really the site it seems to be?
//!
//! Works offline, from three things: the sites a person already has
//! logins for, a list of official domains of brands people get phished
//! with (Kenyan banks, M-Pesa, KRA, eCitizen, Microsoft, Google...), and
//! the shape of the address itself. It never sends the address anywhere.
//!
//! It catches the common tricks:
//! - a brand name on someone else's domain: `kcb-secure-login.com`
//! - a misspelling or look-alike letters: `equitybnak.co.ke`, `safaricorn.com`
//! - the right name with a different ending: `kcbgroup.net`
//! - an address that hides where it goes: `https://kcbgroup.com@evil.site`
//! - international look-alike letters (punycode), raw IP addresses,
//!   link shorteners, and throwaway domain endings.

use serde::Serialize;

use crate::categorize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// A site you have a login for, or a brand's official site.
    Trusted,
    /// Nothing known either way.
    Unknown,
    /// Has warning signs; be careful.
    Suspicious,
    /// Pretends to be a site it is not. Do not enter anything.
    Dangerous,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Assessment {
    pub verdict: Verdict,
    /// The host as the browser would go to it (punycode for IDNs).
    pub host: String,
    /// The part of the host a company actually owns, e.g. `kcbgroup.com`.
    pub domain: String,
    /// Plain-language reasons, most important first.
    pub reasons: Vec<String>,
    /// The site it imitates, e.g. "KCB".
    pub imitates: Option<String>,
    /// That site's real address.
    pub official: Option<String>,
}

/// Brands people are commonly phished with: display name, words that
/// identify it in an address, official registrable domains.
const BRANDS: &[(&str, &[&str], &[&str])] = &[
    ("KCB", &["kcb", "kcbgroup", "kcbbank"], &["kcbgroup.com", "kcbbankgroup.com"]),
    ("Equity Bank", &["equity", "equitybank", "equitel"], &["equitybank.co.ke", "equitygroupholdings.com", "equitybankgroup.com"]),
    ("M-Pesa / Safaricom", &["mpesa", "m-pesa", "safaricom", "fuliza", "mshwari"], &["safaricom.co.ke", "safaricom.com", "mpesa.co.ke", "m-pesa.com", "safaricom.et", "safaricomcloud.com"]),
    ("NCBA", &["ncba", "ncbagroup"], &["ncbagroup.com", "ncbaloop.com"]),
    ("Co-op Bank", &["coopbank", "co-opbank", "mcoopcash"], &["co-opbank.co.ke"]),
    ("Absa", &["absa", "absabank"], &["absabank.co.ke", "absa.co.za", "absa.africa", "absa.co.ke"]),
    ("Stanbic", &["stanbic", "stanbicbank"], &["stanbicbank.co.ke", "stanbicbank.co.ug", "stanbicbank.co.tz", "stanbic.com"]),
    ("Standard Chartered", &["standardchartered", "stanchart"], &["sc.com"]),
    ("I&M Bank", &["imbank", "imbankgroup"], &["imbankgroup.com"]),
    ("DTB", &["dtbafrica", "dtbkenya"], &["dtbafrica.com"]),
    ("Family Bank", &["familybank"], &["familybank.co.ke"]),
    ("Airtel Money", &["airtel", "airtelmoney"], &["airtelkenya.com", "airtel.africa", "airtel.com", "airtelmoney.com", "airtel.co.ke"]),
    ("KRA iTax", &["kra", "itax"], &["kra.go.ke"]),
    ("eCitizen", &["ecitizen"], &["ecitizen.go.ke"]),
    ("SHA / NHIF", &["nhif", "sha-ke"], &["sha.go.ke", "nhif.or.ke"]),
    ("HELB", &["helb"], &["helb.co.ke"]),
    ("PayPal", &["paypal"], &["paypal.com", "paypal.me", "paypalobjects.com"]),
    ("Microsoft", &["microsoft", "office365", "microsoft365", "outlook", "onedrive", "sharepoint", "hotmail"], &[
        "microsoft.com", "microsoftonline.com", "live.com", "office.com", "office365.com", "outlook.com", "microsoft365.com",
        "sharepoint.com", "onedrive.com", "hotmail.com", "azure.com", "windows.net", "msauth.net", "msftauth.net", "skype.com", "xbox.com", "bing.com",
    ]),
    ("Google", &["google", "gmail"], &["google.com", "gmail.com", "googleusercontent.com", "gstatic.com", "youtube.com", "google.co.ke", "withgoogle.com", "googleapis.com", "goo.gl", "g.co"]),
    ("Apple", &["apple", "icloud", "appleid"], &["apple.com", "icloud.com", "me.com", "apple.co"]),
    ("Facebook", &["facebook", "fb-login"], &["facebook.com", "fb.com", "meta.com", "messenger.com", "fbcdn.net"]),
    ("Instagram", &["instagram"], &["instagram.com", "cdninstagram.com"]),
    ("WhatsApp", &["whatsapp"], &["whatsapp.com", "whatsapp.net", "wa.me"]),
    ("Netflix", &["netflix"], &["netflix.com"]),
    ("Amazon", &["amazon"], &["amazon.com", "amazon.co.uk", "amazon.de", "aws.amazon.com", "amazonaws.com", "amazon.in"]),
    ("Jumia", &["jumia"], &["jumia.co.ke", "jumia.com", "jumia.com.ng"]),
    ("Binance", &["binance"], &["binance.com"]),
    ("DHL", &["dhl"], &["dhl.com", "dhl.co.ke", "dhl.de"]),
    ("GitHub", &["github"], &["github.com", "githubusercontent.com", "github.io"]),
];

/// Second-level endings that belong to a registry, not a company.
const MULTI_SUFFIXES: &[&str] = &[
    "co.ke", "or.ke", "go.ke", "ac.ke", "ne.ke", "sc.ke", "me.ke", "mobi.ke", "info.ke",
    "co.ug", "or.ug", "go.ug", "ac.ug", "co.tz", "or.tz", "go.tz", "ac.tz", "co.rw", "gov.rw",
    "com.ng", "gov.ng", "com.gh", "gov.gh", "co.za", "org.za", "gov.za", "ac.za", "com.et",
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.in", "co.jp", "com.br",
    "github.io", "herokuapp.com", "vercel.app", "netlify.app", "web.app", "firebaseapp.com",
    "pages.dev", "workers.dev", "blogspot.com", "azurewebsites.net", "appspot.com", "ngrok.io",
    "ngrok-free.app", "glitch.me", "wixsite.com", "weebly.com", "000webhostapp.com",
];

const SHORTENERS: &[&str] = &[
    "bit.ly", "tinyurl.com", "t.ly", "cutt.ly", "rb.gy", "is.gd", "ow.ly", "shorturl.at", "rebrand.ly",
    "tiny.cc", "s.id", "t.co", "lnkd.in", "buff.ly", "bit.do", "shorte.st",
];

const RISKY_ENDINGS: &[&str] = &[
    "xyz", "top", "click", "zip", "mov", "icu", "buzz", "rest", "cfd", "sbs", "cyou", "monster", "quest",
    "support", "live", "online", "site", "website", "shop", "info", "work", "gq", "tk", "ml", "cf", "ga",
];

const LURE_WORDS: &[&str] = &[
    "login", "signin", "sign-in", "verify", "verification", "secure", "security", "update", "account",
    "confirm", "unlock", "suspend", "suspended", "wallet", "reward", "bonus", "refund", "kyc", "support",
];

/// The part of a host its owner registered: `ke.kcbgroup.com` -> `kcbgroup.com`,
/// `online.equitybank.co.ke` -> `equitybank.co.ke`.
pub fn registrable_domain(host: &str) -> String {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() <= 2 {
        return host;
    }
    let last_two = labels[labels.len() - 2..].join(".");
    let take = if MULTI_SUFFIXES.contains(&last_two.as_str()) {
        3
    } else {
        let last_three = labels[labels.len() - 3..].join(".");
        if labels.len() >= 4 && MULTI_SUFFIXES.contains(&last_three.as_str()) { 4 } else { 2 }
    };
    labels[labels.len() - take.min(labels.len())..].join(".")
}

/// First label of a registrable domain: `equitybank.co.ke` -> `equitybank`.
fn name_label(domain: &str) -> &str {
    domain.split('.').next().unwrap_or(domain)
}

fn ending(domain: &str) -> &str {
    domain.split_once('.').map(|(_, e)| e).unwrap_or("")
}

/// Undo the usual look-alike swaps so `rn`, `0` and `1` compare like
/// `m`, `o` and `l`.
fn skeleton(s: &str) -> String {
    s.replace("rn", "m")
        .replace("vv", "w")
        .replace("cl", "d")
        .chars()
        .map(|c| match c {
            '0' => 'o',
            '1' | 'i' | '!' | '|' => 'l',
            '3' => 'e',
            '4' | '@' => 'a',
            '5' | '$' => 's',
            '7' => 't',
            '8' => 'b',
            '-' | '_' => '\0',
            c => c,
        })
        .filter(|c| *c != '\0')
        .collect()
}

/// Edit distance counting a swap of neighbours as one edit.
fn distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (n, m) = (a.len(), b.len());
    let mut d = vec![vec![0usize; m + 1]; n + 1];
    for (i, row) in d.iter_mut().enumerate() {
        row[0] = i;
    }
    for j in 0..=m {
        d[0][j] = j;
    }
    for i in 1..=n {
        for j in 1..=m {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            d[i][j] = (d[i - 1][j] + 1).min(d[i][j - 1] + 1).min(d[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                d[i][j] = d[i][j].min(d[i - 2][j - 2] + 1);
            }
        }
    }
    d[n][m]
}

fn looks_like(candidate: &str, real: &str) -> bool {
    if candidate == real || real.len() < 5 {
        return false;
    }
    let (sc, sr) = (skeleton(candidate), skeleton(real));
    if sc == sr {
        return true;
    }
    let allowed = if real.len() >= 9 { 2 } else { 1 };
    distance(candidate, real) <= allowed || distance(&sc, &sr) <= allowed
}

struct Known {
    name: String,
    domains: Vec<String>,
    words: Vec<String>,
    /// From the hand-picked brand list (not derived from saved logins).
    curated: bool,
}

fn known_sites(saved: &[String]) -> Vec<Known> {
    let mut out: Vec<Known> = BRANDS
        .iter()
        .map(|(name, words, domains)| Known {
            name: (*name).to_string(),
            domains: domains.iter().map(|d| d.to_string()).collect(),
            words: words.iter().map(|w| w.to_string()).collect(),
            curated: true,
        })
        .collect();
    // Every finance and banking site Clavium already recognises counts as
    // a brand too (its name label is the identifying word).
    for d in categorize::known_domains(&["banking", "finance"]) {
        let reg = registrable_domain(d);
        if out.iter().any(|k| k.domains.contains(&reg)) {
            continue;
        }
        // Short names ("sc", "wise", "citi") would match innocent words.
        let label = name_label(&reg).to_string();
        let words = if label.len() >= 6 { vec![label] } else { vec![] };
        out.push(Known { name: reg.clone(), words, domains: vec![reg], curated: true });
    }
    for h in saved {
        let reg = registrable_domain(h);
        if reg.contains('.') && !out.iter().any(|k| k.domains.contains(&reg)) {
            out.push(Known { name: reg.clone(), words: vec![], domains: vec![reg], curated: false });
        }
    }
    out
}

fn host_of(url: &str) -> Option<(url::Url, String)> {
    let trimmed = url.trim();
    let with_scheme = if trimmed.contains("://") { trimmed.to_string() } else { format!("https://{trimmed}") };
    let parsed = url::Url::parse(&with_scheme).ok()?;
    let host = parsed.host_str()?.trim_end_matches('.').to_ascii_lowercase();
    Some((parsed, host))
}

/// Check one address. `saved_urls` are the website addresses in the
/// person's vaults (sites they already trust enough to have a login for).
pub fn assess(url: &str, saved_urls: &[String]) -> Assessment {
    let Some((parsed, host)) = host_of(url) else {
        return Assessment {
            verdict: Verdict::Unknown,
            host: String::new(),
            domain: String::new(),
            reasons: vec!["This is not a web address Clavium can read.".into()],
            imitates: None,
            official: None,
        };
    };
    let saved_hosts: Vec<String> = saved_urls.iter().filter_map(|u| host_of(u).map(|(_, h)| h)).collect();
    let is_ip = parsed.host().is_some_and(|h| !matches!(h, url::Host::Domain(_)));
    let domain = if is_ip { host.clone() } else { registrable_domain(&host) };
    let mut a = Assessment { verdict: Verdict::Unknown, host: host.clone(), domain: domain.clone(), reasons: vec![], imitates: None, official: None };
    let insecure = parsed.scheme() == "http";

    // Text before an @ is decoration; the browser goes to what follows it.
    if !parsed.username().is_empty() || parsed.password().is_some() {
        a.verdict = Verdict::Dangerous;
        a.reasons.push(format!(
            "The address is written to look like \"{}\" but actually goes to {host}.",
            urlencoding_lossy(parsed.username())
        ));
        return a;
    }

    let known = known_sites(&saved_hosts);
    let saved_domains: Vec<String> = saved_hosts.iter().map(|h| registrable_domain(h)).collect();
    let is_saved = saved_domains.contains(&domain);

    if let Some(k) = known.iter().find(|k| k.curated && k.domains.contains(&domain)) {
        a.verdict = Verdict::Trusted;
        a.reasons.push(format!("This is the official website of {}.", k.name));
        if insecure {
            a.reasons.push("But this page is not encrypted (http). Do not type a password here.".into());
            a.verdict = Verdict::Suspicious;
        }
        return a;
    }
    if is_ip {
        a.verdict = Verdict::Suspicious;
        a.reasons.push("The address is a bare number, not a website name. Real banks and services never send you to one.".into());
        return a;
    }

    if let Some((k, official, reason)) = imitation(&host, &domain, &known) {
        if is_saved {
            // Saved before: either a lookalike someone fell for, or a real
            // site that happens to resemble a brand. Warn, do not block.
            if !k.curated {
                a.verdict = Verdict::Trusted;
                a.reasons.push("You have a login saved for this website.".into());
                return a;
            }
            a.verdict = Verdict::Suspicious;
            a.imitates = Some(k.name.clone());
            a.official = Some(official);
            a.reasons.push(format!("You have a login saved here, but {reason}"));
            a.reasons.push(format!("If you typed your {} password into this site, change it on the real site now.", k.name));
            return a;
        }
        a.verdict = Verdict::Dangerous;
        a.imitates = Some(k.name.clone());
        a.official = Some(official);
        a.reasons.push(capitalised(reason));
        return a;
    }
    if is_saved {
        a.verdict = Verdict::Trusted;
        a.reasons.push("You have a login saved for this website.".into());
        if insecure {
            a.reasons.push("But this page is not encrypted (http). Do not type a password here.".into());
            a.verdict = Verdict::Suspicious;
        }
        return a;
    }
    let tokens: Vec<&str> = host.split(['.', '-', '_']).filter(|t| !t.is_empty()).collect();

    if host.split('.').any(|l| l.starts_with("xn--")) {
        a.verdict = Verdict::Suspicious;
        a.reasons.push("The address uses foreign letters that can look identical to normal ones.".into());
    }
    if SHORTENERS.contains(&domain.as_str()) {
        a.reasons.push("This is a short link: it hides the real address. Open it only if you trust who sent it.".into());
    }
    let tld = host.rsplit('.').next().unwrap_or("");
    let lure = tokens.iter().any(|t| LURE_WORDS.contains(t));
    if RISKY_ENDINGS.contains(&tld) && lure {
        a.verdict = Verdict::Suspicious;
        a.reasons.push(format!("A cheap \".{tld}\" address asking you to log in or verify something: a common scam pattern."));
    } else if lure && tokens.len() >= 4 {
        a.verdict = a.verdict.max_with(Verdict::Suspicious);
        a.reasons.push("The address is stuffed with words like \"secure\" or \"verify\": a common scam pattern.".into());
    }
    if insecure {
        a.reasons.push("This page is not encrypted (http). Do not type a password here.".into());
        a.verdict = a.verdict.max_with(Verdict::Suspicious);
    }
    if a.reasons.is_empty() {
        a.reasons.push("Clavium does not know this website. That is not bad in itself: just check it is the site you meant.".into());
    }
    a
}

/// Does this address imitate a known site? Returns the site, its real
/// address and a plain-language reason.
fn imitation<'k>(host: &str, domain: &str, known: &'k [Known]) -> Option<(&'k Known, String, String)> {
    let tokens: Vec<&str> = host.split(['.', '-', '_']).filter(|t| !t.is_empty()).collect();
    let label = name_label(domain);
    let joined_host = host.replace(['.', '-', '_'], "");
    // A brand's name on someone else's domain.
    for k in known.iter().filter(|k| !k.words.is_empty()) {
        let hit = k.words.iter().any(|w| {
            let plain = w.replace('-', "");
            tokens.iter().any(|t| *t == w.as_str() || *t == plain.as_str()) || (plain.len() >= 5 && joined_host.contains(&plain))
        });
        if hit {
            let official = k.domains.first().cloned().unwrap_or_default();
            return Some((k, official.clone(), format!("the address mentions {} but this is not {}'s website. Their real address is {official}.", k.name, k.name)));
        }
    }
    // A misspelling, look-alike letters, or the same name with another ending.
    for k in known {
        for d in &k.domains {
            let real = name_label(d);
            if d == domain {
                continue;
            }
            if real == label && ending(d) != ending(domain) && real.len() >= 4 {
                return Some((k, d.clone(), format!("it has the same name as {d} but a different ending ({domain}). Copycats register these.")));
            }
            if looks_like(label, real) {
                return Some((k, d.clone(), format!("{domain} is spelled to look like {d}.")));
            }
        }
    }
    None
}

fn capitalised(s: String) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => s,
    }
}

impl Verdict {
    fn rank(self) -> u8 {
        match self {
            Verdict::Trusted => 0,
            Verdict::Unknown => 1,
            Verdict::Suspicious => 2,
            Verdict::Dangerous => 3,
        }
    }
    fn max_with(self, other: Verdict) -> Verdict {
        if other.rank() > self.rank() { other } else { self }
    }
}

fn urlencoding_lossy(s: &str) -> String {
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(url: &str) -> Verdict {
        assess(url, &[]).verdict
    }

    #[test]
    fn official_and_saved_sites_are_trusted() {
        assert_eq!(v("https://ke.kcbgroup.com/login"), Verdict::Trusted);
        assert_eq!(v("online.equitybank.co.ke"), Verdict::Trusted);
        assert_eq!(v("https://login.microsoftonline.com/common/oauth2"), Verdict::Trusted);
        assert_eq!(v("https://itax.kra.go.ke"), Verdict::Trusted);
        let saved = vec!["https://portal.tenrixgroup.com".to_string()];
        assert_eq!(assess("https://portal.tenrixgroup.com/x", &saved).verdict, Verdict::Trusted);
        assert_eq!(assess("https://other.tenrixgroup.com", &saved).verdict, Verdict::Trusted);
    }

    #[test]
    fn brand_names_on_other_domains_are_dangerous() {
        let a = assess("https://kcb-secure-login.com/verify", &[]);
        assert_eq!(a.verdict, Verdict::Dangerous);
        assert_eq!(a.imitates.as_deref(), Some("KCB"));
        assert_eq!(a.official.as_deref(), Some("kcbgroup.com"));
        assert_eq!(v("http://mpesa-reversal.co.ke"), Verdict::Dangerous);
        assert_eq!(v("safaricom.account-update.top"), Verdict::Dangerous);
        assert_eq!(v("https://kra-itax-refund.online"), Verdict::Dangerous);
        assert_eq!(v("https://microsoft365-login.web.app"), Verdict::Dangerous);
        assert_eq!(v("https://ecitizen-gov.ke-services.com"), Verdict::Dangerous);
    }

    #[test]
    fn misspellings_and_other_endings_are_dangerous() {
        assert_eq!(v("https://equitybnak.co.ke"), Verdict::Dangerous);
        assert_eq!(v("https://safaricorn.co.ke"), Verdict::Dangerous);
        assert_eq!(v("https://paypa1.com"), Verdict::Dangerous);
        assert_eq!(v("https://kcbgroup.net"), Verdict::Dangerous);
        assert_eq!(v("https://ncbagr0up.com"), Verdict::Dangerous);
        let saved = vec!["https://portal.tenrixgroup.com".to_string()];
        assert_eq!(assess("https://tenrixgruop.com", &saved).verdict, Verdict::Dangerous);
    }

    #[test]
    fn hidden_destinations_and_odd_addresses() {
        let a = assess("https://kcbgroup.com@evil.example/login", &[]);
        assert_eq!(a.verdict, Verdict::Dangerous);
        assert!(a.reasons[0].contains("evil.example"));
        assert_eq!(v("http://192.168.4.20/login"), Verdict::Suspicious);
        assert_eq!(v("https://xn--80ak6aa92e.com"), Verdict::Suspicious);
        assert_eq!(v("https://secure-account-verify.top"), Verdict::Suspicious);
        assert_eq!(v("http://ke.kcbgroup.com"), Verdict::Suspicious);
        let short = assess("https://bit.ly/3abc", &[]);
        assert_eq!(short.verdict, Verdict::Unknown);
        assert!(short.reasons[0].contains("short link"));
    }

    #[test]
    fn no_known_legitimate_site_is_called_dangerous() {
        let all = categorize::known_domains(&[
            "banking", "finance", "email", "social", "work", "development", "cloud", "infrastructure", "network",
            "shopping", "entertainment", "government", "travel", "utilities", "health", "education", "personal", "software", "other",
        ]);
        let extra = [
            "nation.africa", "standardmedia.co.ke", "kplc.co.ke", "kenyapower.co.ke", "nairobiwater.co.ke", "kenya-airways.com",
            "kq.com", "uonbi.ac.ke", "strathmore.edu", "jkuat.ac.ke", "bolt.eu", "uber.com", "glovoapp.com", "sendy.co.ke",
            "zuku.co.ke", "faiba.co.ke", "telkom.co.ke", "kenyalaw.org", "businessdailyafrica.com", "the-star.co.ke",
            "pesalink.co.ke", "ipsl.co.ke", "kenswitch.com", "sasapay.co.ke", "kopokopo.co.ke", "tala.co.ke", "branch.co.ke",
        ];
        for d in all.iter().copied().chain(extra) {
            let a = assess(&format!("https://{d}/login"), &[]);
            assert_ne!(a.verdict, Verdict::Dangerous, "{d}: {:?}", a.reasons);
        }
    }

    #[test]
    fn a_saved_lookalike_still_warns_but_a_saved_internal_site_does_not() {
        let saved = vec!["https://equitybnak.co.ke/login".to_string(), "https://mpesa-tools.internal.co.ke".to_string()];
        let a = assess("https://equitybnak.co.ke/login", &saved);
        assert_eq!(a.verdict, Verdict::Suspicious);
        assert!(a.reasons[0].starts_with("You have a login saved here, but"), "{:?}", a.reasons);
        assert!(a.reasons[1].contains("change it"));
        // A saved site resembling another saved site is the person's own business.
        let mine = vec!["https://tenrixgroup.com".to_string(), "https://tenrixgruop.com".to_string()];
        assert_eq!(assess("https://tenrixgruop.com", &mine).verdict, Verdict::Trusted);
    }

    #[test]
    fn ordinary_unknown_sites_are_not_flagged() {
        for u in ["https://nation.africa", "https://example.org", "https://kenyatta.ac.ke", "https://mydukashop.co.ke", "https://loopedin.io"] {
            assert_eq!(v(u), Verdict::Unknown, "{u}");
        }
        assert_eq!(registrable_domain("a.b.equitybank.co.ke"), "equitybank.co.ke");
        assert_eq!(registrable_domain("ke.kcbgroup.com"), "kcbgroup.com");
        assert_eq!(registrable_domain("evil.github.io"), "evil.github.io");
    }
}
