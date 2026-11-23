//! Automatic categorisation. Runs on the device, against decrypted records:
//! the server never sees a record's contents, so it could not categorise
//! even if we wanted it to. Rules only, no model. Order of evidence:
//!
//! 1. A rule this person taught the vault (they recategorised a record for
//!    `kcbgroup.com`, so every other `kcbgroup.com` record follows).
//! 2. The record's kind (a `Card` is banking whatever its title says).
//! 3. The record's URL, matched against curated domain lists and
//!    well-known public suffixes (`.go.ke`, `.ac.ke`, `.gov`, ...).
//! 4. Keywords in the title.
//!
//! A category a person picked by hand ([`CategorySource::User`]) is never
//! overwritten.

use std::collections::BTreeMap;

use crate::record::{CategorySource, Record, RecordKind};

/// Every category slug a client can show, with its display label.
pub const CATEGORIES: &[(&str, &str)] = &[
    ("banking", "Banking & mobile money"),
    ("finance", "Payments, investing & insurance"),
    ("email", "Email"),
    ("social", "Social"),
    ("work", "Work & collaboration"),
    ("development", "Development"),
    ("cloud", "Cloud & hosting"),
    ("infrastructure", "Servers & databases"),
    ("network", "Wi-Fi & network"),
    ("shopping", "Shopping"),
    ("entertainment", "Entertainment"),
    ("government", "Government"),
    ("travel", "Travel & transport"),
    ("utilities", "Utilities & telecom"),
    ("health", "Health"),
    ("education", "Education"),
    ("personal", "Personal & identity"),
    ("software", "Software licences"),
    ("other", "Other"),
];

pub fn is_known_category(slug: &str) -> bool {
    CATEGORIES.iter().any(|(s, _)| *s == slug)
}

pub fn category_label(slug: &str) -> Option<&'static str> {
    CATEGORIES.iter().find(|(s, _)| *s == slug).map(|(_, l)| *l)
}

/// Registrable-domain suffixes per category. A host matches when it equals
/// the entry or ends with `.` + the entry.
const DOMAINS: &[(&str, &[&str])] = &[
    (
        "banking",
        &[
            // Kenya
            "kcbgroup.com", "ke.kcbgroup.com", "equitybank.co.ke", "equitygroupholdings.com",
            "ncbagroup.com", "co-opbank.co.ke", "stanbicbank.co.ke", "absabank.co.ke",
            "sc.com", "imbankgroup.com", "dtbafrica.com", "familybank.co.ke",
            "nationalbank.co.ke", "sidianbank.co.ke", "gulfafricanbank.com", "hfgroup.co.ke",
            "primebank.co.ke", "kingdombankltd.co.ke", "ecobank.com", "boakenya.com",
            "mpesa.co.ke", "m-pesa.com", "airtelmoney.com", "tkash.co.ke", "centralbank.go.ke",
            // International
            "chase.com", "bankofamerica.com", "wellsfargo.com", "citi.com", "hsbc.com",
            "hsbc.co.uk", "barclays.co.uk", "lloydsbank.com", "natwest.com", "santander.com",
            "monzo.com", "revolut.com", "wise.com", "n26.com", "capitalone.com", "usbank.com",
            "standardbank.co.za", "fnb.co.za", "nedbank.co.za", "gtbank.com", "accessbankplc.com",
            "zenithbank.com", "firstbanknigeria.com", "crdbbank.co.tz", "nmbbank.co.tz",
            "stanbicbank.co.ug", "centenarybank.co.ug",
        ],
    ),
    (
        "finance",
        &[
            "paypal.com", "stripe.com", "flutterwave.com", "paystack.com", "pesapal.com",
            "cellulant.io", "visa.com", "mastercard.com", "americanexpress.com", "klarna.com",
            "coinbase.com", "binance.com", "kraken.com", "robinhood.com", "etrade.com",
            "fidelity.com", "vanguard.com", "schwab.com", "nse.co.ke", "cdsckenya.com",
            "britam.com", "jubileeinsurance.com", "cic.co.ke", "oldmutual.co.ke", "sanlam.com",
            "quickbooks.intuit.com", "xero.com", "freshbooks.com", "zohobooks.com",
        ],
    ),
    (
        "email",
        &[
            "mail.google.com", "gmail.com", "outlook.com", "outlook.live.com", "hotmail.com",
            "live.com", "mail.yahoo.com", "yahoo.com", "proton.me", "protonmail.com",
            "icloud.com", "zoho.com", "mail.zoho.com", "fastmail.com", "tutanota.com", "aol.com",
        ],
    ),
    (
        "social",
        &[
            "facebook.com", "instagram.com", "twitter.com", "x.com", "linkedin.com",
            "tiktok.com", "snapchat.com", "reddit.com", "pinterest.com", "threads.net",
            "whatsapp.com", "web.whatsapp.com", "telegram.org", "discord.com", "signal.org",
            "mastodon.social", "bsky.app", "quora.com", "tumblr.com",
        ],
    ),
    (
        "work",
        &[
            "office.com", "microsoft365.com", "login.microsoftonline.com", "sharepoint.com",
            "teams.microsoft.com", "workspace.google.com", "slack.com", "zoom.us",
            "atlassian.com", "atlassian.net", "notion.so", "asana.com", "trello.com",
            "monday.com", "clickup.com", "salesforce.com", "hubspot.com", "zendesk.com",
            "freshdesk.com", "dropbox.com", "box.com", "docusign.com", "odoo.com",
            "calendly.com", "miro.com", "figma.com", "canva.com", "webex.com",
        ],
    ),
    (
        "development",
        &[
            "github.com", "gitlab.com", "bitbucket.org", "npmjs.com", "pypi.org",
            "crates.io", "hub.docker.com", "docker.com", "stackoverflow.com", "sentry.io",
            "jetbrains.com", "postman.com", "expo.dev", "pub.dev", "sonarcloud.io",
            "circleci.com", "travis-ci.com", "anthropic.com", "openai.com", "huggingface.co",
            "play.google.com", "developer.apple.com", "appstoreconnect.apple.com",
        ],
    ),
    (
        "cloud",
        &[
            "aws.amazon.com", "console.aws.amazon.com", "portal.azure.com", "azure.com",
            "azure.microsoft.com", "cloud.google.com", "console.cloud.google.com",
            "digitalocean.com", "linode.com", "vultr.com", "hetzner.com", "ovh.com",
            "cloudflare.com", "heroku.com", "vercel.com", "netlify.com", "render.com",
            "fly.io", "supabase.com", "firebase.google.com", "namecheap.com", "godaddy.com",
            "kenic.or.ke", "truehost.co.ke", "safaricomcloud.com", "hostpinnacle.co.ke",
            "backblaze.com", "wasabi.com",
        ],
    ),
    (
        "shopping",
        &[
            "amazon.com", "amazon.co.uk", "amazon.de", "jumia.co.ke", "jumia.com",
            "kilimall.co.ke", "ebay.com", "aliexpress.com", "alibaba.com", "temu.com",
            "shein.com", "etsy.com", "walmart.com", "target.com", "carrefour.ke",
            "naivas.online", "glovoapp.com", "shopify.com", "ikea.com", "bestbuy.com",
        ],
    ),
    (
        "entertainment",
        &[
            "netflix.com", "spotify.com", "youtube.com", "showmax.com", "dstv.com",
            "disneyplus.com", "primevideo.com", "hulu.com", "max.com", "apple.com/tv",
            "twitch.tv", "steampowered.com", "store.steampowered.com", "epicgames.com",
            "playstation.com", "xbox.com", "nintendo.com", "boomplay.com", "deezer.com",
            "audiomack.com", "soundcloud.com", "crunchyroll.com", "gotv.co.ke",
        ],
    ),
    (
        "government",
        &[
            "ecitizen.go.ke", "kra.go.ke", "itax.kra.go.ke", "nssf.or.ke", "sha.go.ke",
            "nhif.or.ke", "ntsa.go.ke", "huduma.go.ke", "irs.gov", "gov.uk", "hmrc.gov.uk",
            "usa.gov", "ssa.gov", "login.gov",
        ],
    ),
    (
        "travel",
        &[
            "booking.com", "airbnb.com", "expedia.com", "kenya-airways.com", "kq.com",
            "emirates.com", "qatarairways.com", "ethiopianairlines.com", "turkishairlines.com",
            "britishairways.com", "jambojet.com", "uber.com", "bolt.eu", "littlecab.com",
            "tripadvisor.com", "skyscanner.net", "trip.com", "hotels.com", "agoda.com",
            "sgr.krc.co.ke", "metickets.krc.co.ke",
        ],
    ),
    (
        "utilities",
        &[
            "kplc.co.ke", "safaricom.co.ke", "safaricom.com", "airtelkenya.com", "airtel.com",
            "telkom.co.ke", "zuku.co.ke", "faiba.co.ke", "starlink.com", "nairobiwater.co.ke",
            "vodafone.com", "verizon.com", "att.com", "t-mobile.com", "mtn.com",
        ],
    ),
    (
        "health",
        &[
            "aku.edu", "agakhanhospitals.org", "nairobihospital.org", "mpshahhosp.org",
            "mydawa.com", "goodlife.co.ke", "myfitnesspal.com", "fitbit.com", "strava.com",
            "mychart.org", "zocdoc.com", "teladoc.com",
        ],
    ),
    (
        "education",
        &[
            "coursera.org", "udemy.com", "edx.org", "khanacademy.org", "duolingo.com",
            "linkedinlearning.com", "pluralsight.com", "udacity.com", "skillshare.com",
            "moodle.org", "classroom.google.com", "instructure.com", "canvas.net",
        ],
    ),
];

/// Public-suffix families that say something about the site on their own.
const SUFFIXES: &[(&str, &str)] = &[
    ("go.ke", "government"),
    ("gov", "government"),
    ("gov.uk", "government"),
    ("gov.au", "government"),
    ("gc.ca", "government"),
    ("gov.za", "government"),
    ("go.tz", "government"),
    ("go.ug", "government"),
    ("gov.ng", "government"),
    ("mil", "government"),
    ("ac.ke", "education"),
    ("edu", "education"),
    ("ac.uk", "education"),
    ("edu.au", "education"),
    ("ac.za", "education"),
    ("ac.tz", "education"),
    ("ac.ug", "education"),
    ("bank", "banking"),
    ("insurance", "finance"),
];

/// Title keywords, matched as whole words (lowercased). Checked last,
/// because a title is the least reliable signal.
const KEYWORDS: &[(&str, &[&str])] = &[
    // Most specific first: "Office Wi-Fi" is network, not work.
    ("network", &["wifi", "wi-fi", "wlan", "ssid", "hotspot"]),
    ("infrastructure", &["server", "ssh", "database", "db", "postgres", "mysql", "router", "firewall", "rdp"]),
    (
        "banking",
        &[
            "bank", "banking", "sacco", "mpesa", "m-pesa", "paybill", "till", "atm", "kcb",
            "equity", "ncba", "absa", "stanbic", "co-op", "coop", "fuliza", "mshwari",
        ],
    ),
    ("finance", &["paypal", "stripe", "invest", "broker", "crypto", "wallet", "insurance", "pension", "loan"]),
    ("email", &["email", "mail", "gmail", "outlook", "inbox", "smtp", "imap"]),
    ("social", &["facebook", "instagram", "twitter", "tiktok", "linkedin", "whatsapp", "telegram", "discord"]),
    ("work", &["office", "office365", "m365", "slack", "zoom", "teams", "jira", "confluence", "vpn", "intranet", "crm", "erp", "odoo"]),
    ("development", &["github", "gitlab", "git", "npm", "docker", "api", "token", "dev", "staging"]),
    ("cloud", &["aws", "azure", "gcp", "cloudflare", "hosting", "cpanel", "domain", "dns", "vps"]),
    ("shopping", &["shop", "store", "amazon", "jumia", "kilimall"]),
    ("entertainment", &["netflix", "spotify", "showmax", "dstv", "youtube", "steam", "playstation", "xbox", "games"]),
    ("government", &["kra", "itax", "ecitizen", "nhif", "nssf", "sha", "ntsa", "huduma", "passport", "tax"]),
    ("travel", &["airline", "flight", "uber", "bolt", "airbnb", "booking", "hotel", "sgr"]),
    ("utilities", &["kplc", "tokens", "electricity", "water", "safaricom", "airtel", "telkom", "internet", "zuku", "fibre", "fiber"]),
    ("health", &["hospital", "clinic", "insurance", "medical", "pharmacy", "doctor"]),
    ("education", &["school", "university", "college", "course", "student", "portal"]),
];

/// The category a record's kind implies on its own, if any.
fn category_for_kind(kind: RecordKind) -> Option<&'static str> {
    match kind {
        RecordKind::BankAccount | RecordKind::Card => Some("banking"),
        RecordKind::Identity => Some("personal"),
        RecordKind::Wifi => Some("network"),
        RecordKind::SshKey | RecordKind::Server | RecordKind::Database => Some("infrastructure"),
        RecordKind::ApiKey => Some("development"),
        RecordKind::SoftwareLicense => Some("software"),
        RecordKind::Login | RecordKind::SecureNote | RecordKind::Passkey => None,
    }
}

/// The lowercased host of a record URL, tolerating a missing scheme
/// ("kcbgroup.com/login") the way people actually type URLs.
pub fn host_of(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let with_scheme = if raw.contains("://") {
        raw.to_string()
    } else {
        format!("https://{raw}")
    };
    let parsed = url::Url::parse(&with_scheme).ok()?;
    let host = parsed.host_str()?.trim_end_matches('.').to_ascii_lowercase();
    let host = host.strip_prefix("www.").map(str::to_string).unwrap_or(host);
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

fn host_matches(host: &str, domain: &str) -> bool {
    host == domain || host.ends_with(&format!(".{domain}"))
}

/// Category from the URL alone. The longest (most specific) matching
/// domain wins, so `mail.google.com` is email even though other google.com
/// properties might be listed elsewhere.
pub fn category_for_url(raw: &str) -> Option<&'static str> {
    let host = host_of(raw)?;
    let mut best: Option<(&'static str, usize)> = None;
    for (category, domains) in DOMAINS {
        for domain in *domains {
            if host_matches(&host, domain) && best.map_or(true, |(_, len)| domain.len() > len) {
                best = Some((category, domain.len()));
            }
        }
    }
    if let Some((category, _)) = best {
        return Some(category);
    }
    let mut best_suffix: Option<(&'static str, usize)> = None;
    for (suffix, category) in SUFFIXES {
        if host_matches(&host, suffix) && best_suffix.map_or(true, |(_, len)| suffix.len() > len) {
            best_suffix = Some((category, suffix.len()));
        }
    }
    best_suffix.map(|(c, _)| c)
}

/// Category from title keywords alone.
pub fn category_for_title(title: &str) -> Option<&'static str> {
    let lower = title.to_lowercase();
    let words: Vec<&str> = lower
        .split(|c: char| !(c.is_alphanumeric() || c == '-'))
        .filter(|w| !w.is_empty())
        .collect();
    for (category, keywords) in KEYWORDS {
        if keywords.iter().any(|k| words.contains(k)) {
            return Some(category);
        }
    }
    None
}

/// The best category for `record`, consulting `learned` (host → category
/// rules this person taught the vault) first. `None` means "no evidence",
/// which a client shows as uncategorised rather than forcing "other".
pub fn suggest_category(record: &Record, learned: &BTreeMap<String, String>) -> Option<String> {
    if let Some(host) = host_of(&record.url) {
        // Most specific learned rule wins too.
        let mut best: Option<(&String, usize)> = None;
        for (domain, category) in learned {
            if host_matches(&host, domain) && best.map_or(true, |(_, len)| domain.len() > len) {
                best = Some((category, domain.len()));
            }
        }
        if let Some((category, _)) = best {
            return Some(category.clone());
        }
    }
    if let Some(c) = category_for_kind(record.kind) {
        return Some(c.to_string());
    }
    if let Some(c) = category_for_url(&record.url) {
        return Some(c.to_string());
    }
    if let Some(c) = category_for_title(&record.title) {
        return Some(c.to_string());
    }
    None
}

/// Apply [`suggest_category`] unless a person already chose the category.
/// Also fills in a card's brand when it can be read off the number.
/// Returns true when the record changed.
pub fn auto_categorize(record: &mut Record, learned: &BTreeMap<String, String>) -> bool {
    let mut changed = false;
    if record.category_source == CategorySource::Auto {
        let suggestion = suggest_category(record, learned);
        if suggestion != record.category {
            record.category = suggestion;
            changed = true;
        }
    }
    if record.kind == RecordKind::Card && record.field("brand").map_or(true, str::is_empty) {
        if let Some(brand) = record.field("number").and_then(detect_card_brand) {
            record.fields.insert("brand".into(), brand.to_string());
            changed = true;
        }
    }
    changed
}

/// Luhn checksum over a digit string (spaces and dashes ignored).
pub fn luhn_valid(number: &str) -> bool {
    let digits: Vec<u32> = number
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| c.to_digit(10))
        .collect::<Option<Vec<_>>>()
        .unwrap_or_default();
    if digits.len() < 12 || digits.len() > 19 {
        return false;
    }
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| {
            if i % 2 == 1 {
                let x = d * 2;
                if x > 9 {
                    x - 9
                } else {
                    x
                }
            } else {
                d
            }
        })
        .sum();
    sum % 10 == 0
}

/// Card network from its number (IIN ranges), only for numbers that pass
/// the Luhn check, so a typo is not confidently labelled.
pub fn detect_card_brand(number: &str) -> Option<&'static str> {
    if !luhn_valid(number) {
        return None;
    }
    let digits: String = number.chars().filter(|c| c.is_ascii_digit()).collect();
    let prefix = |n: usize| digits.get(..n).and_then(|p| p.parse::<u32>().ok());
    let p1 = prefix(1)?;
    let p2 = prefix(2)?;
    let p3 = prefix(3).unwrap_or(0);
    let p4 = prefix(4).unwrap_or(0);
    let p6 = prefix(6).unwrap_or(0);

    if p2 == 34 || p2 == 37 {
        return Some("amex");
    }
    if (2221..=2720).contains(&p4) || (51..=55).contains(&p2) {
        return Some("mastercard");
    }
    if p4 == 6011 || p2 == 65 || (644..=649).contains(&p3) || (622126..=622925).contains(&p6) {
        return Some("discover");
    }
    if p2 == 62 {
        return Some("unionpay");
    }
    if (3528..=3589).contains(&p4) {
        return Some("jcb");
    }
    if p2 == 36 || p2 == 38 || p2 == 39 || (300..=305).contains(&p3) {
        return Some("diners");
    }
    if p2 == 50 || (56..=58).contains(&p2) || p2 == 63 || p2 == 67 {
        return Some("maestro");
    }
    if p1 == 4 {
        return Some("visa");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn login(title: &str, url: &str) -> Record {
        let mut r = Record::new(title);
        r.url = url.into();
        r
    }

    #[test]
    fn kenyan_banks_and_mobile_money_are_banking() {
        let none = BTreeMap::new();
        assert_eq!(suggest_category(&login("KCB", "https://ke.kcbgroup.com/login"), &none).as_deref(), Some("banking"));
        assert_eq!(suggest_category(&login("Equity", "equitybank.co.ke"), &none).as_deref(), Some("banking"));
        assert_eq!(suggest_category(&login("M-Pesa org portal", ""), &none).as_deref(), Some("banking"));
    }

    #[test]
    fn the_most_specific_domain_wins() {
        assert_eq!(category_for_url("https://mail.google.com/mail/u/0"), Some("email"));
        assert_eq!(category_for_url("https://console.aws.amazon.com"), Some("cloud"));
        assert_eq!(category_for_url("https://www.amazon.com/orders"), Some("shopping"));
    }

    #[test]
    fn public_suffixes_categorise_unknown_sites() {
        assert_eq!(category_for_url("https://some-county.go.ke"), Some("government"));
        assert_eq!(category_for_url("https://students.uonbi.ac.ke"), Some("education"));
    }

    #[test]
    fn lookalike_domains_do_not_match() {
        // "notgithub.com" must not count as github.com.
        assert_eq!(category_for_url("https://notgithub.com"), None);
        assert_eq!(category_for_url("https://github.com.evil.example"), None);
    }

    #[test]
    fn kind_beats_url_and_title() {
        let mut card = Record::new_of_kind(RecordKind::Card, "Netflix card");
        card.url = "netflix.com".into();
        assert_eq!(suggest_category(&card, &BTreeMap::new()).as_deref(), Some("banking"));
    }

    #[test]
    fn learned_rules_beat_everything() {
        let mut learned = BTreeMap::new();
        learned.insert("github.com".to_string(), "work".to_string());
        let r = login("GitHub", "https://github.com/login");
        assert_eq!(suggest_category(&r, &learned).as_deref(), Some("work"));
    }

    #[test]
    fn a_user_chosen_category_is_never_overwritten() {
        let mut r = login("GitHub", "https://github.com");
        r.category = Some("personal".into());
        r.category_source = CategorySource::User;
        assert!(!auto_categorize(&mut r, &BTreeMap::new()));
        assert_eq!(r.category.as_deref(), Some("personal"));
    }

    #[test]
    fn title_keywords_are_whole_words() {
        assert_eq!(category_for_title("Office Wi-Fi"), Some("network"));
        // "tillage" contains "till" but is not the word "till".
        assert_eq!(category_for_title("Tillage notes"), None);
    }

    #[test]
    fn card_brands_need_a_valid_luhn() {
        assert_eq!(detect_card_brand("4111 1111 1111 1111"), Some("visa"));
        assert_eq!(detect_card_brand("5555-5555-5555-4444"), Some("mastercard"));
        assert_eq!(detect_card_brand("378282246310005"), Some("amex"));
        assert_eq!(detect_card_brand("6011111111111117"), Some("discover"));
        assert_eq!(detect_card_brand("4111 1111 1111 1112"), None);
    }

    #[test]
    fn auto_categorize_fills_card_brand() {
        let mut card = Record::new_of_kind(RecordKind::Card, "Personal Visa");
        card.fields.insert("number".into(), "4111111111111111".into());
        assert!(auto_categorize(&mut card, &BTreeMap::new()));
        assert_eq!(card.field("brand"), Some("visa"));
        assert_eq!(card.category.as_deref(), Some("banking"));
    }

    #[test]
    fn every_category_slug_used_in_rules_is_declared() {
        for (c, _) in DOMAINS {
            assert!(is_known_category(c), "{c}");
        }
        for (_, c) in SUFFIXES {
            assert!(is_known_category(c), "{c}");
        }
        for (c, _) in KEYWORDS {
            assert!(is_known_category(c), "{c}");
        }
    }
}
