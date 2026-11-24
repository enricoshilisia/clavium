//! Breached-password check with k-anonymity (Have I Been Pwned "range" API).
//!
//! For each password the app sends only the first 5 hex characters of its
//! SHA-1 to `https://api.pwnedpasswords.com/range/{prefix}` and gets back
//! every leaked-password hash suffix starting with them (hundreds of
//! them, padded with fakes). The match happens here, on the device. The
//! service never learns which password, or even which hash, was checked.

use std::collections::BTreeMap;

use serde::Serialize;
use sha1::{Digest, Sha1};
use uuid::Uuid;

use crate::record::Record;

/// Uppercase hex SHA-1, split into the 5-character prefix and the rest.
pub fn split_hash(password: &str) -> (String, String) {
    let hex: String = Sha1::digest(password.as_bytes()).iter().map(|b| format!("{b:02X}")).collect();
    (hex[..5].to_string(), hex[5..].to_string())
}

/// How many times `suffix` appears in a range response (0 = not found).
/// Padding lines have a count of 0 and never match a real suffix anyway.
pub fn count_in_range(body: &str, suffix: &str) -> u64 {
    body.lines()
        .filter_map(|l| l.trim().split_once(':'))
        .find(|(s, _)| s.eq_ignore_ascii_case(suffix))
        .and_then(|(_, n)| n.trim().parse().ok())
        .unwrap_or(0)
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct BreachHit {
    pub id: Uuid,
    pub title: String,
    /// How many times this exact password appears in known breaches.
    pub count: u64,
}

/// The distinct prefixes to fetch for these records.
pub fn prefixes<'a>(records: impl IntoIterator<Item = &'a Record>) -> Vec<String> {
    let mut out: Vec<String> = records
        .into_iter()
        .filter(|r| !r.password.is_empty())
        .map(|r| split_hash(&r.password).0)
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Match records against fetched ranges (prefix -> response body).
/// Records whose prefix was not fetched are skipped, not reported clean.
pub fn find<'a>(records: impl IntoIterator<Item = &'a Record>, ranges: &BTreeMap<String, String>) -> Vec<BreachHit> {
    let mut hits: Vec<BreachHit> = records
        .into_iter()
        .filter(|r| !r.password.is_empty())
        .filter_map(|r| {
            let (prefix, suffix) = split_hash(&r.password);
            let body = ranges.get(&prefix)?;
            let count = count_in_range(body, &suffix);
            (count > 0).then(|| BreachHit { id: r.id, title: r.title.clone(), count })
        })
        .collect();
    hits.sort_by(|a, b| b.count.cmp(&a.count));
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vector_and_matching() {
        // SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        let (p, s) = split_hash("password");
        assert_eq!((p.as_str(), s.as_str()), ("5BAA6", "1E4C9B93F3F0682250B6CF8331B7EE68FD8"));
        let body = "003D68EB55068C33ACE09247EE4C639306B:3\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:10434004\r\nFFFF0000000000000000000000000000000:0".to_string();
        assert_eq!(count_in_range(&body, &s), 10434004);
        assert_eq!(count_in_range(&body, "0000000000000000000000000000000000A"), 0);

        let mut weak = Record::new("Old router");
        weak.password = "password".into();
        let mut strong = Record::new("Bank");
        strong.password = "uY7#kq!2Lp9@vZ4m".into();
        let empty = Record::new("No password");
        let recs = vec![weak.clone(), strong.clone(), empty];
        let pre = prefixes(&recs);
        assert_eq!(pre.len(), 2);
        let mut ranges = BTreeMap::new();
        ranges.insert("5BAA6".to_string(), body.clone());
        let hits = find(&recs, &ranges);
        assert_eq!(hits, vec![BreachHit { id: weak.id, title: "Old router".into(), count: 10434004 }]);
    }
}
