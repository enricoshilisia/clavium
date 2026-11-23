//! Password health, computed on the device over decrypted records. Only
//! the aggregate numbers are ever meant to leave the device (for an
//! organisation's security dashboard); the per-record lists are for the
//! person's own "fix these" screen.

use std::collections::HashMap;

use chrono::{Duration, Utc};
use serde::Serialize;
use uuid::Uuid;

use crate::record::{Record, RecordKind};

/// Passwords seen at the top of every breach corpus. A tiny list on
/// purpose: it catches the worst cases offline; a full breach check goes
/// through HIBP's k-anonymity API from the client.
const COMMON: &[&str] = &[
    "123456", "123456789", "12345678", "password", "qwerty", "12345", "1234567890",
    "111111", "1234567", "qwerty123", "000000", "abc123", "password1", "iloveyou",
    "admin", "welcome", "letmein", "monkey", "dragon", "sunshine", "princess",
    "football", "123123", "654321", "superman", "qwertyuiop", "passw0rd", "password123",
];

/// Rough entropy estimate in bits: length times log2 of the character
/// classes used, heavily penalised for common passwords and repeats.
pub fn estimate_bits(password: &str) -> f64 {
    if password.is_empty() {
        return 0.0;
    }
    let lower = password.to_lowercase();
    if COMMON.contains(&lower.as_str()) {
        return 5.0;
    }
    let mut pool = 0u32;
    if password.chars().any(|c| c.is_ascii_lowercase()) {
        pool += 26;
    }
    if password.chars().any(|c| c.is_ascii_uppercase()) {
        pool += 26;
    }
    if password.chars().any(|c| c.is_ascii_digit()) {
        pool += 10;
    }
    if password.chars().any(|c| !c.is_ascii_alphanumeric()) {
        pool += 33;
    }
    let distinct = {
        let mut cs: Vec<char> = password.chars().collect();
        cs.sort();
        cs.dedup();
        cs.len()
    };
    // Repeated characters ("aaaaaaaaaa") count for little.
    let effective_len = (password.chars().count() as f64).min(distinct as f64 * 2.0);
    effective_len * (pool.max(1) as f64).log2()
}

pub const WEAK_BITS: f64 = 50.0;
pub const OLD_DAYS: i64 = 365;

#[derive(Debug, Serialize, Default, PartialEq)]
pub struct HealthReport {
    /// Records with a password at all.
    pub with_password: usize,
    pub weak: Vec<Uuid>,
    /// Groups of record ids sharing one password (each group has 2+).
    pub reused: Vec<Vec<Uuid>>,
    pub old: Vec<Uuid>,
    /// Logins with no authenticator code stored.
    pub without_totp: Vec<Uuid>,
    /// 0-100, higher is better.
    pub score: u32,
}

pub fn analyze<'a>(records: impl IntoIterator<Item = &'a Record>) -> HealthReport {
    let mut report = HealthReport::default();
    let mut by_password: HashMap<&str, Vec<Uuid>> = HashMap::new();
    let cutoff = Utc::now() - Duration::days(OLD_DAYS);
    let mut logins = 0usize;

    for r in records.into_iter().filter(|r| !r.is_deleted()) {
        if r.kind == RecordKind::Login {
            logins += 1;
            if r.totp_secret.as_deref().map_or(true, str::is_empty) {
                report.without_totp.push(r.id);
            }
        }
        if r.password.is_empty() {
            continue;
        }
        report.with_password += 1;
        if estimate_bits(&r.password) < WEAK_BITS {
            report.weak.push(r.id);
        }
        if r.updated_at < cutoff {
            report.old.push(r.id);
        }
        by_password.entry(r.password.as_str()).or_default().push(r.id);
    }
    report.reused = by_password.into_values().filter(|ids| ids.len() > 1).collect();
    report.reused.sort();

    if report.with_password == 0 {
        report.score = 100;
        return report;
    }
    let n = report.with_password as f64;
    let reused_count: usize = report.reused.iter().map(Vec::len).sum();
    let penalty = 50.0 * report.weak.len() as f64 / n
        + 30.0 * reused_count as f64 / n
        + 10.0 * report.old.len() as f64 / n
        + if logins > 0 { 10.0 * report.without_totp.len() as f64 / logins as f64 } else { 0.0 };
    report.score = (100.0 - penalty).clamp(0.0, 100.0).round() as u32;
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(pw: &str) -> Record {
        let mut r = Record::new("x");
        r.password = pw.into();
        r
    }

    #[test]
    fn common_and_short_passwords_are_weak() {
        assert!(estimate_bits("password") < WEAK_BITS);
        assert!(estimate_bits("aaaaaaaaaaaaaaaaaaaa") < WEAK_BITS);
        assert!(estimate_bits("Xk9#mQ2$vL7!pR4&") > WEAK_BITS);
    }

    #[test]
    fn reuse_weakness_and_score() {
        let a = rec("Xk9#mQ2$vL7!pR4&");
        let b = rec("Xk9#mQ2$vL7!pR4&");
        let c = rec("123456");
        let report = analyze([&a, &b, &c]);
        assert_eq!(report.weak, vec![c.id]);
        assert_eq!(report.reused.len(), 1);
        assert_eq!(report.reused[0].len(), 2);
        assert!(report.score < 100);
        assert_eq!(analyze(std::iter::empty()).score, 100);
    }
}
