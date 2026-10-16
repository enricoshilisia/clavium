//! Generating a password. Lives in the security core deliberately, not the
//! UI layer — the randomness behind a generated password is exactly as
//! security-critical as the randomness behind a nonce, and both should
//! come from the same audited source (`rand`'s OS-backed CSPRNG), not be
//! reimplemented in JavaScript where "random" too easily means
//! `Math.random()`.

use rand::Rng;

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
// Excludes characters that commonly break naive form parsers or are
// visually ambiguous in a monospace font — a generated password a person
// can never successfully paste into the one form that strips `<` is a
// password that gets typed by hand instead, badly.
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.?";

#[derive(Debug, Clone)]
pub struct GeneratorOptions {
    pub length: usize,
    pub include_upper: bool,
    pub include_lower: bool,
    pub include_digits: bool,
    pub include_symbols: bool,
}

impl Default for GeneratorOptions {
    fn default() -> Self {
        Self {
            length: 20,
            include_upper: true,
            include_lower: true,
            include_digits: true,
            include_symbols: true,
        }
    }
}

/// Generate one password from a cryptographically secure source. Panics
/// are avoided entirely rather than guarded against after the fact: an
/// options set with every character class disabled returns an error, not
/// a password generated from an empty alphabet.
pub fn generate(options: &GeneratorOptions) -> Result<String, &'static str> {
    let mut alphabet = Vec::new();
    if options.include_lower {
        alphabet.extend_from_slice(LOWER);
    }
    if options.include_upper {
        alphabet.extend_from_slice(UPPER);
    }
    if options.include_digits {
        alphabet.extend_from_slice(DIGITS);
    }
    if options.include_symbols {
        alphabet.extend_from_slice(SYMBOLS);
    }
    if alphabet.is_empty() {
        return Err("at least one character class must be enabled");
    }
    if options.length == 0 {
        return Err("length must be at least 1");
    }

    let mut rng = rand::thread_rng();
    let password: String = (0..options.length)
        .map(|_| alphabet[rng.gen_range(0..alphabet.len())] as char)
        .collect();
    Ok(password)
}

/// A short, curated English word list for passphrase generation — the
/// Diceware-style approach, genuinely large enough (at minimum a few
/// thousand words) to carry real entropy per word. This is a deliberately
/// small placeholder list for Milestone 0's own tests; the real list
/// (EFF's published Diceware wordlist, 7,776 words, is the standard
/// choice) is a data file swapped in before this ships, not an algorithm
/// change.
const PLACEHOLDER_WORDLIST: &[&str] = &[
    "anchor", "basil", "cedar", "delta", "ember", "forest", "glacier", "harbor", "indigo",
    "jungle", "kernel", "lumen", "meadow", "nectar", "onyx", "pepper", "quartz", "river", "summit",
    "timber", "umber", "valley", "willow", "yonder",
];

/// Generate a passphrase of `word_count` words, separated by `separator`.
pub fn generate_passphrase(word_count: usize, separator: &str) -> Result<String, &'static str> {
    if word_count == 0 {
        return Err("word_count must be at least 1");
    }
    let mut rng = rand::thread_rng();
    let words: Vec<&str> = (0..word_count)
        .map(|_| PLACEHOLDER_WORDLIST[rng.gen_range(0..PLACEHOLDER_WORDLIST.len())])
        .collect();
    Ok(words.join(separator))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_generated_password_has_the_requested_length() {
        let options = GeneratorOptions {
            length: 32,
            ..Default::default()
        };
        let password = generate(&options).unwrap();
        assert_eq!(password.chars().count(), 32);
    }

    #[test]
    fn two_generated_passwords_are_never_the_same() {
        let options = GeneratorOptions::default();
        let a = generate(&options).unwrap();
        let b = generate(&options).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn disabling_every_character_class_is_refused_not_guessed_at() {
        let options = GeneratorOptions {
            include_upper: false,
            include_lower: false,
            include_digits: false,
            include_symbols: false,
            ..Default::default()
        };
        assert!(generate(&options).is_err());
    }

    #[test]
    fn a_digits_only_password_contains_only_digits() {
        let options = GeneratorOptions {
            length: 50,
            include_upper: false,
            include_lower: false,
            include_digits: true,
            include_symbols: false,
        };
        let password = generate(&options).unwrap();
        assert!(password.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn a_passphrase_has_the_requested_word_count() {
        let phrase = generate_passphrase(6, "-").unwrap();
        assert_eq!(phrase.split('-').count(), 6);
    }

    #[test]
    fn zero_length_is_refused() {
        let options = GeneratorOptions {
            length: 0,
            ..Default::default()
        };
        assert!(generate(&options).is_err());
    }
}
