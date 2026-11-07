//! CSPRNG password generator (spec §7.2.4).
//!
//! Characters are drawn uniformly from the OS CSPRNG. When several classes are
//! enabled, every class is guaranteed to appear: candidates that miss a class
//! are rejected and redrawn, which keeps the result uniform over all valid
//! passwords (no "fix-up" bias).

use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Shortest generated password.
pub const MIN_LENGTH: usize = 8;
/// Longest generated password.
pub const MAX_LENGTH: usize = 128;

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.<>/?~";
/// Characters easily confused when read or typed by hand.
const AMBIGUOUS: &str = "Il1O0o|";

/// Options chosen in the generator UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneratorOptions {
    /// Length in characters (8..=128).
    pub length: usize,
    /// Include a-z.
    pub lower: bool,
    /// Include A-Z.
    pub upper: bool,
    /// Include 0-9.
    pub digits: bool,
    /// Include symbols.
    pub symbols: bool,
    /// Drop look-alike characters.
    pub exclude_ambiguous: bool,
}

impl Default for GeneratorOptions {
    fn default() -> Self {
        Self {
            length: 24,
            lower: true,
            upper: true,
            digits: true,
            symbols: true,
            exclude_ambiguous: false,
        }
    }
}

/// Why generation was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GeneratorError {
    /// Length outside 8..=128.
    #[error("length must be between {MIN_LENGTH} and {MAX_LENGTH}")]
    Length,
    /// No character class selected.
    #[error("select at least one character set")]
    NoClasses,
}

/// A generated password plus its exact entropy.
#[derive(Debug)]
pub struct Generated {
    /// The password, wiped on drop.
    pub password: Zeroizing<String>,
    /// `length × log2(alphabet)` bits.
    pub entropy_bits: f64,
}

/// Generates a password.
pub fn generate(opts: &GeneratorOptions) -> Result<Generated, GeneratorError> {
    if !(MIN_LENGTH..=MAX_LENGTH).contains(&opts.length) {
        return Err(GeneratorError::Length);
    }
    let keep = |set: &str| -> Vec<char> {
        set.chars()
            .filter(|c| !(opts.exclude_ambiguous && AMBIGUOUS.contains(*c)))
            .collect()
    };
    let classes: Vec<Vec<char>> = [
        (opts.lower, LOWER),
        (opts.upper, UPPER),
        (opts.digits, DIGITS),
        (opts.symbols, SYMBOLS),
    ]
    .into_iter()
    .filter(|(on, _)| *on)
    .map(|(_, set)| keep(set))
    .collect();
    if classes.is_empty() {
        return Err(GeneratorError::NoClasses);
    }
    let alphabet: Vec<char> = classes.concat();
    let mut rng = OsRng;
    let password = loop {
        let mut candidate = Zeroizing::new(String::with_capacity(opts.length));
        for _ in 0..opts.length {
            // `choose` uses an unbiased uniform range sample.
            candidate.push(*alphabet.choose(&mut rng).expect("alphabet is non-empty"));
        }
        // With length ≥ 8 and ≤ 4 classes, rejection is rare (≈ few %).
        if classes
            .iter()
            .all(|set| candidate.chars().any(|c| set.contains(&c)))
        {
            break candidate;
        }
    };
    Ok(Generated {
        password,
        entropy_bits: opts.length as f64 * (alphabet.len() as f64).log2(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn respects_length_and_classes() {
        for length in [MIN_LENGTH, 24, MAX_LENGTH] {
            let g = generate(&GeneratorOptions {
                length,
                ..Default::default()
            })
            .unwrap();
            let p = g.password.as_str();
            assert_eq!(p.chars().count(), length);
            assert!(p.chars().any(|c| c.is_ascii_lowercase()));
            assert!(p.chars().any(|c| c.is_ascii_uppercase()));
            assert!(p.chars().any(|c| c.is_ascii_digit()));
            assert!(p.chars().any(|c| SYMBOLS.contains(c)));
        }
    }

    #[test]
    fn single_class_and_ambiguous_exclusion() {
        let opts = GeneratorOptions {
            length: 64,
            lower: false,
            upper: false,
            digits: true,
            symbols: false,
            exclude_ambiguous: true,
        };
        let g = generate(&opts).unwrap();
        assert!(g
            .password
            .chars()
            .all(|c| c.is_ascii_digit() && c != '0' && c != '1'));
        assert!((g.entropy_bits - 64.0 * 8f64.log2()).abs() < 1e-9);
    }

    #[test]
    fn rejects_bad_options() {
        let none = GeneratorOptions {
            lower: false,
            upper: false,
            digits: false,
            symbols: false,
            ..Default::default()
        };
        assert_eq!(generate(&none).unwrap_err(), GeneratorError::NoClasses);
        assert_eq!(
            generate(&GeneratorOptions {
                length: 7,
                ..Default::default()
            })
            .unwrap_err(),
            GeneratorError::Length
        );
        assert_eq!(
            generate(&GeneratorOptions {
                length: 129,
                ..Default::default()
            })
            .unwrap_err(),
            GeneratorError::Length
        );
    }

    #[test]
    fn outputs_differ_and_cover_alphabet() {
        let opts = GeneratorOptions {
            length: 128,
            upper: false,
            digits: false,
            symbols: false,
            ..Default::default()
        };
        let a = generate(&opts).unwrap();
        let b = generate(&opts).unwrap();
        assert_ne!(*a.password, *b.password);
        // 2,048 lowercase draws: every letter should appear (miss chance ≈ 1e-33).
        let mut seen = std::collections::HashSet::new();
        for _ in 0..16 {
            seen.extend(generate(&opts).unwrap().password.chars());
        }
        assert_eq!(seen.len(), 26);
    }
}
