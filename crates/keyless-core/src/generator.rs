//! Password generator. All randomness comes from the OS CSPRNG and every
//! choice is made with unbiased rejection sampling.

use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{Error, Result, crypto::random_bytes};

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.<>/?~";
const AMBIGUOUS: &str = "Il1O0o|`'\"";
/// Syllables: a consonant and a vowel, sometimes closed by a consonant.
const CONSONANTS: &str = "bcdfghjklmnprstvz";
const VOWELS: &str = "aeiou";
/// Symbols between words, which any website takes.
const SEPARATOR_SYMBOLS: &str = "!#$%&*+-.=?@_";

const WORDLIST: &str = include_str!("../data/eff_large_wordlist.txt");

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GeneratorOptions {
    Random {
        length: usize,
        #[serde(default = "yes")]
        uppercase: bool,
        #[serde(default = "yes")]
        lowercase: bool,
        #[serde(default = "yes")]
        digits: bool,
        #[serde(default = "yes")]
        symbols: bool,
        #[serde(default)]
        avoid_ambiguous: bool,
    },
    Memorable {
        words: usize,
        #[serde(default = "default_separator")]
        separator: String,
        #[serde(default)]
        capitalize: bool,
        #[serde(default)]
        include_number: bool,
        /// What each word is.
        #[serde(default)]
        style: MemorableStyle,
        /// What goes between them: `separator`, or something random.
        #[serde(default)]
        separators: SeparatorStyle,
    },
    Pin {
        length: usize,
    },
}

/// The parts of a memorable password.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemorableStyle {
    /// Words from the EFF's long list.
    #[default]
    Words,
    /// Made-up words of three syllables ("tavomi"), easy to say.
    Syllables,
    /// Three random letters each.
    ThreeLetters,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeparatorStyle {
    /// The chosen separator, the same each time.
    #[default]
    Fixed,
    /// A random digit each time.
    Digits,
    /// A random digit or symbol each time.
    DigitsSymbols,
}

fn yes() -> bool {
    true
}

fn pick(set: &str) -> Result<char> {
    let chars: Vec<char> = set.chars().collect();
    Ok(chars[uniform(chars.len())?])
}

/// One part of a memorable password, and its entropy in bits.
fn memorable_word(style: MemorableStyle) -> Result<(String, f64)> {
    match style {
        MemorableStyle::Words => {
            let list = wordlist();
            Ok((list[uniform(list.len())?].to_string(), (list.len() as f64).log2()))
        }
        MemorableStyle::Syllables => {
            let (c, v) = (CONSONANTS.len() as f64, VOWELS.len() as f64);
            let mut word = String::new();
            for _ in 0..3 {
                word.push(pick(CONSONANTS)?);
                word.push(pick(VOWELS)?);
            }
            Ok((word, 3.0 * (c * v).log2()))
        }
        MemorableStyle::ThreeLetters => {
            let mut word = String::new();
            for _ in 0..3 {
                word.push(pick(LOWER)?);
            }
            Ok((word, 3.0 * 26f64.log2()))
        }
    }
}

fn default_separator() -> String {
    "-".into()
}

impl Default for GeneratorOptions {
    fn default() -> Self {
        GeneratorOptions::Random {
            length: 24,
            uppercase: true,
            lowercase: true,
            digits: true,
            symbols: true,
            avoid_ambiguous: false,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct GeneratedPassword {
    pub password: Zeroizing<String>,
    /// Estimated entropy in bits, assuming the attacker knows the options.
    pub entropy_bits: f64,
}

pub fn generate(options: &GeneratorOptions) -> Result<GeneratedPassword> {
    match options {
        GeneratorOptions::Random { length, uppercase, lowercase, digits, symbols, avoid_ambiguous } => {
            if !(4..=128).contains(length) {
                return Err(Error::InvalidGeneratorOptions("length must be between 4 and 128".into()));
            }
            let classes: Vec<Vec<char>> = [
                (*lowercase, LOWER),
                (*uppercase, UPPER),
                (*digits, DIGITS),
                (*symbols, SYMBOLS),
            ]
            .iter()
            .filter(|(enabled, _)| *enabled)
            .map(|(_, set)| {
                set.chars()
                    .filter(|c| !(*avoid_ambiguous && AMBIGUOUS.contains(*c)))
                    .collect()
            })
            .collect();
            if classes.is_empty() {
                return Err(Error::InvalidGeneratorOptions("choose at least one character type".into()));
            }
            if classes.len() > *length {
                return Err(Error::InvalidGeneratorOptions("too short for the selected character types".into()));
            }
            let alphabet: Vec<char> = classes.iter().flatten().copied().collect();

            // Rejection sampling: draw uniformly from the full alphabet and
            // retry until every selected class is present. This keeps the
            // result uniform over all valid passwords.
            loop {
                let mut password = Zeroizing::new(String::with_capacity(*length));
                for _ in 0..*length {
                    password.push(alphabet[uniform(alphabet.len())?]);
                }
                if classes.iter().all(|class| password.chars().any(|c| class.contains(&c))) {
                    let entropy_bits = *length as f64 * (alphabet.len() as f64).log2();
                    return Ok(GeneratedPassword { password, entropy_bits });
                }
            }
        }
        GeneratorOptions::Memorable { words, separator, capitalize, include_number, style, separators } => {
            if !(3..=20).contains(words) {
                return Err(Error::InvalidGeneratorOptions("use between 3 and 20 words".into()));
            }
            if separator.chars().count() > 3 {
                return Err(Error::InvalidGeneratorOptions("the separator is too long".into()));
            }
            let number_position = if *include_number { Some(uniform(*words)?) } else { None };
            let mut password = Zeroizing::new(String::new());
            let mut entropy_bits = 0.0;
            for i in 0..*words {
                if i > 0 {
                    match separators {
                        SeparatorStyle::Fixed => password.push_str(separator),
                        SeparatorStyle::Digits => {
                            password.push(pick(DIGITS)?);
                            entropy_bits += 10f64.log2();
                        }
                        SeparatorStyle::DigitsSymbols => {
                            let set = [DIGITS, SEPARATOR_SYMBOLS].concat();
                            password.push(pick(&set)?);
                            entropy_bits += (set.len() as f64).log2();
                        }
                    }
                }
                let (word, bits) = memorable_word(*style)?;
                entropy_bits += bits;
                if *capitalize {
                    let mut chars = word.chars();
                    if let Some(first) = chars.next() {
                        password.extend(first.to_uppercase());
                        password.push_str(chars.as_str());
                    }
                } else {
                    password.push_str(&word);
                }
                if number_position == Some(i) {
                    password.push(char::from(b'0' + uniform(10)? as u8));
                }
            }
            if *include_number {
                entropy_bits += (10.0 * *words as f64).log2();
            }
            Ok(GeneratedPassword { password, entropy_bits })
        }
        GeneratorOptions::Pin { length } => {
            if !(4..=16).contains(length) {
                return Err(Error::InvalidGeneratorOptions("PIN length must be between 4 and 16".into()));
            }
            let mut password = Zeroizing::new(String::with_capacity(*length));
            for _ in 0..*length {
                password.push(char::from(b'0' + uniform(10)? as u8));
            }
            Ok(GeneratedPassword { password, entropy_bits: *length as f64 * 10f64.log2() })
        }
    }
}

/// Uniform integer in `0..n` using rejection sampling on 32-bit draws.
pub fn uniform(n: usize) -> Result<usize> {
    assert!(n > 0 && n <= u32::MAX as usize);
    let n = n as u32;
    let zone = u32::MAX - (u32::MAX % n);
    loop {
        let mut buf = [0u8; 4];
        random_bytes(&mut buf)?;
        let value = u32::from_le_bytes(buf);
        if value < zone {
            return Ok((value % n) as usize);
        }
    }
}

fn wordlist() -> &'static [&'static str] {
    static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();
    WORDS.get_or_init(|| {
        WORDLIST
            .lines()
            .filter_map(|line| line.split('\t').nth(1))
            .map(str::trim)
            .filter(|w| !w.is_empty())
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wordlist_is_complete() {
        assert_eq!(wordlist().len(), 7776);
    }

    #[test]
    fn random_respects_options() {
        for _ in 0..200 {
            let opts = GeneratorOptions::Random {
                length: 12,
                uppercase: true,
                lowercase: true,
                digits: true,
                symbols: false,
                avoid_ambiguous: true,
            };
            let generated = generate(&opts).unwrap();
            let pw = generated.password.as_str();
            assert_eq!(pw.chars().count(), 12);
            assert!(pw.chars().any(|c| c.is_ascii_uppercase()));
            assert!(pw.chars().any(|c| c.is_ascii_lowercase()));
            assert!(pw.chars().any(|c| c.is_ascii_digit()));
            assert!(pw.chars().all(|c| c.is_ascii_alphanumeric()));
            assert!(!pw.chars().any(|c| AMBIGUOUS.contains(c)));
        }
    }

    #[test]
    fn memorable_and_pin() {
        let generated = generate(&GeneratorOptions::Memorable {
            words: 4,
            separator: ".".into(),
            capitalize: true,
            include_number: true,
            style: MemorableStyle::Words,
            separators: SeparatorStyle::Fixed,
        })
        .unwrap();
        let parts: Vec<&str> = generated.password.split('.').collect();
        assert_eq!(parts.len(), 4);
        assert!(parts.iter().all(|p| p.chars().next().unwrap().is_uppercase()));
        assert_eq!(generated.password.chars().filter(|c| c.is_ascii_digit()).count(), 1);
        assert!(generated.entropy_bits > 51.0);

        let pin = generate(&GeneratorOptions::Pin { length: 6 }).unwrap();
        assert_eq!(pin.password.len(), 6);
        assert!(pin.password.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn memorable_styles_and_separators() {
        let options = |style, separators| GeneratorOptions::Memorable {
            words: 4,
            separator: "-".into(),
            capitalize: false,
            include_number: false,
            style,
            separators,
        };
        for _ in 0..50 {
            let syllables = generate(&options(MemorableStyle::Syllables, SeparatorStyle::Fixed)).unwrap();
            let parts: Vec<&str> = syllables.password.split('-').collect();
            assert_eq!(parts.len(), 4);
            assert!(parts.iter().all(|p| p.len() == 6 && p.chars().enumerate().all(|(i, c)| (i % 2 == 1) == VOWELS.contains(c))));

            let letters = generate(&options(MemorableStyle::ThreeLetters, SeparatorStyle::Digits)).unwrap();
            let chars: Vec<char> = letters.password.chars().collect();
            assert_eq!(chars.len(), 4 * 3 + 3);
            for (i, c) in chars.iter().enumerate() {
                assert_eq!(i % 4 == 3, c.is_ascii_digit(), "{}", letters.password.as_str());
            }

            let mixed = generate(&options(MemorableStyle::Words, SeparatorStyle::DigitsSymbols)).unwrap();
            assert_eq!(mixed.password.chars().filter(|c| !c.is_ascii_lowercase()).count(), 3);
        }
        // Random separators add to the strength; fixed ones do not.
        let fixed = generate(&options(MemorableStyle::Words, SeparatorStyle::Fixed)).unwrap().entropy_bits;
        let digits = generate(&options(MemorableStyle::Words, SeparatorStyle::Digits)).unwrap().entropy_bits;
        assert!((digits - fixed - 3.0 * 10f64.log2()).abs() < 1e-9);
    }

    #[test]
    fn invalid_options() {
        assert!(generate(&GeneratorOptions::Random {
            length: 3,
            uppercase: true,
            lowercase: true,
            digits: true,
            symbols: true,
            avoid_ambiguous: false
        })
        .is_err());
        assert!(generate(&GeneratorOptions::Random {
            length: 20,
            uppercase: false,
            lowercase: false,
            digits: false,
            symbols: false,
            avoid_ambiguous: false
        })
        .is_err());
        assert!(generate(&GeneratorOptions::Pin { length: 2 }).is_err());
    }

    #[test]
    fn uniform_is_roughly_uniform() {
        let mut counts = [0usize; 6];
        for _ in 0..60_000 {
            counts[uniform(6).unwrap()] += 1;
        }
        assert!(counts.iter().all(|&c| (9_000..11_000).contains(&c)), "{counts:?}");
    }
}
