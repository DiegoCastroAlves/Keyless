//! What a website accepts in a password (lengths, character classes, how
//! many times a character may repeat), in the "password rules" language of
//! Apple's password-manager-resources and the HTML `passwordrules`
//! attribute, and passwords made to follow them.
//!
//! The rules for 400-odd websites come from that project
//! (`data/password-rules.json`, MIT license, see
//! `data/password-rules.LICENSE.md`); a page can also state its own.
//!
//! The language: `name: value;` pairs. `minlength` and `maxlength` take a
//! number, `max-consecutive` the most times one character may repeat in a
//! row; `required` (each needs at least one of its characters) and `allowed`
//! take classes: `upper`, `lower`, `digit`, `special`, `ascii-printable`,
//! `unicode`, or characters in brackets (`[-().&@?]`).

use std::{collections::HashMap, sync::OnceLock};

use serde::Deserialize;
use zeroize::Zeroizing;

use crate::{
    Error, Result,
    generator::{GeneratedPassword, uniform},
};

const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const DIGITS: &str = "0123456789";
/// The language's "special" class, without the space (a password ending in
/// one is easy to lose).
const SPECIAL: &str = "-~!@#$%^&*_+=`|(){}[:;\"'<>,.?]";
/// Characters easily mistaken for others, left out when there is a choice.
const AMBIGUOUS: &str = "Il1O0o|`'\"";

/// The most a password may be made of, whatever the rules allow.
const MAX_LENGTH: usize = 128;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PasswordRules {
    pub min_length: Option<usize>,
    pub max_length: Option<usize>,
    /// Each set needs at least one of its characters.
    pub required: Vec<Vec<char>>,
    /// Characters allowed besides the required ones.
    pub allowed: Vec<char>,
    /// The most times one character may come in a row.
    pub max_consecutive: Option<usize>,
}

/// The characters of a class, or of a bracketed set.
fn class(name: &str) -> Option<Vec<char>> {
    let name = name.trim();
    if let Some(inner) = name.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        let chars: Vec<char> = inner.chars().filter(|c| c.is_ascii_graphic()).collect();
        return (!chars.is_empty()).then_some(chars);
    }
    let set: String = match name.to_ascii_lowercase().as_str() {
        "upper" => UPPER.into(),
        "lower" => LOWER.into(),
        "digit" => DIGITS.into(),
        "special" => SPECIAL.into(),
        // Keyless makes ASCII passwords: "unicode" allows them too.
        "ascii-printable" | "unicode" => (b'!'..=b'~').map(char::from).collect(),
        _ => return None,
    };
    Some(set.chars().collect())
}

/// The classes of a rule's value, split at commas outside brackets.
fn classes(value: &str) -> Vec<char> {
    let mut out: Vec<char> = Vec::new();
    let mut part = String::new();
    let mut in_brackets = false;
    let mut add = |part: &str| {
        if let Some(chars) = class(part) {
            for c in chars {
                if !out.contains(&c) {
                    out.push(c);
                }
            }
        }
    };
    for c in value.chars() {
        match c {
            '[' if !in_brackets => {
                in_brackets = true;
                part.push(c);
            }
            // A "]" first in the brackets is one of the characters.
            ']' if in_brackets && !part.ends_with('[') => {
                in_brackets = false;
                part.push(c);
            }
            ',' if !in_brackets => {
                add(&part);
                part.clear();
            }
            _ => part.push(c),
        }
    }
    add(&part);
    out
}

/// Reads rules ("minlength: 8; required: upper; ..."); unknown parts are
/// left out. None when nothing in them is understood.
pub fn parse(text: &str) -> Option<PasswordRules> {
    if text.len() > 2048 {
        return None;
    }
    let mut rules = PasswordRules::default();
    let mut understood = false;
    // Split at semicolons outside brackets.
    let mut pairs = Vec::new();
    let mut current = String::new();
    let mut in_brackets = false;
    for c in text.chars() {
        match c {
            '[' if !in_brackets => {
                in_brackets = true;
                current.push(c);
            }
            ']' if in_brackets && !current.ends_with('[') => {
                in_brackets = false;
                current.push(c);
            }
            ';' if !in_brackets => pairs.push(std::mem::take(&mut current)),
            _ => current.push(c),
        }
    }
    pairs.push(current);
    for pair in pairs {
        let Some((name, value)) = pair.split_once(':') else { continue };
        let number = || value.trim().parse::<usize>().ok().filter(|n| *n > 0 && *n <= MAX_LENGTH);
        match name.trim().to_ascii_lowercase().as_str() {
            "minlength" | "maxlength" | "max-consecutive" => {
                let Some(n) = number() else { continue };
                match name.trim().to_ascii_lowercase().as_str() {
                    "minlength" => rules.min_length = Some(n),
                    "maxlength" => rules.max_length = Some(n),
                    _ => rules.max_consecutive = Some(n),
                }
            }
            "required" => {
                let chars = classes(value);
                if chars.is_empty() {
                    continue;
                }
                rules.required.push(chars);
            }
            "allowed" => {
                for c in classes(value) {
                    if !rules.allowed.contains(&c) {
                        rules.allowed.push(c);
                    }
                }
            }
            _ => continue,
        }
        understood = true;
    }
    understood.then_some(rules)
}

#[derive(Deserialize)]
struct Entry {
    #[serde(rename = "password-rules")]
    password_rules: String,
}

fn known() -> &'static HashMap<String, String> {
    static KNOWN: OnceLock<HashMap<String, String>> = OnceLock::new();
    KNOWN.get_or_init(|| {
        let list: HashMap<String, Entry> = serde_json::from_str(include_str!("../data/password-rules.json")).unwrap_or_default();
        list.into_iter().map(|(domain, entry)| (domain, entry.password_rules)).collect()
    })
}

/// The known rules for a website: its host, or the closest parent domain
/// listed.
pub fn rules_for(host: &str) -> Option<PasswordRules> {
    let host = host.trim().trim_start_matches("www.").to_ascii_lowercase();
    let mut candidate = host.as_str();
    loop {
        if let Some(text) = known().get(candidate) {
            return parse(text);
        }
        let (_, parent) = candidate.split_once('.')?;
        if !parent.contains('.') {
            return None;
        }
        candidate = parent;
    }
}

/// `set` without the characters `unwanted` picks, unless none would be left.
fn without(set: Vec<char>, unwanted: impl Fn(char) -> bool) -> Vec<char> {
    let kept: Vec<char> = set.iter().copied().filter(|c| !unwanted(*c)).collect();
    if kept.is_empty() { set } else { kept }
}

/// A password of `length` characters (or as close as the rules allow) that
/// follows `rules`. Without `symbols`, special characters are left out where
/// the rules do not require them; ambiguous ones are left out where there is
/// another choice.
pub fn generate(rules: &PasswordRules, length: usize, symbols: bool) -> Result<GeneratedPassword> {
    // Each set without what is not wanted, where it has something else.
    let trim = |set: &[char]| {
        let set = without(set.to_vec(), |c| AMBIGUOUS.contains(c));
        if symbols { set } else { without(set, |c| !c.is_ascii_alphanumeric()) }
    };
    let required: Vec<Vec<char>> = rules.required.iter().map(|set| trim(set)).collect();
    let mut alphabet: Vec<char> = Vec::new();
    for c in required.iter().flatten().chain(trim(&rules.allowed).iter()) {
        if !alphabet.contains(c) {
            alphabet.push(*c);
        }
    }
    if alphabet.is_empty() {
        // No classes named: letters, digits and (if wanted) symbols.
        let default: Vec<char> = format!("{UPPER}{LOWER}{DIGITS}{}", if symbols { "!@#$%^&*()-_=+?" } else { "" }).chars().collect();
        alphabet = trim(&default);
    }

    let min = rules.min_length.unwrap_or(1).max(required.len()).min(MAX_LENGTH);
    let max = rules.max_length.unwrap_or(MAX_LENGTH).clamp(min, MAX_LENGTH);
    let length = length.clamp(min, max);
    if length == 0 || required.len() > length {
        return Err(Error::InvalidGeneratorOptions("the website's rules cannot be met".into()));
    }

    // Rejection sampling, like the generator: uniform over the passwords
    // that follow the rules.
    for _ in 0..10_000 {
        let mut password = Zeroizing::new(String::with_capacity(length));
        for _ in 0..length {
            password.push(alphabet[uniform(alphabet.len())?]);
        }
        let complete = required.iter().all(|set| password.chars().any(|c| set.contains(&c)));
        let repeats = rules.max_consecutive.is_some_and(|most| {
            let chars: Vec<char> = password.chars().collect();
            chars.windows(most + 1).any(|run| run.iter().all(|c| *c == run[0]))
        });
        if complete && !repeats {
            let entropy_bits = length as f64 * (alphabet.len() as f64).log2();
            return Ok(GeneratedPassword { password, entropy_bits });
        }
    }
    Err(Error::InvalidGeneratorOptions("the website's rules cannot be met".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_rules() {
        let rules = parse("minlength: 8; maxlength: 16; max-consecutive: 2; required: lower, upper; required: digit; allowed: [-().&@?'#,/\"+];").unwrap();
        assert_eq!(rules.min_length, Some(8));
        assert_eq!(rules.max_length, Some(16));
        assert_eq!(rules.max_consecutive, Some(2));
        assert_eq!(rules.required.len(), 2);
        assert_eq!(rules.required[0].len(), 52);
        assert!(rules.allowed.contains(&'(') && rules.allowed.contains(&'"') && rules.allowed.contains(&'#'));
        // Semicolons and colons inside brackets belong to the set.
        let rules = parse("required: [;:]; maxlength: 10;").unwrap();
        assert_eq!(rules.required[0], vec![';', ':']);
        assert_eq!(rules.max_length, Some(10));
        assert_eq!(parse("nonsense"), None);
        assert_eq!(parse("maxlength: 0;"), None);
    }

    #[test]
    fn follows_rules() {
        let rules = parse("minlength: 8; maxlength: 12; max-consecutive: 2; required: upper; required: lower; required: digit; required: [!#];").unwrap();
        for _ in 0..200 {
            let password = generate(&rules, 20, true).unwrap().password;
            assert!((8..=12).contains(&password.len()), "{}", password.as_str());
            assert!(password.chars().any(|c| c.is_ascii_uppercase()));
            assert!(password.chars().any(|c| c.is_ascii_lowercase()));
            assert!(password.chars().any(|c| c.is_ascii_digit()));
            assert!(password.chars().any(|c| "!#".contains(c)));
            assert!(password.chars().all(|c| c.is_ascii_alphanumeric() || "!#".contains(c)));
            let chars: Vec<char> = password.chars().collect();
            assert!(!chars.windows(3).any(|w| w[0] == w[1] && w[1] == w[2]));
        }
        // Digits only (a PIN-like rule).
        let pin = generate(&parse("minlength: 6; maxlength: 6; allowed: digit;").unwrap(), 20, true).unwrap().password;
        assert!(pin.len() == 6 && pin.chars().all(|c| c.is_ascii_digit()));
        // No symbols when not wanted and not required.
        let plain = generate(&parse("allowed: ascii-printable;").unwrap(), 30, false).unwrap().password;
        assert!(plain.chars().all(|c| c.is_ascii_alphanumeric()));
        // Required symbols stay even so.
        let needed = generate(&parse("required: special;").unwrap(), 16, false).unwrap().password;
        assert!(needed.chars().any(|c| !c.is_ascii_alphanumeric()));
    }

    #[test]
    fn known_websites() {
        assert!(known().len() > 400);
        // Listed hosts, and their subdomains.
        assert!(rules_for("apple.com").is_some());
        assert!(rules_for("www.apple.com").is_some());
        assert!(rules_for("id.apple.com").is_some());
        assert!(rules_for("example.com").is_none());
        // Every listed site's rules can be read and met.
        for (domain, text) in known() {
            let rules = parse(text).unwrap_or_else(|| panic!("{domain}: {text}"));
            generate(&rules, 20, true).unwrap_or_else(|_| panic!("{domain}: {text}"));
        }
    }
}
