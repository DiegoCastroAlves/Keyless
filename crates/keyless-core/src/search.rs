//! Searching as people type: without minding case, accents or how a
//! character was written. "mae" finds "Mãe", "acao" finds "Ação", "strasse"
//! finds "Straße", and the other way round.
//!
//! The apps that search their own lists keep the same rule: the desktop's
//! and the extension's TypeScript (`fold` in `lib/search.ts` and
//! `src/search.ts`), Android's Kotlin (`Search.kt`) and iOS's Swift
//! (`Search.swift`). Change them together.

use unicode_normalization::{UnicodeNormalization, char::is_combining_mark};

/// `text` folded for searching: lowercase; accents dropped (compatibility
/// decomposition, then no combining marks: "ﬁ" is "fi", "²" is "2"); the
/// letters that do not decompose spelled out (ß → ss, æ → ae, œ → oe, ø → o,
/// ł → l, đ → d, ı → i); curly quotes and dashes as their plain forms.
pub fn fold(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.nfkd() {
        if is_combining_mark(c) {
            continue;
        }
        match c {
            'ß' | 'ẞ' => out.push_str("ss"),
            'æ' | 'Æ' => out.push_str("ae"),
            'œ' | 'Œ' => out.push_str("oe"),
            'ø' | 'Ø' => out.push('o'),
            'ł' | 'Ł' => out.push('l'),
            'đ' | 'Đ' => out.push('d'),
            'ı' => out.push('i'),
            '\u{2018}' | '\u{2019}' | '\u{201B}' | '\u{2032}' => out.push('\''),
            '\u{201C}' | '\u{201D}' | '\u{201F}' | '\u{2033}' => out.push('"'),
            '\u{2010}'..='\u{2015}' | '\u{2212}' => out.push('-'),
            _ => out.extend(c.to_lowercase()),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folds_case_accents_and_spellings() {
        assert_eq!(fold("Mãe"), "mae");
        assert_eq!(fold("AÇÃO"), "acao");
        assert_eq!(fold("José Ñandú"), "jose nandu");
        assert_eq!(fold("Straße"), "strasse");
        assert_eq!(fold("Æble Œuvre Øl Łódź Đorđe"), "aeble oeuvre ol lodz dorde");
        assert_eq!(fold("ﬁle²"), "file2");
        assert_eq!(fold("d’água – e‑mail"), "d'agua - e-mail");
        assert_eq!(fold("İstanbul"), "istanbul");
        // What needs no folding stays as it is.
        assert_eq!(fold("github.com/me 123"), "github.com/me 123");
    }

    #[test]
    fn details_match_without_accents() {
        let mut details = crate::item::ItemDetails::default();
        details.notes.push_str("Conta da Mãe");
        assert!(details.matches(&fold("mae")));
        assert!(details.matches(&fold("DA MÃE")));
        assert!(!details.matches(&fold("pai")));
    }
}
