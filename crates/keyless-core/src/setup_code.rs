//! Setup codes: the account's email and Secret Key as a `keyless://setup`
//! link, which a signed-in device shows as a QR code ("Set up another
//! device") and the Emergency Kit prints. Scanning, opening or pasting one
//! fills in the sign-in form of a new device; the master password is still
//! needed, as it never appears in a setup code.
//!
//! ```text
//! keyless://setup#email=me%40example.com&key=K1-ABCDEF-GHJKMN-PQRST-VWXYZ-01234
//! ```
//!
//! The values are in the fragment so they stay out of any log of the link.

use zeroize::Zeroizing;

use crate::{Error, Result, keys::SecretKey};

const SCHEME: &str = "keyless://setup";
/// Longest link accepted: an email (254) percent-encoded, plus the key.
const MAX_LEN: usize = 1024;

fn percent_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~@".contains(&byte) {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn percent_decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = text.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// The setup link for an account.
pub fn setup_link(email: &str, secret_key: &SecretKey) -> Zeroizing<String> {
    Zeroizing::new(format!("{SCHEME}#email={}&key={}", percent_encode(email), secret_key.to_display().as_str()))
}

/// Whether `text` is (or starts like) a setup link.
pub fn is_setup_link(text: &str) -> bool {
    text.trim().get(..SCHEME.len()).is_some_and(|head| head.eq_ignore_ascii_case(SCHEME))
}

/// The email and Secret Key in a setup link. Spaces and line breaks (from
/// copying a wrapped link) are ignored.
pub fn parse_setup_link(text: &str) -> Result<(String, SecretKey)> {
    let compact: Zeroizing<String> = Zeroizing::new(text.chars().filter(|c| !c.is_whitespace()).collect());
    if compact.len() > MAX_LEN || !is_setup_link(&compact) {
        return Err(Error::InvalidSecretKey);
    }
    let fragment = compact.split_once('#').map(|(_, f)| f).ok_or(Error::InvalidSecretKey)?;
    let (mut email, mut key) = (None, None);
    for pair in fragment.split('&') {
        match pair.split_once('=') {
            Some(("email", value)) => email = percent_decode(value),
            Some(("key", value)) => key = Some(SecretKey::parse(value)?),
            _ => {}
        }
    }
    match (email.filter(|e| e.contains('@')), key) {
        (Some(email), Some(key)) => Ok((email, key)),
        _ => Err(Error::InvalidSecretKey),
    }
}

/// Finds a setup link inside a file, such as the PDF of an Emergency Kit
/// (where the QR code links to it), written plainly or as a hex string.
pub fn find_setup_link(bytes: &[u8]) -> Option<Zeroizing<String>> {
    let is_link_char = |b: u8| b.is_ascii_alphanumeric() || b"-._~@%#&=:/".contains(&b);
    let plain = |data: &[u8]| -> Option<Zeroizing<String>> {
        let start = data.windows(SCHEME.len()).position(|w| w.eq_ignore_ascii_case(SCHEME.as_bytes()))?;
        let end = data[start..].iter().position(|&b| !is_link_char(b)).map_or(data.len(), |n| start + n);
        let link = Zeroizing::new(String::from_utf8_lossy(&data[start..end]).into_owned());
        parse_setup_link(&link).is_ok().then_some(link)
    };
    if let Some(link) = plain(bytes) {
        return Some(link);
    }
    // PDF hex strings: <6B65796C657373…>.
    let hex_scheme: String = SCHEME.bytes().map(|b| format!("{b:02x}")).collect();
    let lower = bytes.to_ascii_lowercase();
    let start = lower.windows(hex_scheme.len()).position(|w| w == hex_scheme.as_bytes())?;
    let end = lower[start..].iter().position(|b| !b.is_ascii_hexdigit()).map_or(lower.len(), |n| start + n);
    let decoded = Zeroizing::new(
        lower[start..end - (end - start) % 2]
            .chunks(2)
            .filter_map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
            .collect::<Vec<u8>>(),
    );
    plain(&decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let key = SecretKey::generate().unwrap();
        let link = setup_link("Me+tag@example.com", &key);
        assert!(link.starts_with("keyless://setup#email=Me%2Btag@example.com&key=K1-"));
        let (email, parsed) = parse_setup_link(&link).unwrap();
        assert_eq!(email, "Me+tag@example.com");
        assert_eq!(parsed.as_bytes(), key.as_bytes());
        // Wrapped when copied, and upper case.
        let wrapped = format!("{}\n {}", &link[..30], &link[30..]).replacen("keyless://setup", "KEYLESS://SETUP", 1);
        assert!(parse_setup_link(&wrapped).is_ok());
    }

    #[test]
    fn refuses_other_text() {
        assert!(parse_setup_link("https://example.com/#email=a@b.c&key=K1").is_err());
        assert!(parse_setup_link("keyless://setup#email=a@b.c&key=K1-AAAAAA").is_err());
        assert!(parse_setup_link("keyless://setup#key=K1-AAAAAA").is_err());
        assert!(!is_setup_link("keyless://item/1"));
    }

    #[test]
    fn finds_the_link_in_a_pdf() {
        let key = SecretKey::generate().unwrap();
        let link = setup_link("me@example.com", &key);
        let pdf = format!("%PDF-1.4\n<< /Type /Annot /A << /S /URI /URI ({}) >> >>\n%%EOF", link.as_str());
        assert_eq!(find_setup_link(pdf.as_bytes()).unwrap().as_str(), link.as_str());
        let hex: String = link.bytes().map(|b| format!("{b:02X}")).collect();
        let pdf = format!("<< /URI <{hex}> >>");
        assert_eq!(find_setup_link(pdf.as_bytes()).unwrap().as_str(), link.as_str());
        assert!(find_setup_link(b"%PDF-1.4 nothing here").is_none());
    }
}
