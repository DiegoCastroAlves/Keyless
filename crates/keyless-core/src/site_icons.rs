//! Website icons for logins, the same in every app: which sites may be
//! contacted, which icons a page declares, and how icons are kept.
//!
//! Each icon is downloaded from the site itself (never through a service
//! that would learn which sites the user has saved), only from public
//! `https` addresses, and kept on the device encrypted with a key derived
//! from the account's key. Files are named by a keyed hash of the host, so
//! they do not reveal the sites either. The apps do the downloading and the
//! decoding; this module is what they share.

use std::{collections::HashMap, net::IpAddr};

use hkdf::Hkdf;
use sha2::Sha256;
use url::Url;
use zeroize::Zeroizing;

use crate::{
    Error, Result,
    crypto::{SymmetricKey, context},
    item::ItemUrl,
};

/// Largest side of a kept icon, in pixels.
pub const ICON_SIZE: u32 = 64;

/// The keys icons are kept with, derived from the account's user key.
pub struct IconKeys {
    seal: SymmetricKey,
    ids: Hkdf<Sha256>,
}

impl IconKeys {
    pub fn new(user_key: &SymmetricKey) -> Result<Self> {
        let hkdf = Hkdf::<Sha256>::new(Some(b"keyless/site-icons/v1"), user_key.as_bytes());
        let mut seal = Zeroizing::new([0u8; 32]);
        hkdf.expand(b"seal", seal.as_mut()).map_err(|_| Error::Kdf)?;
        Ok(Self { seal: SymmetricKey::from_slice(seal.as_ref())?, ids: hkdf })
    }

    /// The name an icon is kept under: a keyed hash of the host, so it does not name it.
    pub fn id(&self, host: &str) -> String {
        let mut id = [0u8; 16];
        let _ = self.ids.expand(format!("host:{host}").as_bytes(), &mut id);
        hex::encode(id)
    }

    fn context(id: &str) -> Vec<u8> {
        context("site-icon", &[id])
    }

    /// Seals a PNG and whether it is opaque, or `None` (the site has no
    /// icon, asked again later): first byte 1 when opaque, then the PNG.
    pub fn seal(&self, id: &str, icon: Option<(&[u8], bool)>) -> Result<String> {
        let mut plain = Zeroizing::new(Vec::new());
        if let Some((png, opaque)) = icon {
            plain.push(u8::from(opaque));
            plain.extend_from_slice(png);
        }
        self.seal.seal(&plain, &Self::context(id))
    }

    /// The PNG and whether it is opaque; `None` when the site had no icon or
    /// the data does not open.
    pub fn open(&self, id: &str, data: &str) -> Option<(Vec<u8>, bool)> {
        let plain = self.seal.open(data, &Self::context(id)).ok()?;
        let (&opaque, png) = plain.split_first()?;
        Some((png.to_vec(), opaque == 1))
    }
}

/// Icons a page declares, the best first: the one closest to (and at
/// least) our size. SVG is skipped: it can carry scripts and we do not
/// render it.
pub fn icon_links(html: &str, base: &Url) -> Vec<Url> {
    let lower = html.to_ascii_lowercase();
    let mut found: Vec<(u32, Url)> = Vec::new();
    let mut from = 0;
    while let Some(offset) = lower[from..].find("<link") {
        let start = from + offset + "<link".len();
        let Some(length) = lower[start..].find('>') else { break };
        from = start + length;
        let attrs = attributes(&html[start..from]);
        let attr = |name: &str| attrs.get(name).map(String::as_str).unwrap_or("");
        let rel = attr("rel").to_ascii_lowercase();
        let touch = rel.split_whitespace().any(|r| r.starts_with("apple-touch-icon"));
        if !touch && !rel.split_whitespace().any(|r| r == "icon") {
            continue;
        }
        let href = attr("href").trim().replace("&amp;", "&");
        if href.is_empty() || href.starts_with("data:") || attr("type").contains("svg") {
            continue;
        }
        let Ok(url) = base.join(&href) else { continue };
        if url.scheme() != "https" || url.path().to_ascii_lowercase().ends_with(".svg") {
            continue;
        }
        let size = attr("sizes")
            .split_whitespace()
            .filter_map(|s| s.to_ascii_lowercase().split_once('x').and_then(|(w, _)| w.parse::<u32>().ok()))
            .max()
            .unwrap_or(if touch { 180 } else { 32 });
        found.push((size, url));
    }
    found.sort_by_key(|(size, _)| if *size >= ICON_SIZE { size - ICON_SIZE } else { 10_000 + ICON_SIZE - size });
    found.into_iter().map(|(_, url)| url).collect()
}

/// Attributes of a tag (`name="value"`, `name='value'`, `name=value`).
fn attributes(tag: &str) -> HashMap<String, String> {
    let bytes = tag.as_bytes();
    let mut attrs = HashMap::new();
    let mut i = 0;
    while i < bytes.len() {
        while i < bytes.len() && (bytes[i].is_ascii_whitespace() || bytes[i] == b'/') {
            i += 1;
        }
        let name_start = i;
        while i < bytes.len() && !bytes[i].is_ascii_whitespace() && !matches!(bytes[i], b'=' | b'/') {
            i += 1;
        }
        if name_start == i {
            i += 1;
            continue;
        }
        let name = tag[name_start..i].to_ascii_lowercase();
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let mut value = String::new();
        if i < bytes.len() && bytes[i] == b'=' {
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            if i < bytes.len() && matches!(bytes[i], b'"' | b'\'') {
                let quote = bytes[i];
                i += 1;
                let value_start = i;
                while i < bytes.len() && bytes[i] != quote {
                    i += 1;
                }
                value = tag[value_start..i].to_string();
                i += 1;
            } else {
                let value_start = i;
                while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
                    i += 1;
                }
                value = tag[value_start..i].to_string();
            }
        }
        attrs.entry(name).or_insert(value);
    }
    attrs
}

/// The Android app an address names (`android://<package>`,
/// `androidapp://<package>`, Chrome's `android://<hash>@<package>`), or `None`.
pub fn app_package(href: &str) -> Option<&str> {
    let text = href.trim();
    for scheme in ["android://", "androidapp://"] {
        if text.len() >= scheme.len() && text[..scheme.len()].eq_ignore_ascii_case(scheme) {
            let rest = &text[scheme.len()..];
            let name = rest.rsplit('@').next().unwrap_or(rest);
            let package = name.split(['/', '?', '#']).next().unwrap_or("");
            return (!package.is_empty()).then_some(package);
        }
    }
    None
}

/// The website a linked app stands for, for the icon of a login without
/// one: the site its package names, read backwards (org.telegram.messenger
/// is telegram.org), only when that site's name is the app's (its first
/// word, or all of it: "Telegram", "WhatsApp Business"). It is a guess, so
/// one that does not fit gives no icon rather than another site's:
/// com.nu.production is "Nubank", not nu.com, and
/// com.google.android.youtube is "YouTube", not google.com.
pub fn app_site(package: &str, label: &str) -> Option<String> {
    let host = package.trim().split('.').rev().collect::<Vec<_>>().join(".").to_ascii_lowercase();
    let domain = psl::domain(host.as_bytes()).filter(|d| d.suffix().is_known())?;
    let domain = std::str::from_utf8(domain.as_bytes()).ok()?.to_string();
    let name = domain.split('.').next()?;
    let simple = |text: &str| text.chars().filter(|c| c.is_alphanumeric()).collect::<String>().to_lowercase();
    let first = simple(label.split_whitespace().next().unwrap_or(""));
    let fits = !name.is_empty() && (first == name || simple(label) == name);
    (fits && allowed_host(&domain)).then(|| format!("https://{domain}"))
}

/// The address whose icon a login shows: its first website, or else the
/// site of its first linked app that stands for one (`app_site`, with the
/// app's name kept with its link). The same in every app.
pub fn icon_address(urls: &[ItemUrl]) -> Option<String> {
    let website = urls.iter().find(|u| !u.href.trim().is_empty() && app_package(&u.href).is_none());
    if let Some(website) = website {
        return Some(website.href.clone());
    }
    urls.iter().find_map(|u| app_package(&u.href).and_then(|package| app_site(package, &u.label)))
}

/// A public internet name: not an IP address, not a local or private name,
/// and under a known public suffix.
pub fn allowed_host(host: &str) -> bool {
    const LOCAL: [&str; 8] = [".local", ".lan", ".internal", ".home", ".home.arpa", ".localhost", ".corp", ".intranet"];
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    !host.contains(':')
        && host.parse::<IpAddr>().is_err()
        && host != "localhost"
        && !LOCAL.iter().any(|suffix| host.ends_with(suffix))
        && psl::domain(host.as_bytes()).is_some_and(|domain| domain.suffix().is_known())
}

/// Addresses on the internet, not on this computer or its networks.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.is_documentation()
                || v4.is_multicast()
                || a == 0
                || a >= 240
                || (a == 100 && (b & 0xc0) == 64)
                || (a == 192 && b == 0 && c == 0)
                || (a == 198 && (b & 0xfe) == 18))
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public(IpAddr::V4(v4));
            }
            let s = v6.segments();
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
                || (s[0] == 0x2001 && s[1] == 0x0db8)
                || (s[0] == 0x64 && s[1] == 0xff9b))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_linked_app_stands_for_its_own_site_only() {
        assert_eq!(app_package("android://org.telegram.messenger"), Some("org.telegram.messenger"));
        assert_eq!(app_package("android://AAAA@com.nu.production/"), Some("com.nu.production"));
        assert_eq!(app_package("https://telegram.org"), None);
        assert_eq!(app_site("org.telegram.messenger", "Telegram").as_deref(), Some("https://telegram.org"));
        assert_eq!(app_site("com.whatsapp.w4b", "WhatsApp Business").as_deref(), Some("https://whatsapp.com"));
        assert_eq!(app_site("com.instagram.android", "Instagram").as_deref(), Some("https://instagram.com"));
        assert_eq!(app_site("br.com.example.app", "Example").as_deref(), Some("https://example.com.br"));
        // Another name: no icon rather than another site's.
        assert_eq!(app_site("com.nu.production", "Nubank"), None);
        assert_eq!(app_site("com.google.android.youtube", "YouTube"), None);
        assert_eq!(app_site("org.telegram.messenger", ""), None);
        assert_eq!(app_site("telegram", "Telegram"), None);

        let url = |href: &str, label: &str| ItemUrl { href: href.into(), label: label.into(), ..Default::default() };
        assert_eq!(icon_address(&[url("android://org.telegram.messenger", "Telegram")]).as_deref(), Some("https://telegram.org"));
        // A website comes first; an app without its name, nothing.
        assert_eq!(icon_address(&[url("android://org.telegram.messenger", "Telegram"), url("https://web.telegram.org", "")]).as_deref(), Some("https://web.telegram.org"));
        assert_eq!(icon_address(&[url("android://org.telegram.messenger", "")]), None);
    }

    #[test]
    fn only_public_names_are_contacted() {
        assert!(allowed_host("instagram.com"));
        assert!(allowed_host("accounts.google.com"));
        assert!(!allowed_host("localhost"));
        assert!(!allowed_host("router.lan"));
        assert!(!allowed_host("printer.local"));
        assert!(!allowed_host("192.168.0.1"));
        assert!(!allowed_host("10.0.0.1"));
        assert!(!allowed_host("::1"));
        assert!(!allowed_host("intranet"));
        assert!(!allowed_host("nas.home.arpa"));
    }

    #[test]
    fn private_addresses_are_refused() {
        for ip in ["127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.1.1", "100.64.0.1", "0.0.0.0", "::1", "fd00::1", "fe80::1", "::ffff:192.168.0.1"] {
            assert!(!is_public(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["142.250.78.4", "157.240.12.174", "2a03:2880:f12f:83:face:b00c:0:25de"] {
            assert!(is_public(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn finds_the_best_icon_link() {
        let base = Url::parse("https://www.example.com/login").unwrap();
        let html = r#"<html><head>
            <link rel="icon" href="/favicon-16.png" sizes="16x16">
            <LINK REL='shortcut icon' href=/favicon.ico>
            <link rel="mask-icon" href="/mask.svg">
            <link rel="icon" type="image/svg+xml" href="/icon.svg">
            <link rel="apple-touch-icon" sizes="180x180" href="https://cdn.example.com/touch.png?v=1&amp;x=2">
            <link rel="icon" sizes="96x96" href="/favicon-96.png">
            <link rel="icon" href="http://insecure.example.com/i.png" sizes="64x64">
        </head></html>"#;
        let links: Vec<String> = icon_links(html, &base).into_iter().map(String::from).collect();
        assert_eq!(
            links,
            [
                "https://www.example.com/favicon-96.png",
                "https://cdn.example.com/touch.png?v=1&x=2",
                "https://www.example.com/favicon.ico",
                "https://www.example.com/favicon-16.png",
            ]
        );
    }

    #[test]
    fn icons_are_kept_sealed_under_hashed_names() {
        let keys = IconKeys::new(&SymmetricKey::from_slice(&[7u8; 32]).unwrap()).unwrap();
        let id = keys.id("github.com");
        assert_eq!(id.len(), 32);
        assert!(!id.contains("github"));
        assert_ne!(id, keys.id("gitlab.com"));
        let sealed = keys.seal(&id, Some((b"png bytes", true))).unwrap();
        assert_eq!(keys.open(&id, &sealed), Some((b"png bytes".to_vec(), true)));
        // Bound to its name, and "no icon" opens to nothing.
        assert_eq!(keys.open(&keys.id("gitlab.com"), &sealed), None);
        assert_eq!(keys.open(&id, &keys.seal(&id, None).unwrap()), None);
        let other = IconKeys::new(&SymmetricKey::from_slice(&[8u8; 32]).unwrap()).unwrap();
        assert_ne!(other.id("github.com"), id);
        assert_eq!(other.open(&id, &sealed), None);
    }
}
