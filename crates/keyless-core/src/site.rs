//! Websites: the host of an item's address and the site (registrable
//! domain) it belongs to, the same in every app (the desktop's browser
//! extension, Sentinel).

/// Host part of a URL, accepting bare domains.
pub fn url_host(url: &str) -> Option<String> {
    url_parts(url).map(|(host, _)| host)
}

/// Host and port (when not the scheme's default) of a URL, accepting bare
/// domains.
pub fn url_parts(url: &str) -> Option<(String, Option<u16>)> {
    let url = url.trim();
    let normalized = if url.contains("://") { url.to_string() } else { format!("https://{url}") };
    let parsed = url::Url::parse(&normalized).ok()?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return None;
    }
    let host = parsed.host_str()?.trim_start_matches("www.").to_ascii_lowercase();
    Some((host, parsed.port()))
}

/// Registrable domain ("eTLD+1"), e.g. accounts.google.com -> google.com.
/// Addresses by number (192.168.1.1, [::1]) are whole hosts.
pub fn site_of(host: &str) -> String {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    if bare.parse::<std::net::IpAddr>().is_ok() {
        return host.to_string();
    }
    psl::domain_str(host).map(str::to_string).unwrap_or_else(|| host.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts() {
        assert_eq!(url_host("https://www.GitHub.com/login"), Some("github.com".into()));
        assert_eq!(url_host("github.com"), Some("github.com".into()));
        assert_eq!(url_host("javascript:alert(1)"), None);
        assert_eq!(url_host("file:///etc/passwd"), None);
        assert_eq!(url_parts("http://example.com:8080/a"), Some(("example.com".into(), Some(8080))));
        assert_eq!(url_parts("https://example.com:443"), Some(("example.com".into(), None)));
    }

    #[test]
    fn sites() {
        assert_eq!(site_of("accounts.google.com"), "google.com");
        assert_eq!(site_of("alice.github.io"), "alice.github.io");
        assert_ne!(site_of("victim.vercel.app"), site_of("attacker.vercel.app"));
        assert_eq!(site_of("[::1]"), "[::1]");
        assert_eq!(site_of("192.168.1.1"), "192.168.1.1");
    }
}
