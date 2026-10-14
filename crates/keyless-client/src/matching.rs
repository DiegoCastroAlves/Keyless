//! Which logins belong to an app or a website (autofill): the same site
//! (registrable domain, so `accounts.example.com` and `example.com` match),
//! a subdomain of it, or an Android app named in the item
//! (`android://<package>` or `androidapp://<package>`).

/// How well the item address `href` fits `domain` (a host name) or
/// `package` (an Android app): 0 not at all, higher is better.
pub fn score(href: &str, domain: Option<&str>, package: Option<&str>) -> u8 {
    let href = href.trim();
    if let Some(package) = package.filter(|p| !p.is_empty()) {
        for scheme in ["android://", "androidapp://"] {
            if let Some(rest) = href.strip_prefix(scheme) {
                // android://<hash>@<package>/ (Chrome's form) or android://<package>
                let rest = rest.rsplit('@').next().unwrap_or(rest);
                let name = rest.split(['/', '?', '#']).next().unwrap_or(rest);
                if name.eq_ignore_ascii_case(package) {
                    return 4;
                }
            }
        }
    }
    let Some(domain) = domain.map(|d| d.trim().trim_end_matches('.').to_lowercase()).filter(|d| !d.is_empty()) else {
        return 0;
    };
    let Some(host) = host_of(href) else { return 0 };
    if host == domain {
        return 3;
    }
    match (registrable(&host), registrable(&domain)) {
        (Some(a), Some(b)) if a == b => 2,
        _ => 0,
    }
}

/// The host of an address, with or without a scheme.
pub fn host_of(href: &str) -> Option<String> {
    let rest = href.split_once("://").map_or(href, |(scheme, rest)| if scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https") { rest } else { "" });
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority.rsplit('@').next()?;
    let host = if host.starts_with('[') { host.split(']').next().map(|h| format!("{h}]"))? } else { host.split(':').next()?.to_string() };
    let host = host.trim_end_matches('.').to_lowercase();
    (!host.is_empty() && host.chars().all(|c| c.is_ascii_alphanumeric() || "-.[]:".contains(c))).then_some(host)
}

/// The registrable domain (eTLD+1), from the Public Suffix List.
pub fn registrable(host: &str) -> Option<String> {
    let domain = psl::domain(host.as_bytes())?;
    std::str::from_utf8(domain.as_bytes()).ok().map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn websites() {
        assert_eq!(score("https://github.com/login", Some("github.com"), None), 3);
        assert_eq!(score("github.com", Some("GitHub.com."), None), 3);
        assert_eq!(score("https://github.com", Some("gist.github.com"), None), 2);
        assert_eq!(score("https://accounts.google.com", Some("mail.google.com"), None), 2);
        assert_eq!(score("https://example.co.uk", Some("other.co.uk"), None), 0);
        assert_eq!(score("https://evilgithub.com", Some("github.com"), None), 0);
        assert_eq!(score("ftp://github.com", Some("github.com"), None), 0);
    }

    #[test]
    fn apps() {
        assert_eq!(score("android://com.nu.production", None, Some("com.nu.production")), 4);
        assert_eq!(score("android://AAAA@com.nu.production/", None, Some("com.nu.production")), 4);
        assert_eq!(score("androidapp://com.nu.production", None, Some("com.other")), 0);
        assert_eq!(score("https://nubank.com.br", None, Some("com.nu.production")), 0);
    }
}
