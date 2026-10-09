//! Websites that share one account: a login saved for one is offered on the
//! others (iCloud signs in on apple.com, Mercado Pago with a Mercado Livre
//! account).
//!
//! From Apple's password-manager-resources (`data/shared-credentials.json`,
//! MIT license, see `data/shared-credentials.LICENSE.md`), which password
//! managers maintain together, plus a few big services it leaves out. Groups
//! name registrable domains; "shared" groups go both ways, "from"/"to" ones
//! only from the old or secondary domains to the main ones.

use std::{
    collections::{HashMap, HashSet},
    sync::OnceLock,
};

use serde::Deserialize;

const APPLE_LIST: &str = include_str!("data/shared-credentials.json");

/// Big services Apple's list leaves out, each signing in on the others.
const EXTRA: &[&[&str]] = &[
    &["apple.com", "icloud.com"],
    &["google.com", "youtube.com", "gmail.com"],
    &[
        "microsoft.com",
        "live.com",
        "microsoftonline.com",
        "office.com",
        "outlook.com",
        "hotmail.com",
        "xbox.com",
        "skype.com",
        "bing.com",
        "azure.com",
    ],
    &[
        "amazon.com",
        "amazon.com.br",
        "amazon.ca",
        "amazon.com.mx",
        "amazon.co.uk",
        "amazon.de",
        "amazon.es",
        "amazon.fr",
        "amazon.it",
        "amazon.co.jp",
        "amazon.com.au",
    ],
    &["steampowered.com", "steamcommunity.com"],
    &["twitter.com", "x.com"],
    &["facebook.com", "messenger.com"],
    &["playstation.com", "sonyentertainmentnetwork.com"],
    &["battle.net", "blizzard.com"],
];

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Entry {
    #[serde(default)]
    shared: Vec<String>,
    #[serde(default)]
    from: Vec<String>,
    #[serde(default)]
    to: Vec<String>,
}

/// Site -> the sites its logins are also offered on.
fn table() -> &'static HashMap<String, HashSet<String>> {
    static TABLE: OnceLock<HashMap<String, HashSet<String>>> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut table: HashMap<String, HashSet<String>> = HashMap::new();
        let mut link = |from: &str, to: &str| {
            if from != to {
                table.entry(from.to_string()).or_default().insert(to.to_string());
            }
        };
        let apple: Vec<Entry> = serde_json::from_str(APPLE_LIST).unwrap_or_default();
        let groups = apple.iter().map(|e| e.shared.iter().map(String::as_str).collect::<Vec<_>>()).chain(EXTRA.iter().map(|g| g.to_vec()));
        for group in groups {
            for a in &group {
                for b in &group {
                    link(a, b);
                }
            }
        }
        for entry in &apple {
            for from in &entry.from {
                for to in &entry.to {
                    link(from, to);
                }
            }
        }
        table
    })
}

/// A login saved for `item_site` may be offered on `page_site` (two
/// registrable domains, already different).
pub fn shares_account(item_site: &str, page_site: &str) -> bool {
    table().get(item_site).is_some_and(|sites| sites.contains(page_site))
}

/// Two registrable domains of one service, as far as Keyless knows: the
/// same, or sharing one account either way (a frame of one inside a page of
/// the other is the service's own, as for iCloud's sign-in from apple.com).
pub fn same_owner(a: &str, b: &str) -> bool {
    !a.is_empty() && (a == b || shares_account(a, b) || shares_account(b, a))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_accounts() {
        // Apple's list, both ways for shared groups.
        assert!(shares_account("tutsplus.com", "envato.com"));
        assert!(shares_account("envato.com", "tutsplus.com"));
        // One way for an old domain to the main one.
        assert!(shares_account("mercadopago.com.br", "mercadolivre.com"));
        assert!(!shares_account("mercadolivre.com", "mercadopago.com.br"));
        // Keyless's own additions.
        assert!(shares_account("icloud.com", "apple.com"));
        assert!(shares_account("apple.com", "icloud.com"));
        assert!(!shares_account("icloud.com", "google.com"));
        assert!(!shares_account("example.com", "example.org"));
        assert!(table().len() > 100);
    }

    #[test]
    fn same_owners() {
        assert!(same_owner("apple.com", "apple.com"));
        assert!(same_owner("icloud.com", "apple.com"));
        // One-way entries still name one service.
        assert!(same_owner("mercadolivre.com", "mercadopago.com.br"));
        assert!(!same_owner("apple.com", "example.com"));
        assert!(!same_owner("", ""));
    }
}
