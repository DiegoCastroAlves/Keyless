//! Website icons for the Android app, kept as the desktop keeps them (see
//! `keyless_core::site_icons`): the host downloads each icon from the site
//! itself and decodes it; this says which sites to ask, which icons a page
//! declares and which addresses are public, and seals what is kept.

use std::net::IpAddr;

use base64::{Engine, engine::general_purpose::STANDARD};
use keyless_core::{
    item::Category,
    site::url_host,
    site_icons::{IconKeys, allowed_host, icon_address, icon_links, is_public},
};
use serde::Deserialize;
use serde_json::{Value, json};
use url::Url;

use crate::{Client, Failure, Outcome, args};

impl Client {
    fn icon_keys(&self) -> Outcome<IconKeys> {
        Ok(IconKeys::new(self.unlocked()?.account.user_key())?)
    }

    /// The hosts of the logins (and passwords) that may have an icon, each
    /// with the name its icon is kept under: `[{host, id}]`.
    pub(crate) fn site_icon_hosts(&self) -> Outcome<Value> {
        let unlocked = self.unlocked()?;
        let keys = self.icon_keys()?;
        let mut hosts: Vec<String> = Vec::new();
        for (id, row) in &self.store.items {
            if row.deleted {
                continue;
            }
            let (Some(vault), Some(enc)) = (unlocked.vaults.get(&row.vault_id), row.enc_overview.as_deref()) else { continue };
            let Ok(overview) = vault.key.open_overview(&row.vault_id, id, enc) else { continue };
            if overview.trashed_at.is_some() || !matches!(overview.category, Category::Login | Category::Password) {
                continue;
            }
            hosts.extend(overview.urls.iter().filter_map(|u| url_host(&u.href)).filter(|h| allowed_host(h)));
            // A linked app's site, for a login with no website.
            hosts.extend(icon_address(&overview.urls).and_then(|a| url_host(&a)).filter(|h| allowed_host(h)));
        }
        hosts.sort();
        hosts.dedup();
        Ok(Value::Array(hosts.into_iter().map(|host| json!({ "id": keys.id(&host), "host": host })).collect()))
    }

    /// Seals an icon to keep: `png` (base64) and whether it is `opaque`, or
    /// no `png` when the site has none.
    pub(crate) fn site_icon_seal(&self, json: &str) -> Outcome<Value> {
        #[derive(Deserialize)]
        struct A {
            id: String,
            #[serde(default)]
            png: Option<String>,
            #[serde(default)]
            opaque: bool,
        }
        let a: A = args(json)?;
        let png = a.png.map(|p| STANDARD.decode(p)).transpose().map_err(|_| Failure::new("invalid_request"))?;
        Ok(json!(self.icon_keys()?.seal(&a.id, png.as_deref().map(|p| (p, a.opaque)))?))
    }

    /// A kept icon: `{png, padded}` (padded: transparent, shown on a light
    /// tile), or null when the site had none.
    pub(crate) fn site_icon_open(&self, json: &str) -> Outcome<Value> {
        #[derive(Deserialize)]
        struct A {
            id: String,
            data: String,
        }
        let a: A = args(json)?;
        Ok(match self.icon_keys()?.open(&a.id, &a.data) {
            Some((png, opaque)) => json!({ "png": STANDARD.encode(png), "padded": !opaque }),
            None => Value::Null,
        })
    }
}

/// The icons a page at `url` declares (`html`), the best first.
pub(crate) fn site_icon_links(json: &str) -> Outcome<Value> {
    #[derive(Deserialize)]
    struct A {
        html: String,
        url: String,
    }
    let a: A = args(json)?;
    let base = Url::parse(&a.url).map_err(|_| Failure::new("invalid_request"))?;
    Ok(Value::Array(icon_links(&a.html, &base).into_iter().map(|u| json!(u.as_str())).collect()))
}

/// Whether `host` may be contacted for its icon (a public internet name).
pub(crate) fn site_icon_allowed(json: &str) -> Outcome<Value> {
    #[derive(Deserialize)]
    struct A {
        host: String,
    }
    let a: A = args(json)?;
    Ok(json!(allowed_host(&a.host)))
}

/// Whether `ip` is on the internet (not this phone or its networks).
pub(crate) fn public_address(json: &str) -> Outcome<Value> {
    #[derive(Deserialize)]
    struct A {
        ip: String,
    }
    let a: A = args(json)?;
    Ok(json!(a.ip.trim_matches(['[', ']']).parse::<IpAddr>().is_ok_and(is_public)))
}
