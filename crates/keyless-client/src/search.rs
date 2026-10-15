//! Searching inside items, as the desktop does (`ItemDetails::matches`), and
//! lists that need the details (items with a passkey, a Wi-Fi QR code).

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{Client, Failure, Outcome, args};

impl Client {
    /// Ids of the items whose details hold `query`: notes, labels, section
    /// titles, file names and values that are not secret. Below two
    /// characters, none.
    pub(crate) fn search_details(&self, json: &str) -> Outcome<Value> {
        #[derive(Deserialize)]
        struct A {
            query: String,
        }
        let a: A = args(json)?;
        let query = a.query.trim().to_lowercase();
        if query.chars().count() < 2 {
            return Ok(json!([]));
        }
        let ids: Vec<&String> = self.store.items.iter().filter(|(_, row)| !row.deleted).map(|(id, _)| id).collect();
        Ok(json!(ids.into_iter().filter(|id| self.open_item(id).is_ok_and(|(_, _, details)| details.matches(&query))).collect::<Vec<_>>()))
    }

    /// Ids of the items that keep a passkey.
    pub(crate) fn items_with_passkeys(&self) -> Outcome<Value> {
        let ids: Vec<&String> = self.store.items.iter().filter(|(_, row)| !row.deleted).map(|(id, _)| id).collect();
        Ok(json!(ids.into_iter().filter(|id| self.open_item(id).is_ok_and(|(_, _, details)| !details.passkeys.is_empty())).collect::<Vec<_>>()))
    }

    /// A wireless router item's Wi-Fi QR code, as modules (see `qr::modules`).
    pub(crate) fn wifi_qr(&self, json: &str) -> Outcome<Value> {
        #[derive(Deserialize)]
        struct A {
            id: String,
        }
        let a: A = args(json)?;
        let (_, _, details) = self.open_item(&a.id)?;
        let payload = keyless_core::wifi::payload(&details).map_err(|_| Failure::new("wifi_no_name"))?;
        Ok(json!(crate::qr::modules(&payload).ok_or(Failure::new("qr_too_long"))?))
    }
}

/// Any text as a QR code's modules, for large type.
/// A QR code in Keyless's look (`keyless_core::qr::art`), for the codes one
/// Keyless app shows another.
pub(crate) fn qr_art(json: &str) -> Outcome<Value> {
    #[derive(Deserialize)]
    struct A {
        text: zeroize::Zeroizing<String>,
    }
    let a: A = args(json)?;
    Ok(json!(keyless_core::qr::art(&a.text).ok_or(Failure::new("qr_too_long"))?))
}

pub(crate) fn qr_modules(json: &str) -> Outcome<Value> {
    #[derive(Deserialize)]
    struct A {
        text: zeroize::Zeroizing<String>,
    }
    let a: A = args(json)?;
    Ok(json!(crate::qr::modules(&a.text).ok_or(Failure::new("qr_too_long"))?))
}
