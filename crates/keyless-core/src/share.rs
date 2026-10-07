//! Share links: a copy of an item for someone without Keyless, like
//! 1Password's "share item" (see the `shares` migration).
//!
//! The app encrypts a snapshot of the item with a fresh random key and puts
//! the key only in the link's fragment (`…/share/#<id>.<key>`), which
//! browsers never send to a server. The web page that opens links decrypts
//! the snapshot in the recipient's browser, with the same envelope format as
//! everything else (XChaCha20-Poly1305, padded, bound to the share's id).
//!
//! The snapshot holds the title, websites, notes and fields with a value;
//! one-time password secrets, passkeys, attachments and password history
//! stay out.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    Error, Result,
    crypto::{SymmetricKey, context},
    item::{FieldKind, FieldPurpose, ItemDetails, ItemOverview},
};

const FORMAT: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct SharedField {
    pub label: String,
    pub value: String,
    /// The field kind as items store it ("text", "concealed", "url", ...).
    pub kind: String,
    /// Shown hidden until revealed (passwords, PINs, card numbers).
    pub secret: bool,
    /// The section it is in, if any.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub section: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct SharedItem {
    /// Format version, for the page.
    pub format: u32,
    pub title: String,
    /// The item category as items store it ("login", "credit_card", ...).
    pub category: String,
    pub fields: Vec<SharedField>,
    pub urls: Vec<String>,
    pub notes: String,
    /// Unix seconds.
    pub shared_at: i64,
}

impl SharedItem {
    /// The part of an item a link shares.
    pub fn of(overview: &ItemOverview, details: &ItemDetails, now: i64) -> Self {
        let kind = |k: FieldKind| serde_json::to_value(k).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_else(|| "text".into());
        let shared = |field: &crate::item::Field, section: &str| SharedField {
            label: field.label.clone(),
            value: field.value.clone(),
            kind: kind(field.kind),
            secret: field.kind.is_secret() || field.purpose == Some(FieldPurpose::Password),
            section: section.to_string(),
        };
        let mut sorted = details.clone();
        sorted.sort_main_fields();
        let keep = |f: &&crate::item::Field| !f.value.is_empty() && f.kind != FieldKind::Totp;
        let mut fields: Vec<SharedField> = sorted.fields.iter().filter(keep).map(|f| shared(f, "")).collect();
        for section in &sorted.sections {
            fields.extend(section.fields.iter().filter(keep).map(|f| shared(f, &section.title)));
        }
        Self {
            format: FORMAT,
            title: overview.title.clone(),
            category: serde_json::to_value(overview.category).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_else(|| "login".into()),
            fields,
            urls: overview.urls.iter().map(|u| u.href.clone()).filter(|h| !h.is_empty()).collect(),
            notes: details.notes.clone(),
            shared_at: now,
        }
    }
}

/// A link's secret half: its id and key.
pub struct ShareKey {
    pub id: String,
    key: SymmetricKey,
}

impl ShareKey {
    pub fn generate() -> Result<Self> {
        Ok(Self { id: uuid::Uuid::new_v4().to_string(), key: SymmetricKey::generate()? })
    }

    /// Reads the fragment of a link (`<id>.<key>`).
    pub fn from_fragment(fragment: &str) -> Result<Self> {
        let (id, key) = fragment.trim_start_matches('#').split_once('.').ok_or(Error::InvalidKey)?;
        let id = uuid::Uuid::parse_str(id).map_err(|_| Error::InvalidKey)?.to_string();
        let bytes = Zeroizing::new(URL_SAFE_NO_PAD.decode(key).map_err(|_| Error::InvalidKey)?);
        Ok(Self { id, key: SymmetricKey::from_slice(&bytes)? })
    }

    /// The link for the page at `base` (which ends with '/').
    pub fn link(&self, base: &str) -> Zeroizing<String> {
        Zeroizing::new(format!("{base}#{}.{}", self.id, URL_SAFE_NO_PAD.encode(self.key.as_bytes())))
    }

    pub fn seal(&self, item: &SharedItem) -> Result<String> {
        let json = Zeroizing::new(serde_json::to_vec(item)?);
        self.key.seal_padded(&json, &self.context())
    }

    pub fn open(&self, envelope: &str) -> Result<SharedItem> {
        let json = self.key.open_padded(envelope, &self.context())?;
        serde_json::from_slice(&json).map_err(Error::from)
    }

    fn context(&self) -> Vec<u8> {
        context("keyless/share", &[&self.id])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::{Category, Field, ItemUrl, Section};

    fn field(label: &str, kind: FieldKind, value: &str, purpose: Option<FieldPurpose>) -> Field {
        Field { id: label.into(), label: label.into(), kind, value: value.into(), purpose }
    }

    fn item() -> (ItemOverview, ItemDetails) {
        let overview = ItemOverview {
            title: "Netflix".into(),
            category: Category::Login,
            urls: vec![ItemUrl { href: "https://netflix.com".into(), ..Default::default() }],
            ..Default::default()
        };
        let mut details = ItemDetails::default();
        details.fields = vec![
            field("password", FieldKind::Concealed, "hunter2", Some(FieldPurpose::Password)),
            field("username", FieldKind::Text, "ana@example.com", Some(FieldPurpose::Username)),
            field("one-time password", FieldKind::Totp, "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP", None),
            field("empty", FieldKind::Text, "", None),
        ];
        details.sections = vec![Section { id: "s".into(), title: "Profiles".into(), fields: vec![field("pin", FieldKind::Pin, "1234", None)] }];
        details.notes = "Shared family account".into();
        details.password_history.push(crate::item::PasswordHistoryEntry { value: "old".into(), changed_at: 1 });
        (overview, details)
    }

    #[test]
    fn shares_only_what_it_should() {
        let (overview, details) = item();
        let shared = SharedItem::of(&overview, &details, 5);
        let labels: Vec<&str> = shared.fields.iter().map(|f| f.label.as_str()).collect();
        // Username first, no one-time password, no empty field.
        assert_eq!(labels, ["username", "password", "pin"]);
        assert!(shared.fields[1].secret && shared.fields[2].secret && !shared.fields[0].secret);
        assert_eq!(shared.fields[2].section, "Profiles");
        assert_eq!(shared.fields[2].kind, "pin");
        assert_eq!(shared.category, "login");
        assert_eq!(shared.urls, ["https://netflix.com"]);
        let json = serde_json::to_string(&shared).unwrap();
        assert!(!json.contains("otpauth") && !json.contains("\"old\""));
    }

    #[test]
    fn links_round_trip() {
        let (overview, details) = item();
        let shared = SharedItem::of(&overview, &details, 5);
        let key = ShareKey::generate().unwrap();
        let envelope = key.seal(&shared).unwrap();
        let link = key.link("https://keyless.example/share/");
        let fragment = link.split_once('#').unwrap().1;
        let opened = ShareKey::from_fragment(fragment).unwrap();
        assert_eq!(opened.id, key.id);
        assert_eq!(opened.open(&envelope).unwrap(), shared);
        // Another link's id, or another key, opens nothing.
        let other = ShareKey::generate().unwrap();
        assert!(other.open(&envelope).is_err());
        let moved = ShareKey::from_fragment(&format!("{}.{}", other.id, fragment.split_once('.').unwrap().1)).unwrap();
        assert!(moved.open(&envelope).is_err());
        assert!(ShareKey::from_fragment("nonsense").is_err());
    }
}
