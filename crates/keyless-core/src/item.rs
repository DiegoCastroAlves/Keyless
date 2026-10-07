//! Item data model.
//!
//! Each item is stored as two independently encrypted documents:
//!
//! - the **overview** (title, subtitle, URLs, tags, flags) — decrypted for the
//!   item list, search and autofill matching;
//! - the **details** (fields, notes, password history) — decrypted only when
//!   an item is opened or filled.
//!
//! All fields use `#[serde(default)]` so older clients can read items written
//! by newer ones.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    #[default]
    Login,
    Password,
    SecureNote,
    CreditCard,
    Identity,
    BankAccount,
    ApiCredential,
    Database,
    Server,
    SshKey,
    SoftwareLicense,
    WirelessRouter,
    EmailAccount,
    Passport,
    DriverLicense,
    Membership,
    CryptoWallet,
    MedicalRecord,
    Document,
    #[serde(other)]
    Other,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemUrl {
    pub href: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub label: String,
    /// Where the login may be filled, like 1Password's "autofill behavior".
    #[serde(default, skip_serializing_if = "UrlMatch::is_default")]
    pub fill: UrlMatch,
}

/// Which pages an item's website covers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UrlMatch {
    /// Anywhere on the website: the same registrable domain
    /// (accounts.example.com for example.com).
    #[default]
    Domain,
    /// Only this exact host (and port, when one is given).
    Host,
    /// Never: kept for reference, not filled anywhere.
    Never,
}

impl UrlMatch {
    pub fn is_default(&self) -> bool {
        *self == UrlMatch::Domain
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemOverview {
    pub title: String,
    #[serde(default)]
    pub subtitle: String,
    #[serde(default)]
    pub category: Category,
    #[serde(default)]
    pub urls: Vec<ItemUrl>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub favorite: bool,
    #[serde(default)]
    pub archived: bool,
    /// Unix seconds when the item was moved to Recently Deleted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trashed_at: Option<i64>,
    /// Unix seconds.
    #[serde(default)]
    pub created_at: i64,
    /// Unix seconds.
    #[serde(default)]
    pub updated_at: i64,
    /// Incremented by the client on every write. Clients refuse to replace a
    /// copy with an older version (rollback protection).
    #[serde(default)]
    pub version: u64,
    /// Random id shared by the overview and details written together, so the
    /// two documents of different versions cannot be mixed.
    #[serde(default)]
    pub content_id: String,
    /// Watchtower alerts the user chose to ignore for this item ("weak",
    /// "reused", "breached", "compromised", "unsecured", "expiring",
    /// "two_factor").
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub watchtower_ignored: Vec<String>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
#[serde(rename_all = "snake_case")]
pub enum FieldKind {
    Concealed,
    Email,
    Url,
    Phone,
    Totp,
    Date,
    MonthYear,
    CardNumber,
    Pin,
    Multiline,
    /// Plain text. Unknown kinds written by newer clients also read as text.
    #[default]
    #[serde(other)]
    Text,
}

impl FieldKind {
    /// Fields whose value should be hidden until the user reveals it.
    pub fn is_secret(self) -> bool {
        matches!(self, FieldKind::Concealed | FieldKind::Pin | FieldKind::CardNumber | FieldKind::Totp)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
#[serde(rename_all = "snake_case")]
pub enum FieldPurpose {
    Username,
    Password,
    #[serde(other)]
    Other,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Field {
    pub id: String,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub kind: FieldKind,
    #[serde(default)]
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<FieldPurpose>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Section {
    pub id: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub fields: Vec<Field>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct PasswordHistoryEntry {
    pub value: String,
    /// Unix seconds.
    pub changed_at: i64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ItemDetails {
    /// Main fields shown at the top of the item (username, password, card
    /// number, ...).
    #[serde(default)]
    pub fields: Vec<Field>,
    #[serde(default)]
    pub sections: Vec<Section>,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub password_history: Vec<PasswordHistoryEntry>,
    /// Same as [`ItemOverview::version`].
    #[serde(default)]
    pub version: u64,
    /// Same as [`ItemOverview::content_id`].
    #[serde(default)]
    pub content_id: String,
    /// Passkeys for the item's website (see `passkey`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub passkeys: Vec<crate::passkey::Passkey>,
}

impl ItemDetails {
    pub fn all_fields(&self) -> impl Iterator<Item = &Field> {
        self.fields
            .iter()
            .chain(self.sections.iter().flat_map(|s| s.fields.iter()))
    }

    /// Puts the username before the password, then the other main fields
    /// as they were. Imports keep the source's order, which sometimes has
    /// the password first.
    pub fn sort_main_fields(&mut self) {
        self.fields.sort_by_key(|f| match f.purpose {
            Some(FieldPurpose::Username) => 0,
            Some(FieldPurpose::Password) => 1,
            _ => 2,
        });
    }

    pub fn field_by_purpose(&self, purpose: FieldPurpose) -> Option<&Field> {
        self.all_fields().find(|f| f.purpose == Some(purpose))
    }

    pub fn username(&self) -> Option<&str> {
        self.field_by_purpose(FieldPurpose::Username)
            .map(|f| f.value.as_str())
    }

    pub fn password(&self) -> Option<&str> {
        self.field_by_purpose(FieldPurpose::Password)
            .map(|f| f.value.as_str())
    }
}

/// Short random id for fields and sections.
pub fn new_field_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..12].to_string()
}

/// Random id linking an overview and details written together.
pub fn new_content_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

/// Stamps a new version on both documents of an item before encryption.
pub fn stamp_version(overview: &mut ItemOverview, details: &mut ItemDetails, version: u64) {
    let content_id = new_content_id();
    overview.version = version;
    overview.content_id = content_id.clone();
    details.version = version;
    details.content_id = content_id;
}

/// Whether an overview and details belong to the same write.
pub fn same_write(overview: &ItemOverview, details: &ItemDetails) -> bool {
    overview.version == details.version && overview.content_id == details.content_id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_values_are_tolerated() {
        let json = r#"{"title":"x","category":"spaceship","future_flag":true}"#;
        let overview: ItemOverview = serde_json::from_str(json).unwrap();
        assert_eq!(overview.category, Category::Other);

        let field: Field = serde_json::from_str(r#"{"id":"a","kind":"hologram","purpose":"thing"}"#).unwrap();
        assert_eq!(field.kind, FieldKind::Text);
        assert_eq!(field.purpose, Some(FieldPurpose::Other));
    }

    #[test]
    fn username_and_password_lookup() {
        let mut details = ItemDetails::default();
        details.fields = vec![
            Field { id: "u".into(), label: "username".into(), kind: FieldKind::Text, value: "me".into(), purpose: Some(FieldPurpose::Username) },
            Field { id: "p".into(), label: "password".into(), kind: FieldKind::Concealed, value: "pw".into(), purpose: Some(FieldPurpose::Password) },
        ];
        assert_eq!(details.username(), Some("me"));
        assert_eq!(details.password(), Some("pw"));
    }

    #[test]
    fn username_comes_before_password() {
        let field = |id: &str, purpose| Field { id: id.into(), label: id.into(), kind: FieldKind::Text, value: String::new(), purpose };
        let mut details = ItemDetails::default();
        details.fields = vec![
            field("otp", Some(FieldPurpose::Other)),
            field("password", Some(FieldPurpose::Password)),
            field("note", None),
            field("username", Some(FieldPurpose::Username)),
        ];
        details.sort_main_fields();
        let order: Vec<&str> = details.fields.iter().map(|f| f.id.as_str()).collect();
        assert_eq!(order, ["username", "password", "otp", "note"]);
    }
}
