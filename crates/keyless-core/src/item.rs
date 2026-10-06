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
}

impl ItemDetails {
    pub fn all_fields(&self) -> impl Iterator<Item = &Field> {
        self.fields
            .iter()
            .chain(self.sections.iter().flat_map(|s| s.fields.iter()))
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
}
