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
//! by newer ones, and fields this version does not know are kept as they are
//! ([`Unknown`]) so editing an item here does not drop them.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Fields written by a later Keyless version, kept as they were.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Unknown(pub Map<String, Value>);

impl Zeroize for Unknown {
    fn zeroize(&mut self) {
        // They may be secrets: wiped like the fields this version knows.
        self.0.values_mut().for_each(wipe_json);
        self.0.clear();
    }
}

/// Overwrites every string in a JSON value (they may hold secrets) before it
/// is freed.
pub fn wipe_json(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(list) => list.iter_mut().for_each(wipe_json),
        Value::Object(map) => map.values_mut().for_each(wipe_json),
        _ => {}
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize, Zeroize)]
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

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
pub struct ItemUrl {
    pub href: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub label: String,
    /// Where the login may be filled, like 1Password's "autofill behavior".
    #[serde(default, skip_serializing_if = "UrlMatch::is_default")]
    pub fill: UrlMatch,
    /// Whether filling it there also signs in (sends the form); `None`
    /// follows the browser extension's setting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub submit: Option<bool>,
    #[serde(flatten)]
    pub unknown: Unknown,
}

/// Which pages an item's website covers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
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

/// What lists and search need (title, username, websites, tags). It says
/// which sites the user has accounts on and with which usernames, so the
/// copies kept while unlocked are wiped on lock (`Zeroize`, without a
/// `Drop` so it can still be built with `..Default::default()`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
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
    /// Sentinel alerts the user chose to ignore for this item ("weak",
    /// "reused", "breached", "compromised", "unsecured", "expiring",
    /// "two_factor", "passkey", "duplicate", "lastpass").
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sentinel_ignored: Vec<String>,
    /// The item has its own icon ([`ItemDetails::icon`]), shown instead of
    /// the website's or the category's.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub custom_icon: bool,
    /// Where the item was imported from, when Sentinel cares: "lastpass"
    /// (LastPass's stored vaults were stolen in 2022).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub imported_from: String,
    #[serde(flatten)]
    pub unknown: Unknown,
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
    /// A postal address: its parts in [`FieldExtra::address`], the value
    /// holds them as text.
    Address,
    /// The label is the question, the value its answer (kept secret).
    SecurityQuestion,
    /// The account signs in through another provider ("Sign in with
    /// Google"): the value names it, [`FieldExtra::link`] may point to the
    /// provider's login item.
    SignInWith,
    /// A place: the value describes it, [`FieldExtra::geo`] has its
    /// coordinates when known.
    Location,
    /// Another item this one relates to: its id in [`FieldExtra::link`].
    Reference,
    /// One of the item's attachments: its id is the value.
    File,
    /// Plain text. Unknown kinds written by newer clients also read as text.
    #[default]
    #[serde(other)]
    Text,
}

impl FieldKind {
    /// Fields whose value should be hidden until the user reveals it.
    pub fn is_secret(self) -> bool {
        matches!(self, FieldKind::Concealed | FieldKind::Pin | FieldKind::CardNumber | FieldKind::Totp | FieldKind::SecurityQuestion)
    }

    /// Fields that hold a date the item may expire on.
    pub fn is_date(self) -> bool {
        matches!(self, FieldKind::Date | FieldKind::MonthYear)
    }
}

/// How long before a date field's date to warn that it expires.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
#[serde(rename_all = "snake_case")]
pub enum ExpiryAlert {
    /// Not a date that expires.
    Never,
    Day,
    Week,
    TwoWeeks,
    Month,
    TwoMonths,
    ThreeMonths,
    SixMonths,
    NineMonths,
    /// A value from a newer version: treated as no choice made.
    #[serde(other)]
    Unknown,
}

impl ExpiryAlert {
    /// Days ahead to warn; `None` for never (and unknown values).
    pub fn days(self) -> Option<i64> {
        match self {
            ExpiryAlert::Never | ExpiryAlert::Unknown => None,
            ExpiryAlert::Day => Some(1),
            ExpiryAlert::Week => Some(7),
            ExpiryAlert::TwoWeeks => Some(14),
            ExpiryAlert::Month => Some(30),
            ExpiryAlert::TwoMonths => Some(61),
            ExpiryAlert::ThreeMonths => Some(91),
            ExpiryAlert::SixMonths => Some(182),
            ExpiryAlert::NineMonths => Some(273),
        }
    }
}

/// The parts of an address field.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
pub struct Address {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub street: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub line2: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub city: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub state: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub zip: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub country: String,
    #[serde(flatten)]
    pub unknown: Unknown,
}

impl Address {
    /// The address as text, a line per part (city, state and zip together),
    /// which is what the field's value holds.
    pub fn formatted(&self) -> String {
        let city_line = [self.city.trim(), self.state.trim(), self.zip.trim()]
            .into_iter()
            .filter(|p| !p.is_empty())
            .collect::<Vec<_>>()
            .join(", ");
        [self.street.trim(), self.line2.trim(), city_line.as_str(), self.country.trim()]
            .into_iter()
            .filter(|p| !p.is_empty())
            .collect::<Vec<_>>()
            .join("\n")
    }

    pub fn is_empty(&self) -> bool {
        self.formatted().is_empty()
    }
}

/// What some kinds of field hold besides their value. Flattened into the
/// field, so items stay readable by versions that do not know these.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
pub struct FieldExtra {
    /// Date fields: when to warn before the date; `None` lets Keyless
    /// decide from the field's label (expiry dates warn a month ahead).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alert: Option<ExpiryAlert>,
    /// Address fields: the parts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<Address>,
    /// Another item: the related item, or the login a "sign in with"
    /// account uses.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub link: String,
    /// Location fields: "latitude,longitude".
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub geo: String,
    /// Keys written by a later version.
    #[serde(flatten)]
    pub unknown: Unknown,
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
    #[serde(flatten)]
    pub extra: FieldExtra,
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
    /// Files kept in the item (see `attachment`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<crate::attachment::Attachment>,
    /// The item's own icon: a small PNG as a data URL (kept here, not in
    /// the overview, whose size the server limits).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub icon: String,
    #[serde(flatten)]
    pub unknown: Unknown,
}

impl ItemDetails {
    /// Whether the details hold `query` (lowercase): notes, labels, section
    /// titles, file names and the values that are not secret (passwords,
    /// card numbers, codes and answers are never searched).
    pub fn matches(&self, query: &str) -> bool {
        let has = |text: &str| text.to_lowercase().contains(query);
        if has(&self.notes) {
            return true;
        }
        if self.sections.iter().any(|s| has(&s.title)) || self.attachments.iter().any(|a| has(&a.name)) {
            return true;
        }
        self.all_fields().any(|f| {
            let secret = f.kind.is_secret() || f.purpose == Some(FieldPurpose::Password);
            has(&f.label) || (!secret && f.kind != FieldKind::File && f.kind != FieldKind::Reference && has(&f.value))
        })
    }

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
    fn fields_of_later_versions_are_kept() {
        let json = r#"{"title":"x","urls":[{"href":"https://a.example","fill":"host","pattern":"/login"}],"future_flag":true,"version":3}"#;
        let overview: ItemOverview = serde_json::from_str(json).unwrap();
        assert_eq!(overview.version, 3);
        assert_eq!(overview.urls[0].fill, UrlMatch::Host);
        assert_eq!(overview.unknown.0.keys().collect::<Vec<_>>(), ["future_flag"]);
        assert_eq!(overview.urls[0].unknown.0["pattern"], "/login");
        let again: Value = serde_json::to_value(&overview).unwrap();
        assert_eq!(again["future_flag"], true);
        assert_eq!(again["urls"][0]["pattern"], "/login");

        let json = r#"{"notes":"n","documents":[{"id":"f1","key":"secret"}]}"#;
        let mut details: ItemDetails = serde_json::from_str(json).unwrap();
        assert_eq!(details.notes, "n");
        assert_eq!(serde_json::to_value(&details).unwrap()["documents"][0]["key"], "secret");
        details.zeroize();
        assert!(details.unknown.0.is_empty());
        // Nothing extra is written for items without such fields.
        assert!(!serde_json::to_string(&ItemDetails::default()).unwrap().contains("unknown"));
    }

    #[test]
    fn field_extras_round_trip_and_unknown_keys_stay() {
        let json = r#"{"id":"a","label":"home","kind":"address","value":"x","address":{"street":"Rua A, 1","city":"Recife","zip":"50000-000","floor":"3"},"alert":"two_weeks","link":"item-1","geo":"-8.05,-34.9","shape":"round"}"#;
        let field: Field = serde_json::from_str(json).unwrap();
        assert_eq!(field.kind, FieldKind::Address);
        assert_eq!(field.extra.alert, Some(ExpiryAlert::TwoWeeks));
        assert_eq!(field.extra.link, "item-1");
        assert_eq!(field.extra.geo, "-8.05,-34.9");
        let address = field.extra.address.clone().unwrap();
        assert_eq!(address.formatted(), "Rua A, 1\nRecife, 50000-000");
        let again = serde_json::to_value(&field).unwrap();
        assert_eq!(again["shape"], "round");
        assert_eq!(again["address"]["floor"], "3");
        assert_eq!(again["alert"], "two_weeks");
        // A plain field writes nothing extra.
        let plain = Field { id: "p".into(), label: "x".into(), kind: FieldKind::Text, value: "v".into(), purpose: None, extra: Default::default() };
        assert_eq!(serde_json::to_string(&plain).unwrap(), r#"{"id":"p","label":"x","kind":"text","value":"v"}"#);
    }

    #[test]
    fn expiry_alerts() {
        assert_eq!(ExpiryAlert::Day.days(), Some(1));
        assert_eq!(ExpiryAlert::NineMonths.days(), Some(273));
        assert_eq!(ExpiryAlert::Never.days(), None);
        let alert: ExpiryAlert = serde_json::from_str(r#""fortnightly""#).unwrap();
        assert_eq!(alert, ExpiryAlert::Unknown);
        assert!(FieldKind::SecurityQuestion.is_secret());
        assert!(FieldKind::MonthYear.is_date());
    }

    #[test]
    fn username_and_password_lookup() {
        let mut details = ItemDetails::default();
        details.fields = vec![
            Field { id: "u".into(), label: "username".into(), kind: FieldKind::Text, value: "me".into(), purpose: Some(FieldPurpose::Username), extra: Default::default() },
            Field { id: "p".into(), label: "password".into(), kind: FieldKind::Concealed, value: "pw".into(), purpose: Some(FieldPurpose::Password), extra: Default::default() },
        ];
        assert_eq!(details.username(), Some("me"));
        assert_eq!(details.password(), Some("pw"));
    }

    #[test]
    fn username_comes_before_password() {
        let field = |id: &str, purpose| Field { id: id.into(), label: id.into(), kind: FieldKind::Text, value: String::new(), purpose, extra: Default::default() };
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
