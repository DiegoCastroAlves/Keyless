//! Vault keys and item encryption.
//!
//! Every vault has its own random 256-bit key. Items in the vault are
//! encrypted with it, each ciphertext bound to `(vault_id, item_id, purpose)`
//! so the server cannot move ciphertexts between items or vaults.

use serde::{Deserialize, Serialize};

use crate::{
    Result,
    crypto::{SymmetricKey, context},
    item::{ItemDetails, ItemOverview},
};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultMeta {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub icon: String,
    #[serde(default)]
    pub color: String,
}

pub struct VaultKey(SymmetricKey);

impl VaultKey {
    pub fn generate() -> Result<Self> {
        Ok(Self(SymmetricKey::generate()?))
    }

    pub fn duplicate(&self) -> Self {
        Self(self.0.duplicate())
    }

    /// Encrypts this vault key for its owner under their user key.
    pub fn wrap(&self, user_key: &SymmetricKey, vault_id: &str) -> Result<String> {
        user_key.seal(self.0.as_bytes(), &context("vault-key", &[vault_id]))
    }

    pub fn unwrap(user_key: &SymmetricKey, vault_id: &str, enc_vault_key: &str) -> Result<Self> {
        let bytes = user_key.open(enc_vault_key, &context("vault-key", &[vault_id]))?;
        Ok(Self(SymmetricKey::from_slice(&bytes)?))
    }

    pub fn seal_meta(&self, vault_id: &str, meta: &VaultMeta) -> Result<String> {
        let json = zeroize::Zeroizing::new(serde_json::to_vec(meta)?);
        self.0.seal_padded(&json, &context("vault-meta", &[vault_id]))
    }

    pub fn open_meta(&self, vault_id: &str, enc_meta: &str) -> Result<VaultMeta> {
        let json = self.0.open_padded(enc_meta, &context("vault-meta", &[vault_id]))?;
        Ok(serde_json::from_slice(&json)?)
    }

    pub fn seal_overview(&self, vault_id: &str, item_id: &str, overview: &ItemOverview) -> Result<String> {
        let json = zeroize::Zeroizing::new(serde_json::to_vec(overview)?);
        self.0
            .seal_padded(&json, &context("item-overview", &[vault_id, item_id]))
    }

    pub fn open_overview(&self, vault_id: &str, item_id: &str, enc_overview: &str) -> Result<ItemOverview> {
        let json = self
            .0
            .open_padded(enc_overview, &context("item-overview", &[vault_id, item_id]))?;
        Ok(serde_json::from_slice(&json)?)
    }

    pub fn seal_details(&self, vault_id: &str, item_id: &str, details: &ItemDetails) -> Result<String> {
        let json = zeroize::Zeroizing::new(serde_json::to_vec(details)?);
        self.0
            .seal_padded(&json, &context("item-details", &[vault_id, item_id]))
    }

    pub fn open_details(&self, vault_id: &str, item_id: &str, enc_details: &str) -> Result<ItemDetails> {
        let json = self
            .0
            .open_padded(enc_details, &context("item-details", &[vault_id, item_id]))?;
        Ok(serde_json::from_slice(&json)?)
    }
}

impl std::fmt::Debug for VaultKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VaultKey(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::{Category, Field, FieldKind, FieldPurpose};

    fn sample() -> (ItemOverview, ItemDetails) {
        let overview = ItemOverview {
            title: "Example".into(),
            subtitle: "me@example.com".into(),
            category: Category::Login,
            ..Default::default()
        };
        let mut details = ItemDetails::default();
        details.fields.push(Field {
            id: "p".into(),
            label: "password".into(),
            kind: FieldKind::Concealed,
            value: "hunter2".into(),
            purpose: Some(FieldPurpose::Password),
        });
        (overview, details)
    }

    #[test]
    fn item_roundtrip() {
        let vk = VaultKey::generate().unwrap();
        let (overview, details) = sample();
        let eo = vk.seal_overview("v1", "i1", &overview).unwrap();
        let ed = vk.seal_details("v1", "i1", &details).unwrap();
        assert_eq!(vk.open_overview("v1", "i1", &eo).unwrap(), overview);
        assert_eq!(vk.open_details("v1", "i1", &ed).unwrap(), details);
    }

    #[test]
    fn ciphertexts_are_bound_to_item_vault_and_purpose() {
        let vk = VaultKey::generate().unwrap();
        let (overview, details) = sample();
        let eo = vk.seal_overview("v1", "i1", &overview).unwrap();
        let ed = vk.seal_details("v1", "i1", &details).unwrap();
        assert!(vk.open_overview("v1", "i2", &eo).is_err());
        assert!(vk.open_overview("v2", "i1", &eo).is_err());
        assert!(vk.open_details("v1", "i1", &eo).is_err());
        assert!(vk.open_overview("v1", "i1", &ed).is_err());
    }

    #[test]
    fn vault_key_wrapping() {
        let user_key = SymmetricKey::generate().unwrap();
        let vk = VaultKey::generate().unwrap();
        let wrapped = vk.wrap(&user_key, "v1").unwrap();
        let unwrapped = VaultKey::unwrap(&user_key, "v1", &wrapped).unwrap();
        let meta = VaultMeta { name: "Personal".into(), ..Default::default() };
        let enc = vk.seal_meta("v1", &meta).unwrap();
        assert_eq!(unwrapped.open_meta("v1", &enc).unwrap(), meta);
        assert!(VaultKey::unwrap(&user_key, "v2", &wrapped).is_err());
    }
}
