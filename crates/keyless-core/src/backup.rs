//! Encrypted backup files (`.keyless`).
//!
//! A backup is a self-contained JSON document encrypted with a key derived
//! from a backup password chosen at export time (independent of the account),
//! so it can be restored even without the account or the Secret Key:
//!
//! ```text
//! key  = Argon2id(NFKD(trim(password)), random salt[16], m, t, p)[32]
//! file = { format, version, kdf, salt, data: seal(key, padded JSON, "backup") }
//! ```

use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{
    Error, Result,
    crypto::{SymmetricKey, random_array},
    import::{ImportResult, ImportedItem, ImportedVault},
    item::{ItemDetails, ItemOverview},
    keys::{KdfParams, normalize_master_password},
};

const FORMAT: &str = "keyless-backup";
const VERSION: u32 = 1;
const CONTEXT: &[u8] = b"backup";
/// Backups larger than this are refused on import.
pub const MAX_BACKUP_BYTES: usize = 512 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
struct BackupFile {
    format: String,
    version: u32,
    kdf: KdfParams,
    salt: String,
    data: String,
}

#[derive(Serialize, Deserialize, Default)]
pub struct BackupData {
    /// Unix seconds.
    pub exported_at: i64,
    pub vaults: Vec<BackupVault>,
}

#[derive(Serialize, Deserialize, Default)]
pub struct BackupVault {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub items: Vec<BackupItem>,
}

#[derive(Serialize, Deserialize)]
pub struct BackupItem {
    pub overview: ItemOverview,
    pub details: ItemDetails,
}

fn derive_key(password: &str, salt: &[u8], kdf: &KdfParams) -> Result<SymmetricKey> {
    kdf.validate()?;
    let password = normalize_master_password(password);
    if password.is_empty() {
        return Err(Error::EmptyPassword);
    }
    let params = Params::new(kdf.m, kdf.t, kdf.p, Some(32)).map_err(|_| Error::Kdf)?;
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .map_err(|_| Error::Kdf)?;
    SymmetricKey::from_slice(key.as_ref())
}

/// Encrypts a backup with `password`. Returns the file contents.
pub fn export_backup(password: &str, data: &BackupData) -> Result<Zeroizing<String>> {
    let kdf = KdfParams::recommended();
    let salt = random_array::<16>()?;
    let key = derive_key(password, salt.as_ref(), &kdf)?;
    let json = Zeroizing::new(serde_json::to_vec(data)?);
    let file = BackupFile {
        format: FORMAT.into(),
        version: VERSION,
        kdf,
        salt: URL_SAFE_NO_PAD.encode(salt.as_ref()),
        data: key.seal_padded(&json, CONTEXT)?,
    };
    Ok(Zeroizing::new(serde_json::to_string_pretty(&file)?))
}

/// Decrypts a backup file. Fails with [`Error::Decryption`] on a wrong
/// password or a modified file.
pub fn decrypt_backup(password: &str, contents: &[u8]) -> Result<BackupData> {
    if contents.len() > MAX_BACKUP_BYTES {
        return Err(Error::Import("the backup is too large".into()));
    }
    let file: BackupFile =
        serde_json::from_slice(contents).map_err(|_| Error::Import("this is not a Keyless backup file".into()))?;
    if file.format != FORMAT || file.version != VERSION {
        return Err(Error::Import("unsupported backup version".into()));
    }
    let salt = URL_SAFE_NO_PAD
        .decode(&file.salt)
        .map_err(|_| Error::Import("damaged backup file".into()))?;
    if salt.len() != 16 {
        return Err(Error::Import("damaged backup file".into()));
    }
    let key = derive_key(password, &salt, &file.kdf)?;
    let json = key.open_padded(&file.data, CONTEXT)?;
    Ok(serde_json::from_slice(&json)?)
}

impl BackupData {
    pub fn into_import(self) -> ImportResult {
        ImportResult {
            vaults: self
                .vaults
                .into_iter()
                .map(|v| ImportedVault {
                    name: v.name,
                    items: v
                        .items
                        .into_iter()
                        .map(|i| ImportedItem { overview: i.overview, details: i.details })
                        .collect(),
                })
                .collect(),
            warnings: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::{Category, Field, FieldKind, FieldPurpose};

    fn sample() -> BackupData {
        let mut details = ItemDetails::default();
        details.fields.push(Field {
            id: "p".into(),
            label: "password".into(),
            kind: FieldKind::Concealed,
            value: "s3cret".into(),
            purpose: Some(FieldPurpose::Password),
        });
        BackupData {
            exported_at: 1,
            vaults: vec![BackupVault {
                name: "Personal".into(),
                description: String::new(),
                items: vec![BackupItem {
                    overview: ItemOverview { title: "Example".into(), category: Category::Login, ..Default::default() },
                    details,
                }],
            }],
        }
    }

    #[test]
    fn roundtrip() {
        let file = export_backup("backup password 1", &sample()).unwrap();
        assert!(!file.contains("s3cret") && !file.contains("Example"));
        let restored = decrypt_backup("backup password 1", file.as_bytes()).unwrap();
        assert_eq!(restored.vaults[0].items[0].details.password(), Some("s3cret"));
        let import = restored.into_import();
        assert_eq!(import.summary().total_items, 1);
    }

    #[test]
    fn wrong_password_or_tampering_fails() {
        let file = export_backup("backup password 1", &sample()).unwrap();
        assert!(matches!(decrypt_backup("backup password 2", file.as_bytes()), Err(Error::Decryption)));

        let mut parsed: serde_json::Value = serde_json::from_str(&file).unwrap();
        parsed["kdf"]["m"] = serde_json::json!(1024);
        let weakened = serde_json::to_vec(&parsed).unwrap();
        assert!(decrypt_backup("backup password 1", &weakened).is_err());

        assert!(decrypt_backup("x", b"not json").is_err());
    }
}
