//! What the host keeps between runs: the account's key bundle and the
//! vaults' and items' ciphertext, as the server has them, with what the
//! checks need (versions, cursors). Nothing here is readable without the
//! master password and Secret Key.

use std::collections::BTreeMap;

use keyless_core::account::AccountBundle;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Store {
    pub format: u32,
    pub user_id: String,
    pub email: String,
    pub bundle: Option<AccountBundle>,
    pub vaults: BTreeMap<String, VaultRow>,
    pub items: BTreeMap<String, ItemRow>,
    /// Per vault: the server's counter of the last item received.
    pub cursors: BTreeMap<String, i64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultRow {
    pub owner_id: String,
    pub role: String,
    pub enc_meta: String,
    pub enc_vault_key: String,
    pub seq: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemRow {
    pub vault_id: String,
    pub enc_overview: Option<String>,
    pub enc_details: Option<String>,
    pub revision: i64,
    pub seq: i64,
    pub deleted: bool,
    /// The content's version (or the deletion's): never goes back.
    pub version: u64,
    pub enc_tombstone: Option<String>,
}
