//! Local encrypted cache (SQLite).
//!
//! The local database mirrors what the server stores: ciphertexts, wrapped
//! keys and public metadata. Nothing in it is readable without the master
//! password and Secret Key. It lets Keyless unlock and show items offline.

use std::path::Path;

use keyless_core::account::AccountBundle;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Serialize, de::DeserializeOwned};

use crate::error::AppResult;

const SCHEMA_VERSION: i64 = 5;

pub struct Store {
    conn: Connection,
}

#[derive(Clone, Debug)]
pub struct LocalAccount {
    pub user_id: String,
    pub email: String,
    pub server_url: String,
    pub bundle: AccountBundle,
    /// Refresh token sealed with the user key.
    pub enc_session: Option<String>,
}

#[derive(Clone, Debug)]
pub struct LocalVault {
    pub id: String,
    pub owner_id: String,
    pub role: String,
    pub enc_meta: String,
    pub enc_vault_key: String,
    pub seq: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dirty {
    Clean = 0,
    Upsert = 1,
    Delete = 2,
}

impl Dirty {
    fn from_i64(v: i64) -> Self {
        match v {
            1 => Dirty::Upsert,
            2 => Dirty::Delete,
            _ => Dirty::Clean,
        }
    }
}

#[derive(Clone, Debug)]
pub struct LocalItem {
    pub id: String,
    pub vault_id: String,
    pub enc_overview: Option<String>,
    pub enc_details: Option<String>,
    /// Last server revision this copy is based on (0 = never uploaded).
    pub revision: i64,
    pub seq: i64,
    pub deleted: bool,
    pub dirty: Dirty,
    /// Client-side version of this copy (rollback protection).
    pub version: u64,
    /// Proof of deletion, for tombstones waiting to be uploaded.
    pub enc_tombstone: Option<String>,
}

impl Store {
    pub fn open(path: &Path) -> AppResult<Self> {
        let conn = Connection::open(path)?;
        restrict_permissions(path);
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA foreign_keys = ON;
             PRAGMA secure_delete = ON;
             PRAGMA synchronous = NORMAL;",
        )?;
        let store = Self { conn };
        store.migrate()?;
        Ok(store)
    }

    #[cfg(test)]
    pub fn open_in_memory() -> AppResult<Self> {
        let store = Self { conn: Connection::open_in_memory()? };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> AppResult<()> {
        let version: i64 = self.conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if version < 1 {
            self.conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS account (
                    user_id TEXT PRIMARY KEY,
                    email TEXT NOT NULL,
                    server_url TEXT NOT NULL,
                    bundle TEXT NOT NULL,
                    enc_session TEXT
                 );
                 CREATE TABLE IF NOT EXISTS vaults (
                    id TEXT PRIMARY KEY,
                    owner_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    enc_meta TEXT NOT NULL,
                    enc_vault_key TEXT NOT NULL,
                    seq INTEGER NOT NULL DEFAULT 0
                 );
                 CREATE TABLE IF NOT EXISTS items (
                    id TEXT PRIMARY KEY,
                    vault_id TEXT NOT NULL,
                    enc_overview TEXT,
                    enc_details TEXT,
                    revision INTEGER NOT NULL DEFAULT 0,
                    seq INTEGER NOT NULL DEFAULT 0,
                    deleted INTEGER NOT NULL DEFAULT 0,
                    dirty INTEGER NOT NULL DEFAULT 0
                 );
                 CREATE INDEX IF NOT EXISTS items_vault_idx ON items (vault_id);
                 CREATE TABLE IF NOT EXISTS sync_cursors (
                    vault_id TEXT PRIMARY KEY,
                    cursor INTEGER NOT NULL
                 );",
            )?;
        }
        if version < 2 {
            // Version 2: item versions and tombstone proofs, per-vault sync
            // counters (old cursors are meaningless), paired browser
            // extensions.
            self.conn.execute_batch(
                "ALTER TABLE items ADD COLUMN version INTEGER NOT NULL DEFAULT 0;
                 ALTER TABLE items ADD COLUMN enc_tombstone TEXT;
                 DELETE FROM sync_cursors;
                 CREATE TABLE IF NOT EXISTS bridge_peers (
                    public_key TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                 );",
            )?;
        }
        if version < 3 {
            // Version 3: how often and when each item was used, for sorting.
            // Local only, never synced; items are referenced by their random
            // ids.
            self.conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS item_usage (
                    item_id TEXT PRIMARY KEY,
                    uses INTEGER NOT NULL DEFAULT 0,
                    last_used_at INTEGER NOT NULL
                 );",
            )?;
        }
        if version < 4 {
            // Version 4: website icons (see `site_icons`), encrypted; ids are
            // keyed hashes of the host. Local only.
            self.conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS site_icons (
                    id TEXT PRIMARY KEY,
                    data TEXT NOT NULL,
                    found INTEGER NOT NULL,
                    fetched_at INTEGER NOT NULL
                 );",
            )?;
        }
        if version < 5 {
            // Version 5: generator history (see `generator_history`),
            // encrypted. Local only.
            self.conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS generator_history (
                    id TEXT PRIMARY KEY,
                    data TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                 );",
            )?;
        }
        self.conn
            .execute_batch(&format!("PRAGMA user_version = {SCHEMA_VERSION};"))?;
        Ok(())
    }

    // ----- settings -------------------------------------------------------

    pub fn setting<T: DeserializeOwned>(&self, key: &str) -> AppResult<Option<T>> {
        let raw: Option<String> = self
            .conn
            .query_row("SELECT value FROM settings WHERE key = ?1", [key], |r| r.get(0))
            .optional()?;
        Ok(match raw {
            Some(raw) => serde_json::from_str(&raw).ok(),
            None => None,
        })
    }

    pub fn set_setting<T: Serialize>(&self, key: &str, value: &T) -> AppResult<()> {
        self.conn.execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, serde_json::to_string(value)?],
        )?;
        Ok(())
    }

    pub fn delete_setting(&self, key: &str) -> AppResult<()> {
        self.conn.execute("DELETE FROM settings WHERE key = ?1", [key])?;
        Ok(())
    }

    // ----- account --------------------------------------------------------

    pub fn account(&self) -> AppResult<Option<LocalAccount>> {
        let row = self
            .conn
            .query_row(
                "SELECT user_id, email, server_url, bundle, enc_session FROM account LIMIT 1",
                [],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, Option<String>>(4)?,
                    ))
                },
            )
            .optional()?;
        match row {
            Some((user_id, email, server_url, bundle, enc_session)) => Ok(Some(LocalAccount {
                user_id,
                email,
                server_url,
                bundle: serde_json::from_str(&bundle)?,
                enc_session,
            })),
            None => Ok(None),
        }
    }

    pub fn save_account(&self, account: &LocalAccount) -> AppResult<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute("DELETE FROM account WHERE user_id <> ?1", [&account.user_id])?;
        tx.execute(
            "INSERT INTO account (user_id, email, server_url, bundle, enc_session)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(user_id) DO UPDATE SET
                email = excluded.email,
                server_url = excluded.server_url,
                bundle = excluded.bundle,
                enc_session = excluded.enc_session",
            params![
                account.user_id,
                account.email,
                account.server_url,
                serde_json::to_string(&account.bundle)?,
                account.enc_session
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn set_enc_session(&self, user_id: &str, enc_session: Option<&str>) -> AppResult<()> {
        self.conn.execute(
            "UPDATE account SET enc_session = ?2 WHERE user_id = ?1",
            params![user_id, enc_session],
        )?;
        Ok(())
    }

    /// Removes every account-related row (sign out). Settings are kept.
    pub fn wipe_account_data(&self) -> AppResult<()> {
        self.conn.execute_batch(
            "DELETE FROM items; DELETE FROM vaults; DELETE FROM sync_cursors; DELETE FROM account; DELETE FROM bridge_peers; DELETE FROM item_usage; DELETE FROM site_icons; DELETE FROM generator_history;",
        )?;
        // Reclaim pages so deleted ciphertext does not linger in the file.
        let _ = self.conn.execute_batch("VACUUM;");
        Ok(())
    }

    // ----- vaults ---------------------------------------------------------

    pub fn vaults(&self) -> AppResult<Vec<LocalVault>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, owner_id, role, enc_meta, enc_vault_key, seq FROM vaults")?;
        let rows = stmt.query_map([], |r| {
            Ok(LocalVault {
                id: r.get(0)?,
                owner_id: r.get(1)?,
                role: r.get(2)?,
                enc_meta: r.get(3)?,
                enc_vault_key: r.get(4)?,
                seq: r.get(5)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn upsert_vault(&self, vault: &LocalVault) -> AppResult<()> {
        self.conn.execute(
            "INSERT INTO vaults (id, owner_id, role, enc_meta, enc_vault_key, seq)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(id) DO UPDATE SET
                owner_id = excluded.owner_id,
                role = excluded.role,
                enc_meta = excluded.enc_meta,
                enc_vault_key = excluded.enc_vault_key,
                seq = excluded.seq",
            params![vault.id, vault.owner_id, vault.role, vault.enc_meta, vault.enc_vault_key, vault.seq],
        )?;
        Ok(())
    }

    pub fn delete_vault(&self, vault_id: &str) -> AppResult<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute("DELETE FROM items WHERE vault_id = ?1", [vault_id])?;
        tx.execute("DELETE FROM sync_cursors WHERE vault_id = ?1", [vault_id])?;
        tx.execute("DELETE FROM vaults WHERE id = ?1", [vault_id])?;
        tx.commit()?;
        Ok(())
    }

    // ----- items ----------------------------------------------------------

    fn map_item(r: &rusqlite::Row<'_>) -> rusqlite::Result<LocalItem> {
        Ok(LocalItem {
            id: r.get(0)?,
            vault_id: r.get(1)?,
            enc_overview: r.get(2)?,
            enc_details: r.get(3)?,
            revision: r.get(4)?,
            seq: r.get(5)?,
            deleted: r.get::<_, i64>(6)? != 0,
            dirty: Dirty::from_i64(r.get(7)?),
            version: r.get::<_, i64>(8)?.max(0) as u64,
            enc_tombstone: r.get(9)?,
        })
    }

    const ITEM_COLUMNS: &'static str =
        "id, vault_id, enc_overview, enc_details, revision, seq, deleted, dirty, version, enc_tombstone";

    pub fn items(&self) -> AppResult<Vec<LocalItem>> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {} FROM items WHERE deleted = 0",
            Self::ITEM_COLUMNS
        ))?;
        let rows = stmt.query_map([], Self::map_item)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn item(&self, id: &str) -> AppResult<Option<LocalItem>> {
        Ok(self
            .conn
            .query_row(
                &format!("SELECT {} FROM items WHERE id = ?1", Self::ITEM_COLUMNS),
                [id],
                Self::map_item,
            )
            .optional()?)
    }

    pub fn dirty_items(&self) -> AppResult<Vec<LocalItem>> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {} FROM items WHERE dirty <> 0",
            Self::ITEM_COLUMNS
        ))?;
        let rows = stmt.query_map([], Self::map_item)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn upsert_item(&self, item: &LocalItem) -> AppResult<()> {
        self.conn.execute(
            "INSERT INTO items (id, vault_id, enc_overview, enc_details, revision, seq, deleted, dirty, version, enc_tombstone)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(id) DO UPDATE SET
                vault_id = excluded.vault_id,
                enc_overview = excluded.enc_overview,
                enc_details = excluded.enc_details,
                revision = excluded.revision,
                seq = excluded.seq,
                deleted = excluded.deleted,
                dirty = excluded.dirty,
                version = excluded.version,
                enc_tombstone = excluded.enc_tombstone",
            params![
                item.id,
                item.vault_id,
                item.enc_overview,
                item.enc_details,
                item.revision,
                item.seq,
                item.deleted as i64,
                item.dirty as i64,
                item.version as i64,
                item.enc_tombstone
            ],
        )?;
        Ok(())
    }

    // ----- browser extension peers ------------------------------------------

    pub fn is_bridge_peer(&self, public_key: &str) -> AppResult<bool> {
        Ok(self
            .conn
            .query_row("SELECT 1 FROM bridge_peers WHERE public_key = ?1", [public_key], |_| Ok(()))
            .optional()?
            .is_some())
    }

    pub fn add_bridge_peer(&self, public_key: &str, name: &str) -> AppResult<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO bridge_peers (public_key, name, created_at) VALUES (?1, ?2, strftime('%s','now'))",
            params![public_key, name],
        )?;
        Ok(())
    }

    // ----- item usage -----------------------------------------------------

    pub fn record_item_use(&self, item_id: &str) -> AppResult<()> {
        self.conn.execute(
            "INSERT INTO item_usage (item_id, uses, last_used_at) VALUES (?1, 1, strftime('%s','now'))
             ON CONFLICT(item_id) DO UPDATE SET uses = uses + 1, last_used_at = excluded.last_used_at",
            [item_id],
        )?;
        Ok(())
    }

    /// Keeps the usage of an item that moved to another vault under a new id.
    pub fn move_item_usage(&self, from: &str, to: &str) -> AppResult<()> {
        self.conn.execute("UPDATE item_usage SET item_id = ?2 WHERE item_id = ?1", [from, to])?;
        Ok(())
    }

    /// item id -> (uses, last used at in Unix seconds).
    pub fn item_usage(&self) -> AppResult<std::collections::HashMap<String, (u32, i64)>> {
        let mut stmt = self.conn.prepare("SELECT item_id, uses, last_used_at FROM item_usage")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, (r.get::<_, u32>(1)?, r.get::<_, i64>(2)?))))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// (encrypted data, whether an icon was found, when it was fetched).
    pub fn site_icon(&self, id: &str) -> AppResult<Option<(String, bool, i64)>> {
        Ok(self
            .conn
            .query_row("SELECT data, found, fetched_at FROM site_icons WHERE id = ?1", [id], |r| {
                Ok((r.get(0)?, r.get::<_, i64>(1)? != 0, r.get(2)?))
            })
            .optional()?)
    }

    pub fn save_site_icon(&self, id: &str, data: &str, found: bool, fetched_at: i64) -> AppResult<()> {
        self.conn.execute(
            "INSERT INTO site_icons (id, data, found, fetched_at) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(id) DO UPDATE SET data = excluded.data, found = excluded.found, fetched_at = excluded.fetched_at",
            rusqlite::params![id, data, found as i64, fetched_at],
        )?;
        Ok(())
    }

    pub fn clear_site_icons(&self) -> AppResult<()> {
        self.conn.execute("DELETE FROM site_icons", [])?;
        Ok(())
    }

    /// Adds a generator history entry and keeps only the newest `keep`.
    pub fn add_generated(&self, id: &str, data: &str, created_at: i64, keep: usize) -> AppResult<()> {
        self.conn.execute(
            "INSERT INTO generator_history (id, data, created_at) VALUES (?1, ?2, ?3)",
            rusqlite::params![id, data, created_at],
        )?;
        self.conn.execute(
            "DELETE FROM generator_history WHERE rowid NOT IN
               (SELECT rowid FROM generator_history ORDER BY created_at DESC, rowid DESC LIMIT ?1)",
            [keep as i64],
        )?;
        Ok(())
    }

    /// (id, encrypted data, created at), newest first.
    pub fn generated_entries(&self, limit: usize) -> AppResult<Vec<(String, String, i64)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, data, created_at FROM generator_history ORDER BY created_at DESC, rowid DESC LIMIT ?1")?;
        let rows = stmt.query_map([limit as i64], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn delete_generated(&self, id: &str) -> AppResult<()> {
        self.conn.execute("DELETE FROM generator_history WHERE id = ?1", [id])?;
        Ok(())
    }

    pub fn clear_generated(&self) -> AppResult<()> {
        self.conn.execute("DELETE FROM generator_history", [])?;
        Ok(())
    }

    pub fn bridge_peers(&self) -> AppResult<Vec<(String, String, i64)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT public_key, name, created_at FROM bridge_peers ORDER BY created_at")?;
        let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn remove_bridge_peer(&self, public_key: &str) -> AppResult<()> {
        self.conn.execute("DELETE FROM bridge_peers WHERE public_key = ?1", [public_key])?;
        Ok(())
    }

    pub fn cursor(&self, vault_id: &str) -> AppResult<i64> {
        Ok(self
            .conn
            .query_row("SELECT cursor FROM sync_cursors WHERE vault_id = ?1", [vault_id], |r| r.get(0))
            .optional()?
            .unwrap_or(0))
    }

    pub fn set_cursor(&self, vault_id: &str, cursor: i64) -> AppResult<()> {
        self.conn.execute(
            "INSERT INTO sync_cursors (vault_id, cursor) VALUES (?1, ?2)
             ON CONFLICT(vault_id) DO UPDATE SET cursor = excluded.cursor",
            params![vault_id, cursor],
        )?;
        Ok(())
    }
}

/// Keeps the database readable only by the current user on Unix. On Windows
/// the per-user app data directory already has a user-only ACL.
fn restrict_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        if let Some(dir) = path.parent() {
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyless_core::keys::KdfParams;

    fn bundle() -> AccountBundle {
        AccountBundle {
            format: 1,
            kdf: KdfParams::recommended(),
            enc_user_key: "k1.a".into(),
            public_key: "pk".into(),
            enc_private_key: "k1.b".into(),
        }
    }

    #[test]
    fn account_roundtrip_and_wipe() {
        let store = Store::open_in_memory().unwrap();
        assert!(store.account().unwrap().is_none());
        let account = LocalAccount {
            user_id: "u1".into(),
            email: "me@example.com".into(),
            server_url: "https://x".into(),
            bundle: bundle(),
            enc_session: None,
        };
        store.save_account(&account).unwrap();
        store.set_enc_session("u1", Some("k1.s")).unwrap();
        let loaded = store.account().unwrap().unwrap();
        assert_eq!(loaded.enc_session.as_deref(), Some("k1.s"));
        assert_eq!(loaded.bundle, bundle());
        store.wipe_account_data().unwrap();
        assert!(store.account().unwrap().is_none());
    }

    #[test]
    fn items_dirty_tracking() {
        let store = Store::open_in_memory().unwrap();
        let mut item = LocalItem {
            id: "i1".into(),
            vault_id: "v1".into(),
            enc_overview: Some("k1.o".into()),
            enc_details: Some("k1.d".into()),
            revision: 0,
            seq: 0,
            deleted: false,
            dirty: Dirty::Upsert,
            version: 1,
            enc_tombstone: None,
        };
        store.upsert_item(&item).unwrap();
        assert_eq!(store.dirty_items().unwrap().len(), 1);
        item.dirty = Dirty::Clean;
        item.revision = 3;
        store.upsert_item(&item).unwrap();
        assert!(store.dirty_items().unwrap().is_empty());
        assert_eq!(store.item("i1").unwrap().unwrap().revision, 3);
        assert_eq!(store.items().unwrap().len(), 1);
        store.set_cursor("v1", 42).unwrap();
        assert_eq!(store.cursor("v1").unwrap(), 42);
        store.delete_vault("v1").unwrap();
        assert!(store.items().unwrap().is_empty());
        assert_eq!(store.cursor("v1").unwrap(), 0);
    }
}
