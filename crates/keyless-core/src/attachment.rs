//! File attachments, like 1Password's documents and files.
//!
//! Each file gets its own random key, kept with its name and size in the
//! item's encrypted details, and is encrypted in chunks of [`CHUNK_SIZE`]
//! bytes, so a large file never has to be in memory at once. Every chunk is
//! bound to its attachment, its position and whether it is the last one:
//! chunks cannot be swapped between files, reordered, dropped or added
//! without decryption failing. The server stores each chunk as an object
//! named `<vault id>/<attachment id>/<chunk number>` (see the `attachments`
//! migration).

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    Error, Result,
    crypto::{SymmetricKey, context},
};

/// Plaintext bytes per chunk.
pub const CHUNK_SIZE: usize = 4 * 1024 * 1024;
/// Bytes a chunk grows by when encrypted (nonce and tag).
pub const CHUNK_OVERHEAD: usize = 24 + 16;
/// Longest file name kept.
const MAX_NAME: usize = 255;

/// Fields default, so one damaged entry never makes the whole item
/// unreadable (it just fails to open).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct Attachment {
    /// A random UUID, also in the server's object names.
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    /// Plaintext size in bytes.
    #[serde(default)]
    pub size: u64,
    /// The file's key, base64url.
    #[serde(default)]
    pub key: String,
    /// Unix seconds.
    #[serde(default)]
    pub created_at: i64,
}

impl Attachment {
    /// A new attachment for a file of `size` bytes, with a fresh id and key.
    pub fn new(name: &str, size: u64, now: i64) -> Result<Self> {
        let key = SymmetricKey::generate()?;
        Ok(Self {
            id: uuid::Uuid::new_v4().to_string(),
            name: clean_name(name),
            size,
            key: URL_SAFE_NO_PAD.encode(key.as_bytes()),
            created_at: now,
        })
    }

    pub fn key(&self) -> Result<SymmetricKey> {
        let bytes = Zeroizing::new(URL_SAFE_NO_PAD.decode(&self.key).map_err(|_| Error::InvalidKey)?);
        SymmetricKey::from_slice(&bytes)
    }

    /// How many chunks the file has (an empty file has one, empty).
    pub fn chunks(&self) -> u32 {
        (self.size.div_ceil(CHUNK_SIZE as u64)).max(1) as u32
    }

    /// The plaintext size of chunk `index`.
    pub fn chunk_len(&self, index: u32) -> usize {
        let start = index as u64 * CHUNK_SIZE as u64;
        self.size.saturating_sub(start).min(CHUNK_SIZE as u64) as usize
    }

    /// The server's name for chunk `index` of this attachment in `vault_id`.
    pub fn object_name(&self, vault_id: &str, index: u32) -> String {
        format!("{vault_id}/{}/{index}", self.id)
    }

    /// Encrypts chunk `index` (which must have [`Attachment::chunk_len`]
    /// bytes).
    pub fn seal_chunk(&self, key: &SymmetricKey, index: u32, plaintext: &[u8]) -> Result<Vec<u8>> {
        if index >= self.chunks() || plaintext.len() != self.chunk_len(index) {
            return Err(Error::Encryption);
        }
        key.seal_raw(plaintext, &self.chunk_context(index))
    }

    /// Decrypts chunk `index`, checking it is the expected size.
    pub fn open_chunk(&self, key: &SymmetricKey, index: u32, raw: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if index >= self.chunks() {
            return Err(Error::Decryption);
        }
        let plaintext = key.open_raw(raw, &self.chunk_context(index))?;
        if plaintext.len() != self.chunk_len(index) {
            return Err(Error::Decryption);
        }
        Ok(plaintext)
    }

    fn chunk_context(&self, index: u32) -> Vec<u8> {
        let last = if index + 1 == self.chunks() { "last" } else { "more" };
        context("keyless/attachment-chunk", &[&self.id, &index.to_string(), last])
    }
}

/// A file name safe to show and to save under: no folders, control
/// characters or names that mean something else.
pub fn clean_name(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or("");
    let cleaned: String = base.chars().filter(|c| !c.is_control()).collect::<String>().trim().trim_matches('.').to_string();
    let cleaned: String = cleaned.chars().take(MAX_NAME).collect();
    if cleaned.is_empty() { "file".into() } else { cleaned }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(size: usize) -> (Attachment, Vec<u8>) {
        let attachment = Attachment::new("report.pdf", size as u64, 1).unwrap();
        let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        (attachment, data)
    }

    fn encrypt(attachment: &Attachment, data: &[u8]) -> Vec<Vec<u8>> {
        let key = attachment.key().unwrap();
        (0..attachment.chunks())
            .map(|i| {
                let start = i as usize * CHUNK_SIZE;
                attachment.seal_chunk(&key, i, &data[start..start + attachment.chunk_len(i)]).unwrap()
            })
            .collect()
    }

    #[test]
    fn round_trip_in_chunks() {
        for size in [0, 1, CHUNK_SIZE, CHUNK_SIZE + 1, 2 * CHUNK_SIZE + 17] {
            let (attachment, data) = file(size);
            let chunks = encrypt(&attachment, &data);
            assert_eq!(chunks.len() as u32, attachment.chunks());
            let key = attachment.key().unwrap();
            let mut out = Vec::new();
            for (i, raw) in chunks.iter().enumerate() {
                assert!(raw.len() <= CHUNK_SIZE + CHUNK_OVERHEAD);
                out.extend_from_slice(&attachment.open_chunk(&key, i as u32, raw).unwrap());
            }
            assert_eq!(out, data, "size {size}");
        }
    }

    #[test]
    fn chunks_cannot_be_moved() {
        let (attachment, data) = file(2 * CHUNK_SIZE + 5);
        let chunks = encrypt(&attachment, &data);
        let key = attachment.key().unwrap();
        // Reordered.
        assert!(attachment.open_chunk(&key, 0, &chunks[1]).is_err());
        // From another file with the same key.
        let mut other = attachment.clone();
        other.id = uuid::Uuid::new_v4().to_string();
        assert!(other.open_chunk(&key, 0, &chunks[0]).is_err());
        // Truncated: a file that claims to end earlier refuses its middle
        // chunk as the last one.
        let mut shorter = attachment.clone();
        shorter.size = 2 * CHUNK_SIZE as u64;
        assert!(shorter.open_chunk(&key, 1, &chunks[1]).is_err());
        // Tampered.
        let mut bad = chunks[2].clone();
        bad[30] ^= 1;
        assert!(attachment.open_chunk(&key, 2, &bad).is_err());
        // Wrong key.
        let stranger = Attachment::new("x", attachment.size, 1).unwrap();
        assert!(attachment.open_chunk(&stranger.key().unwrap(), 0, &chunks[0]).is_err());
        assert_eq!(attachment.object_name("v", 2), format!("v/{}/2", attachment.id));
    }

    #[test]
    fn names() {
        assert_eq!(clean_name("../../etc/passwd"), "passwd");
        assert_eq!(clean_name("C:\\Users\\me\\scan.png"), "scan.png");
        assert_eq!(clean_name("a\u{0}b\nc.txt"), "abc.txt");
        assert_eq!(clean_name(".."), "file");
        assert_eq!(clean_name(""), "file");
        assert_eq!(clean_name(&"x".repeat(400)).len(), 255);
    }

    #[test]
    fn damaged_entries_keep_the_item_readable() {
        let details: crate::item::ItemDetails = serde_json::from_str(r#"{"notes":"n","attachments":[{"id":"x"}]}"#).unwrap();
        assert_eq!(details.notes, "n");
        assert!(details.attachments[0].key().is_err());
    }
}
