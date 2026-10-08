//! Encrypted backup files (`.keyless`).
//!
//! A backup is encrypted with a key derived from a backup password chosen at
//! export time (independent of the account), so it can be restored even
//! without the account or the Secret Key. It is a zip archive:
//!
//! ```text
//! key          = Argon2id(NFKD(trim(password)), random salt[16], 256 MiB, t = 3, p = 4)[32]
//! backup.json  = { format, version: 2, kdf, salt,
//!                  data: seal(key, padded JSON of the items, "backup/2") }
//! files/<id>   = attachment <id>'s chunks, encrypted as the server keeps them
//! ```
//!
//! The items keep each attachment's name, size and key, so a file can only be
//! read with the backup password, and its chunks are bound to the attachment
//! (see `attachment`): files cannot be swapped, cut or changed unnoticed. The
//! archive does show how many files there are and their approximate sizes.
//!
//! A backup has no Secret Key: its password alone resists offline guessing,
//! so its Argon2id uses four times the account's memory (backups are made and
//! restored rarely, on a computer), and the app asks for a very strong
//! password. The parameters are stored in the file, and older backups (64 MiB)
//! still open. Version 1 backups (the JSON document alone, sealed with context
//! "backup", without files) can still be restored.

use std::{
    collections::{HashMap, HashSet},
    io::{Read, Seek, Write},
};

use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;
use zip::{CompressionMethod, write::SimpleFileOptions};

use crate::{
    Error, Result,
    attachment::{Attachment, CHUNK_OVERHEAD},
    crypto::{SymmetricKey, random_array},
    import::{ImportResult, ImportWarning, ImportedFile, ImportedItem, ImportedVault},
    item::{ItemDetails, ItemOverview},
    keys::{KdfParams, normalize_master_password},
};

const FORMAT: &str = "keyless-backup";
const VERSION: u32 = 2;
const CONTEXT: &[u8] = b"backup/2";
const V1_CONTEXT: &[u8] = b"backup";
/// The archive entry with the items.
const ITEMS_ENTRY: &str = "backup.json";
/// The item list of a backup larger than this is refused on import.
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

/// Argon2id for new backups: 256 MiB, 3 passes, 4 lanes.
pub fn backup_kdf() -> KdfParams {
    KdfParams { m: 256 * 1024, ..KdfParams::recommended() }
}

fn seal_items(password: &str, data: &BackupData, version: u32, context: &[u8]) -> Result<Zeroizing<String>> {
    let kdf = backup_kdf();
    let salt = random_array::<16>()?;
    let key = derive_key(password, salt.as_ref(), &kdf)?;
    let json = Zeroizing::new(serde_json::to_vec(data)?);
    let file = BackupFile {
        format: FORMAT.into(),
        version,
        kdf,
        salt: URL_SAFE_NO_PAD.encode(salt.as_ref()),
        data: key.seal_padded(&json, context)?,
    };
    Ok(Zeroizing::new(serde_json::to_string_pretty(&file)?))
}

fn open_items(password: &str, contents: &[u8], version: u32, context: &[u8]) -> Result<BackupData> {
    let file: BackupFile =
        serde_json::from_slice(contents).map_err(|_| Error::Import("this is not a Keyless backup file".into()))?;
    if file.format != FORMAT || file.version != version {
        return Err(Error::Import("unsupported backup version".into()));
    }
    let salt = URL_SAFE_NO_PAD
        .decode(&file.salt)
        .map_err(|_| Error::Import("damaged backup file".into()))?;
    if salt.len() != 16 {
        return Err(Error::Import("damaged backup file".into()));
    }
    let key = derive_key(password, &salt, &file.kdf)?;
    let json = key.open_padded(&file.data, context)?;
    Ok(serde_json::from_slice(&json)?)
}

/// Writes a backup: the attached files first, as they are downloaded, then
/// the items.
pub struct BackupWriter<W: Write + Seek> {
    zip: zip::ZipWriter<W>,
    /// Attachments whose files are written whole.
    written: HashSet<String>,
    /// The file being written.
    current: Option<String>,
}

impl<W: Write + Seek> BackupWriter<W> {
    pub fn new(out: W) -> Self {
        Self { zip: zip::ZipWriter::new(out), written: HashSet::new(), current: None }
    }

    fn fail(e: impl std::fmt::Display) -> Error {
        Error::Import(format!("could not write the backup: {e}"))
    }

    /// Starts `attachment`'s file. Its chunks follow, as the server keeps
    /// them; [`BackupWriter::end_file`] or [`BackupWriter::abort_file`] ends
    /// it.
    pub fn start_file(&mut self, attachment: &Attachment) -> Result<()> {
        // Entry names come from attachment ids: only ids Keyless makes.
        uuid::Uuid::parse_str(&attachment.id).map_err(|_| Self::fail("an attachment has an invalid id"))?;
        let sealed = attachment.size + attachment.chunks() as u64 * CHUNK_OVERHEAD as u64;
        let options = SimpleFileOptions::default()
            .compression_method(CompressionMethod::Stored)
            .large_file(sealed >= u32::MAX as u64);
        self.zip.start_file(format!("files/{}", attachment.id), options).map_err(Self::fail)?;
        self.current = Some(attachment.id.clone());
        Ok(())
    }

    pub fn write_chunk(&mut self, sealed: &[u8]) -> Result<()> {
        self.zip.write_all(sealed).map_err(Self::fail)
    }

    /// The file started last is complete.
    pub fn end_file(&mut self) {
        if let Some(id) = self.current.take() {
            self.written.insert(id);
        }
    }

    /// Leaves out the file being written (it could not be read whole), if
    /// one is (the zip writer would otherwise drop the one before).
    pub fn abort_file(&mut self) -> Result<()> {
        match self.current.take() {
            Some(_) => self.zip.abort_file().map_err(Self::fail),
            None => Ok(()),
        }
    }

    /// Writes the items, encrypted with `password`, and ends the archive.
    /// Every attachment they list must have its file written.
    pub fn finish(mut self, password: &str, data: &BackupData) -> Result<W> {
        let listed = data.vaults.iter().flat_map(|v| &v.items).flat_map(|i| &i.details.attachments);
        if listed.into_iter().any(|a| !self.written.contains(&a.id)) {
            return Err(Self::fail("an attached file is missing"));
        }
        let items = seal_items(password, data, VERSION, CONTEXT)?;
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        self.zip.start_file(ITEMS_ENTRY, options).map_err(Self::fail)?;
        self.zip.write_all(items.as_bytes()).map_err(Self::fail)?;
        self.zip.finish().map_err(Self::fail)
    }
}

/// A backup opened with its password.
pub struct OpenedBackup {
    pub data: BackupData,
    /// The archive's attached files and their sizes (none in version 1).
    files: HashMap<String, u64>,
}

/// Opens a backup of either version. Fails with [`Error::Decryption`] on a
/// wrong password or a modified file. Attached files are read when the
/// import is confirmed (see [`crate::import::ImportArchive`]).
pub fn open_backup<R: Read + Seek>(password: &str, mut reader: R) -> Result<OpenedBackup> {
    let mut magic = [0u8; 4];
    let is_zip = reader.read_exact(&mut magic).is_ok() && magic == *b"PK\x03\x04";
    reader.rewind().map_err(|e| Error::Import(e.to_string()))?;
    if !is_zip {
        let mut contents = Zeroizing::new(Vec::new());
        reader
            .take(MAX_BACKUP_BYTES as u64 + 1)
            .read_to_end(&mut contents)
            .map_err(|e| Error::Import(e.to_string()))?;
        if contents.len() > MAX_BACKUP_BYTES {
            return Err(Error::Import("the backup is too large".into()));
        }
        let data = open_items(password, &contents, 1, V1_CONTEXT)?;
        return Ok(OpenedBackup { data, files: HashMap::new() });
    }

    let not_backup = || Error::Import("this is not a Keyless backup file".into());
    let mut archive = zip::ZipArchive::new(reader).map_err(|_| not_backup())?;
    let mut files = HashMap::new();
    for index in 0..archive.len() {
        if let Ok(file) = archive.by_index_raw(index)
            && file.is_file()
            && let Some(id) = file.name().strip_prefix("files/")
        {
            files.insert(id.to_string(), file.size());
        }
    }
    let entry = archive.by_name(ITEMS_ENTRY).map_err(|_| not_backup())?;
    let mut contents = Zeroizing::new(Vec::new());
    entry
        .take(MAX_BACKUP_BYTES as u64 + 1)
        .read_to_end(&mut contents)
        .map_err(|e| Error::Import(e.to_string()))?;
    if contents.len() > MAX_BACKUP_BYTES {
        return Err(Error::Import("the backup is too large".into()));
    }
    let data = open_items(password, &contents, VERSION, CONTEXT)?;
    Ok(OpenedBackup { data, files })
}

impl OpenedBackup {
    /// The items to import. Their attachments become files to read from the
    /// archive (each gets a new id and key when uploaded); those whose file
    /// is not in it are left out, with a warning.
    pub fn into_import(self) -> ImportResult {
        let mut missing = 0;
        let vaults = self
            .data
            .vaults
            .into_iter()
            .map(|v| ImportedVault {
                name: v.name,
                items: v
                    .items
                    .into_iter()
                    .map(|mut i| {
                        let mut files = Vec::new();
                        for attachment in std::mem::take(&mut i.details.attachments) {
                            let sealed = attachment.size + attachment.chunks() as u64 * CHUNK_OVERHEAD as u64;
                            if self.files.get(&attachment.id) != Some(&sealed) {
                                missing += 1;
                                continue;
                            }
                            files.push(ImportedFile {
                                name: attachment.name.clone(),
                                size: attachment.size,
                                entry: format!("files/{}", attachment.id),
                                sealed: Some(attachment),
                            });
                        }
                        ImportedItem { overview: i.overview, details: i.details, files }
                    })
                    .collect(),
            })
            .collect();
        let warnings = if missing > 0 { vec![ImportWarning::new("files_missing", missing)] } else { Vec::new() };
        ImportResult { vaults, warnings }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::{
        attachment::CHUNK_SIZE,
        import::ImportArchive,
        item::{Category, Field, FieldKind, FieldPurpose},
    };

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

    /// A backup of `data`, with the files of `attachments` (and their
    /// contents) written.
    fn backup(data: &BackupData, files: &[(&Attachment, &[u8])]) -> Vec<u8> {
        let mut writer = BackupWriter::new(Cursor::new(Vec::new()));
        for (attachment, contents) in files {
            let key = attachment.key().unwrap();
            writer.start_file(attachment).unwrap();
            for index in 0..attachment.chunks() {
                let start = index as usize * CHUNK_SIZE;
                let chunk = &contents[start..start + attachment.chunk_len(index)];
                writer.write_chunk(&attachment.seal_chunk(&key, index, chunk).unwrap()).unwrap();
            }
            writer.end_file();
        }
        writer.finish("backup password 1", data).unwrap().into_inner()
    }

    #[test]
    fn roundtrip() {
        let file = backup(&sample(), &[]);
        let mut archive = zip::ZipArchive::new(Cursor::new(&file)).unwrap();
        let mut items = String::new();
        archive.by_name(ITEMS_ENTRY).unwrap().read_to_string(&mut items).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&items).unwrap();
        assert_eq!(parsed["kdf"]["m"], 256 * 1024);
        let text = String::from_utf8_lossy(&file);
        assert!(!text.contains("s3cret") && !text.contains("Example"));
        let restored = open_backup("backup password 1", Cursor::new(&file)).unwrap();
        assert_eq!(restored.data.vaults[0].items[0].details.password(), Some("s3cret"));
        let import = restored.into_import();
        assert_eq!(import.summary().total_items, 1);
    }

    #[test]
    fn keeps_attached_files() {
        let mut data = sample();
        let contents: Vec<u8> = (0..CHUNK_SIZE + 10).map(|i| (i % 251) as u8).collect();
        let big = Attachment::new("scan.pdf", contents.len() as u64, 1).unwrap();
        let empty = Attachment::new("empty.txt", 0, 1).unwrap();
        data.vaults[0].items[0].details.attachments = vec![big.clone(), empty.clone()];
        let file = backup(&data, &[(&big, &contents), (&empty, b"")]);
        assert!(!String::from_utf8_lossy(&file).contains("scan.pdf"));

        let import = open_backup("backup password 1", Cursor::new(&file)).unwrap().into_import();
        assert!(import.warnings.is_empty());
        let item = &import.vaults[0].items[0];
        assert!(item.details.attachments.is_empty());
        assert_eq!(item.files.len(), 2);
        assert_eq!(import.summary().file_bytes, contents.len() as u64);

        let mut archive = ImportArchive::open(Cursor::new(&file)).unwrap();
        let mut read = Vec::new();
        archive
            .read_file(&item.files[0], |chunk| {
                read.extend_from_slice(&chunk);
                Ok(())
            })
            .unwrap();
        assert_eq!(read, contents);
        let mut chunks = 0;
        archive
            .read_file(&item.files[1], |chunk| {
                chunks += 1;
                assert!(chunk.is_empty());
                Ok(())
            })
            .unwrap();
        assert_eq!(chunks, 1);
    }

    #[test]
    fn swapped_files_do_not_open() {
        let mut data = sample();
        let a = Attachment::new("a.txt", 3, 1).unwrap();
        let b = Attachment::new("b.txt", 3, 1).unwrap();
        data.vaults[0].items[0].details.attachments = vec![a.clone(), b.clone()];
        let file = backup(&data, &[(&a, b"aaa"), (&b, b"bbb")]);
        let mut archive = ImportArchive::open(Cursor::new(&file)).unwrap();
        let swapped = ImportedFile { name: "a.txt".into(), size: 3, entry: format!("files/{}", b.id), sealed: Some(a) };
        assert!(archive.read_file(&swapped, |_| Ok(())).is_err());
    }

    #[test]
    fn files_not_written_are_refused_or_reported() {
        let mut data = sample();
        let attachment = Attachment::new("a.txt", 3, 1).unwrap();
        data.vaults[0].items[0].details.attachments = vec![attachment.clone()];
        // Listed but not written: the writer refuses.
        let writer = BackupWriter::new(Cursor::new(Vec::new()));
        assert!(writer.finish("backup password 1", &data).is_err());
        // Started but abandoned: still refused.
        let mut writer = BackupWriter::new(Cursor::new(Vec::new()));
        writer.start_file(&attachment).unwrap();
        writer.write_chunk(b"partial").unwrap();
        writer.abort_file().unwrap();
        assert!(writer.finish("backup password 1", &data).is_err());

        // A version 1 backup has no files: they are reported missing.
        let v1 = seal_items("backup password 1", &data, 1, V1_CONTEXT).unwrap();
        let import = open_backup("backup password 1", Cursor::new(v1.as_bytes())).unwrap().into_import();
        assert_eq!(import.warnings, vec![ImportWarning::new("files_missing", 1)]);
        assert!(import.vaults[0].items[0].files.is_empty());
        assert!(import.vaults[0].items[0].details.attachments.is_empty());
    }

    #[test]
    fn wrong_password_or_tampering_fails() {
        let file = backup(&sample(), &[]);
        assert!(matches!(open_backup("backup password 2", Cursor::new(&file)), Err(Error::Decryption)));

        // The item list of a version 2 backup does not open as version 1.
        let mut archive = zip::ZipArchive::new(Cursor::new(&file)).unwrap();
        let mut items = String::new();
        archive.by_name(ITEMS_ENTRY).unwrap().read_to_string(&mut items).unwrap();
        let mut parsed: serde_json::Value = serde_json::from_str(&items).unwrap();
        parsed["version"] = serde_json::json!(1);
        assert!(open_backup("backup password 1", Cursor::new(serde_json::to_vec(&parsed).unwrap())).is_err());

        let v1 = seal_items("backup password 1", &sample(), 1, V1_CONTEXT).unwrap();
        let mut parsed: serde_json::Value = serde_json::from_str(&v1).unwrap();
        parsed["kdf"]["m"] = serde_json::json!(1024);
        let weakened = serde_json::to_vec(&parsed).unwrap();
        assert!(open_backup("backup password 1", Cursor::new(weakened)).is_err());

        assert!(open_backup("x", Cursor::new(b"not json".to_vec())).is_err());
    }
}
