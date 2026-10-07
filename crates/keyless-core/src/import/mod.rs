//! Importers from other password managers. Importers only parse; the client
//! encrypts the result and decides which vaults to put it in.

pub mod csv;
pub mod onepux;

use std::io::{Read, Seek};

use serde::Serialize;
use zeroize::Zeroizing;

use crate::{
    Error, Result,
    attachment::{Attachment, CHUNK_OVERHEAD},
    item::{ItemDetails, ItemOverview},
};

/// Refuse to read more than this for a single attached file.
pub const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024 * 1024;

pub struct ImportedItem {
    pub overview: ItemOverview,
    pub details: ItemDetails,
    /// Files to attach, read from the import file once the import is
    /// confirmed.
    pub files: Vec<ImportedFile>,
}

/// A file that goes with an imported item, in a zip archive (a 1Password
/// export or a Keyless backup).
#[derive(Clone)]
pub struct ImportedFile {
    pub name: String,
    pub size: u64,
    /// The archive entry that holds it.
    pub entry: String,
    /// For a Keyless backup, the attachment it was: the entry holds its
    /// chunks encrypted as they were on the server. Otherwise the entry holds
    /// the file as it is.
    pub sealed: Option<Attachment>,
}

pub struct ImportedVault {
    pub name: String,
    pub items: Vec<ImportedItem>,
}

pub struct ImportResult {
    pub vaults: Vec<ImportedVault>,
    pub warnings: Vec<ImportWarning>,
}

/// Something the user should know about an import, shown in their language.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImportWarning {
    /// `item_skipped`, `row_skipped`, `rows_limited` or `files_missing`.
    pub code: &'static str,
    /// How many (the row for `row_skipped`, the limit for `rows_limited`).
    pub n: usize,
}

impl ImportWarning {
    pub fn new(code: &'static str, n: usize) -> Self {
        Self { code, n }
    }
}

/// Counts shown to the user before confirming an import.
#[derive(Debug, Serialize)]
pub struct ImportSummary {
    pub vaults: Vec<(String, usize)>,
    pub total_items: usize,
    pub files: usize,
    pub file_bytes: u64,
    pub warnings: Vec<ImportWarning>,
}

impl ImportResult {
    pub fn summary(&self) -> ImportSummary {
        let files = || self.vaults.iter().flat_map(|v| &v.items).flat_map(|i| &i.files);
        ImportSummary {
            vaults: self.vaults.iter().map(|v| (v.name.clone(), v.items.len())).collect(),
            total_items: self.vaults.iter().map(|v| v.items.len()).sum(),
            files: files().count(),
            file_bytes: files().map(|f| f.size).sum(),
            warnings: self.warnings.clone(),
        }
    }
}

/// The zip archive an import came from, to read its files.
pub struct ImportArchive<R: Read + Seek>(zip::ZipArchive<R>);

impl<R: Read + Seek> ImportArchive<R> {
    pub fn open(reader: R) -> Result<Self> {
        zip::ZipArchive::new(reader).map(Self).map_err(|e| Error::Import(format!("not a valid archive: {e}")))
    }

    /// Reads `file` in the chunks a new attachment of its size has
    /// ([`Attachment::chunk_len`]), checking it is exactly as the import
    /// listed it; a backup's chunks are decrypted. Stops at the first error
    /// `each` returns.
    pub fn read_file(&mut self, file: &ImportedFile, mut each: impl FnMut(Zeroizing<Vec<u8>>) -> Result<()>) -> Result<()> {
        let damaged = || Error::Import(format!("{} is missing or damaged in the import file", file.name));
        if file.size > MAX_FILE_BYTES {
            return Err(damaged());
        }
        // Zeroizing types cannot be built with `..Default::default()`.
        let mut shape = Attachment::default();
        shape.size = file.size;
        let sealed = match &file.sealed {
            Some(attachment) if attachment.size == file.size => Some((attachment, attachment.key()?)),
            Some(_) => return Err(damaged()),
            None => None,
        };
        let mut entry = self.0.by_name(&file.entry).map_err(|_| damaged())?;
        for index in 0..shape.chunks() {
            let len = shape.chunk_len(index);
            let chunk = match &sealed {
                Some((attachment, key)) => {
                    let mut raw = vec![0u8; len + CHUNK_OVERHEAD];
                    entry.read_exact(&mut raw).map_err(|_| damaged())?;
                    attachment.open_chunk(key, index, &raw).map_err(|_| damaged())?
                }
                None => {
                    let mut plain = Zeroizing::new(vec![0u8; len]);
                    entry.read_exact(&mut plain).map_err(|_| damaged())?;
                    plain
                }
            };
            each(chunk)?;
        }
        // Nothing may follow.
        if entry.read(&mut [0u8; 1]).map_err(|_| damaged())? != 0 {
            return Err(damaged());
        }
        Ok(())
    }
}
