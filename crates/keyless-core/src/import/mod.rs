//! Importers from other password managers. Importers only parse; the client
//! encrypts the result and decides which vaults to put it in.

pub mod bitwarden;
pub mod csv;
pub mod dashlane;
pub mod decrypt;
pub mod kdbx;
pub mod keeper;
pub mod keyless;
pub mod onepif;
pub mod onepux;
pub mod reconcile;

use std::io::{Read, Seek};

use serde::Serialize;
use zeroize::Zeroizing;

use crate::{
    Error, Result,
    attachment::{Attachment, CHUNK_OVERHEAD},
    item::{FieldKind, ItemDetails, ItemOverview},
};

/// Refuse to read more than this for a single attached file.
pub const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024 * 1024;

pub struct ImportedItem {
    /// The item's id in Keyless, given here so that items can refer to one
    /// another (related items, the login a "sign in with" account uses).
    pub id: String,
    /// Its id in the file, if it has one (see `ImportResult::link`).
    pub source_id: String,
    pub overview: ItemOverview,
    pub details: ItemDetails,
    /// Files to attach, read from the import file once the import is
    /// confirmed.
    pub files: Vec<ImportedFile>,
}

impl ImportedItem {
    pub fn new(source_id: impl Into<String>, overview: ItemOverview, details: ItemDetails, files: Vec<ImportedFile>) -> Self {
        Self { id: uuid::Uuid::new_v4().to_string(), source_id: source_id.into(), overview, details, files }
    }
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
    /// Next to the account's items (see `reconcile`); all new until compared.
    #[serde(flatten)]
    pub counts: reconcile::Counts,
    /// New items in each of `vaults`.
    pub vault_new: Vec<usize>,
    /// The account's vault that has most of each of `vaults`' items already
    /// (`reconcile::Plan::homes`): where its new items go by default.
    pub vault_home: Vec<Option<String>>,
}

impl ImportResult {
    /// Points the items' links (related items, "sign in with" accounts) from
    /// their ids in the file to the new ones; a link to an item that is not
    /// in the import goes.
    pub fn link(mut self) -> Self {
        let ids: std::collections::HashMap<String, String> = self
            .vaults
            .iter()
            .flat_map(|v| &v.items)
            .filter(|i| !i.source_id.is_empty())
            .map(|i| (i.source_id.clone(), i.id.clone()))
            .collect();
        for item in self.vaults.iter_mut().flat_map(|v| v.items.iter_mut()) {
            let details = &mut item.details;
            for field in details.fields.iter_mut().chain(details.sections.iter_mut().flat_map(|s| s.fields.iter_mut())) {
                if field.kind == FieldKind::Reference {
                    field.value = ids.get(field.value.trim()).cloned().unwrap_or_default();
                }
                if !field.extra.link.is_empty() {
                    field.extra.link = ids.get(&field.extra.link).cloned().unwrap_or_default();
                }
            }
            let dangling = |f: &crate::item::Field| f.kind == FieldKind::Reference && f.value.is_empty();
            details.fields.retain(|f| !dangling(f));
            for section in &mut details.sections {
                section.fields.retain(|f| !dangling(f));
            }
        }
        self
    }

    pub fn summary(&self) -> ImportSummary {
        let files = || self.vaults.iter().flat_map(|v| &v.items).flat_map(|i| &i.files);
        ImportSummary {
            vaults: self.vaults.iter().map(|v| (v.name.clone(), v.items.len())).collect(),
            total_items: self.vaults.iter().map(|v| v.items.len()).sum(),
            files: files().count(),
            file_bytes: files().map(|f| f.size).sum(),
            warnings: self.warnings.clone(),
            counts: reconcile::Counts { new_items: self.vaults.iter().map(|v| v.items.len()).sum(), ..Default::default() },
            vault_new: self.vaults.iter().map(|v| v.items.len()).collect(),
            vault_home: vec![None; self.vaults.len()],
        }
    }

    /// The summary, with what `plan` found among the account's items.
    pub fn summary_with(&self, plan: &reconcile::Plan) -> ImportSummary {
        ImportSummary { counts: plan.counts(), vault_new: plan.new_by_vault(), vault_home: plan.homes.clone(), ..self.summary() }
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
