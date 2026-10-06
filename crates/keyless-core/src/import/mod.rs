//! Importers from other password managers. Importers only parse; the client
//! encrypts the result and decides which vaults to put it in.

pub mod csv;
pub mod onepux;

use serde::Serialize;

use crate::item::{ItemDetails, ItemOverview};

pub struct ImportedItem {
    pub overview: ItemOverview,
    pub details: ItemDetails,
}

pub struct ImportedVault {
    pub name: String,
    pub items: Vec<ImportedItem>,
}

pub struct ImportResult {
    pub vaults: Vec<ImportedVault>,
    pub warnings: Vec<String>,
}

/// Counts shown to the user before confirming an import.
#[derive(Debug, Serialize)]
pub struct ImportSummary {
    pub vaults: Vec<(String, usize)>,
    pub total_items: usize,
    pub warnings: Vec<String>,
}

impl ImportResult {
    pub fn summary(&self) -> ImportSummary {
        ImportSummary {
            vaults: self.vaults.iter().map(|v| (v.name.clone(), v.items.len())).collect(),
            total_items: self.vaults.iter().map(|v| v.items.len()).sum(),
            warnings: self.warnings.clone(),
        }
    }
}
