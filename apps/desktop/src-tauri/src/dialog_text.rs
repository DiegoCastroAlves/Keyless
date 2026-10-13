//! The words of the system's file dialogs. The page sends them in the user's
//! language with each command that opens one, so none is fixed here.

use serde::Deserialize;
use tauri::Runtime;
use tauri_plugin_dialog::FileDialogBuilder;

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DialogText {
    pub title: String,
    /// What the files asked for are called ("Images"), shown with the
    /// extensions.
    pub filter: String,
}

impl DialogText {
    /// The dialog with this title, showing only files with `extensions`
    /// (when there are any).
    pub fn apply<R: Runtime>(&self, dialog: FileDialogBuilder<R>, extensions: &[&str]) -> FileDialogBuilder<R> {
        let dialog = if self.title.is_empty() { dialog } else { dialog.set_title(&self.title) };
        if extensions.is_empty() {
            dialog
        } else {
            let name = if self.filter.is_empty() { extensions.join(", ") } else { self.filter.clone() };
            dialog.add_filter(name, extensions)
        }
    }
}
