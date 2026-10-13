//! Sentinel for developers: secrets left in files on this computer. It looks
//! in `.env` files (outside hidden folders, dependency folders and the like),
//! in the usual credential files (`~/.git-credentials`, `~/.npmrc`,
//! `~/.aws/credentials`…), and for SSH private keys without a passphrase in
//! `~/.ssh`. What it finds can be saved in Keyless, after which the file can
//! go to the trash. It only runs when the user asks, reads at most a few
//! hundred kilobytes per file, and never sends anything anywhere (no
//! secret is ever tried against its service).

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    sync::Mutex,
    time::{Duration, Instant},
};

use keyless_core::item::{Category, Field, FieldKind, FieldPurpose, new_field_id};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Manager};
use zeroize::Zeroizing;

use crate::{
    error::{AppError, AppResult, Msg},
    items::{self, ItemDraft, ItemSummary},
    secret_patterns,
    state::AppState,
};

/// Folders not looked into: dependencies, builds, caches, other systems'.
const SKIP_DIRS: [&str; 22] = [
    "node_modules", "target", "vendor", "dist", "build", "out", "__pycache__", "site-packages", "venv", "env", "bower_components", "Pods",
    "DerivedData", "AppData", "Library", "snap", "flatpak", "go", "pkg", "Trash", "lost+found", "proc",
];
/// How deep under the home folder.
const MAX_DEPTH: usize = 8;
/// Entries looked at, at most, and for how long.
const MAX_ENTRIES: usize = 400_000;
const MAX_TIME: Duration = Duration::from_secs(90);
/// Larger files are not read.
const MAX_FILE: u64 = 256 * 1024;
/// Credential files, under the home folder.
const CREDENTIAL_FILES: [&str; 8] =
    [".git-credentials", ".npmrc", ".pypirc", ".netrc", ".aws/credentials", ".docker/config.json", ".config/gh/hosts.yml", ".yarnrc.yml"];

/// One secret found.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    /// Stable for the same secret in the same place.
    pub id: String,
    /// The format's id ("github_token"…), "ssh_key" or "secret_variable".
    pub format: String,
    /// What it is, for the UI to word: "token", "key", "secret", "webhook",
    /// "webhook_secret", "private_key", "database_password",
    /// "url_password", "jwt", "ssh_key" or "secret_variable".
    pub kind: String,
    /// The service it is for ("GitHub"), when known.
    pub service: String,
    pub path: String,
    /// The path as shown: "~/…" under the home folder.
    pub shown_path: String,
    /// 1-based; 0 for a whole file (an SSH key).
    pub line: usize,
    /// The variable or setting that holds it, or the key's file name.
    pub key: String,
    /// The secret, mostly hidden ("ghp_…3kd"), or an SSH key's fingerprint.
    pub preview: String,
    pub ignored: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanResult {
    pub findings: Vec<Finding>,
    /// Files read.
    pub files: usize,
    /// The scan stopped early (too many files, or too long).
    pub partial: bool,
    pub formats: usize,
    /// Unix seconds.
    pub scanned_at: i64,
}

/// The last scan's findings, to act on.
static LAST: Mutex<Vec<Finding>> = Mutex::new(Vec::new());

fn home() -> Option<PathBuf> {
    std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).map(PathBuf::from).filter(|p| p.is_absolute())
}

fn finding_id(path: &Path, line: usize, kind: &str, value: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(path.to_string_lossy().as_bytes());
    hash.update([0]);
    hash.update(line.to_string().as_bytes());
    hash.update([0]);
    hash.update(kind.as_bytes());
    hash.update([0]);
    hash.update(Sha256::digest(value.as_bytes()));
    hex::encode(&hash.finalize()[..16])
}

/// A `.env` file, not one of the examples kept next to it.
fn is_env_file(name: &str) -> bool {
    let lower = name.to_lowercase();
    let example = [".example", ".sample", ".template", ".dist", ".defaults", ".tpl", ".schema"].iter().any(|s| lower.ends_with(s));
    !example && (lower == ".env" || lower.starts_with(".env.") || (lower.ends_with(".env") && lower.len() > 4))
}

/// Looks at every file it is given; finds the `.env` files to look at.
struct Walker {
    started: Instant,
    entries: usize,
    partial: bool,
}

impl Walker {
    fn env_files(&mut self, root: &Path) -> Vec<PathBuf> {
        let mut found = Vec::new();
        let mut stack = vec![(root.to_path_buf(), 0usize)];
        while let Some((dir, depth)) = stack.pop() {
            let Ok(read) = std::fs::read_dir(&dir) else { continue };
            for entry in read.flatten() {
                self.entries += 1;
                if self.entries > MAX_ENTRIES || self.started.elapsed() > MAX_TIME {
                    self.partial = true;
                    return found;
                }
                let Ok(kind) = entry.file_type() else { continue };
                let name = entry.file_name().to_string_lossy().into_owned();
                if kind.is_dir() {
                    if depth + 1 < MAX_DEPTH && !name.starts_with('.') && !SKIP_DIRS.contains(&name.as_str()) {
                        stack.push((entry.path(), depth + 1));
                    }
                } else if kind.is_file() && is_env_file(&name) {
                    found.push(entry.path());
                }
            }
        }
        found
    }
}

fn read_small(path: &Path) -> Option<Zeroizing<String>> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_FILE {
        return None;
    }
    String::from_utf8(std::fs::read(path).ok()?).ok().map(Zeroizing::new)
}

/// `NAME=value` (or `name = value`, `name: value`, `"name": "value"`), with
/// `export` and quotes taken off.
fn assignment(line: &str) -> Option<(&str, &str)> {
    let line = line.trim();
    if line.starts_with('#') || line.starts_with("//") {
        return None;
    }
    let line = line.strip_prefix("export ").unwrap_or(line);
    let at = line.find(['=', ':'])?;
    let name = line[..at].trim().trim_matches('"').trim_matches('\'');
    let value = line[at + 1..].trim().trim_end_matches(',');
    let value = value.strip_prefix('"').and_then(|v| v.strip_suffix('"')).or_else(|| value.strip_prefix('\'').and_then(|v| v.strip_suffix('\''))).unwrap_or(value);
    (!name.is_empty() && !name.contains(char::is_whitespace)).then_some((name, value))
}

/// The secrets in one text file.
fn scan_text(path: &Path, text: &str, out: &mut Vec<Finding>) {
    for (index, line) in text.lines().enumerate() {
        let number = index + 1;
        let (name, value) = assignment(line).unwrap_or(("", line));
        let found = secret_patterns::find(value);
        for secret in &found {
            // A private key in a variable is the whole value.
            let value = if secret.id == "private_key" { value } else { secret.value };
            out.push(Finding {
                id: finding_id(path, number, secret.id, value),
                format: secret.id.to_string(),
                kind: secret.kind.to_string(),
                service: secret.service.to_string(),
                path: path.to_string_lossy().into_owned(),
                shown_path: String::new(),
                line: number,
                key: name.to_string(),
                preview: secret_patterns::masked(value),
                ignored: false,
            });
        }
        if found.is_empty() && !name.is_empty() && secret_patterns::secret_variable(name, value) {
            out.push(Finding {
                id: finding_id(path, number, "secret_variable", value),
                format: "secret_variable".into(),
                kind: "secret_variable".into(),
                service: String::new(),
                path: path.to_string_lossy().into_owned(),
                shown_path: String::new(),
                line: number,
                key: name.to_string(),
                preview: secret_patterns::masked(value),
                ignored: false,
            });
        }
    }
}

/// Private keys in `~/.ssh` that anyone who reads the file can use. Returns
/// how many files it read.
fn scan_ssh(home: &Path, out: &mut Vec<Finding>) -> usize {
    let mut files = 0;
    let Ok(read) = std::fs::read_dir(home.join(".ssh")) else { return 0 };
    for entry in read.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.ends_with(".pub") || ["known_hosts", "known_hosts.old", "config", "authorized_keys"].contains(&name.as_str()) {
            continue;
        }
        let Some(text) = read_small(&path) else { continue };
        files += 1;
        if !text.contains("PRIVATE KEY-----") || text.contains("ENCRYPTED") {
            continue;
        }
        // OpenSSH keys say whether they are encrypted only once parsed.
        let Ok(key) = crate::ssh_keys::parse_private(&text, None) else { continue };
        out.push(Finding {
            id: finding_id(&path, 0, "ssh_key", &text),
            format: "ssh_key".into(),
            kind: "ssh_key".into(),
            service: String::new(),
            path: path.to_string_lossy().into_owned(),
            shown_path: String::new(),
            line: 0,
            key: name,
            preview: key.fingerprint(ssh_key::HashAlg::Sha256).to_string(),
            ignored: false,
        });
    }
    files
}

/// Looks for secrets under the home folder (blocking: run it on a thread).
fn scan_blocking(ignored: &BTreeSet<String>) -> ScanResult {
    let mut findings = Vec::new();
    let mut files = 0;
    let mut walker = Walker { started: Instant::now(), entries: 0, partial: false };
    let home = home();
    if let Some(home) = &home {
        files += scan_ssh(home, &mut findings);
        let credential_files = CREDENTIAL_FILES.iter().map(|f| home.join(f));
        for path in walker.env_files(home).into_iter().chain(credential_files) {
            if let Some(text) = read_small(&path) {
                files += 1;
                scan_text(&path, &text, &mut findings);
            }
        }
    }
    let mut seen = BTreeSet::new();
    findings.retain(|f| seen.insert(f.id.clone()));
    for finding in &mut findings {
        finding.ignored = ignored.contains(&finding.id);
        finding.shown_path = match home.as_ref().and_then(|h| Path::new(&finding.path).strip_prefix(h).ok()) {
            Some(rest) => format!("~{}{}", std::path::MAIN_SEPARATOR, rest.display()),
            None => finding.path.clone(),
        };
    }
    ScanResult { findings, files, partial: walker.partial, formats: secret_patterns::count(), scanned_at: crate::api::now_secs() }
}

const IGNORED_ROW: &str = "dev_ignored";

pub async fn scan(app: &AppHandle) -> AppResult<ScanResult> {
    let state = app.state::<AppState>();
    let ignored: BTreeSet<String> = crate::health::load_private(&state, IGNORED_ROW).await?.unwrap_or_default();
    let result = tauri::async_runtime::spawn_blocking(move || scan_blocking(&ignored)).await.map_err(|e| AppError::Store(e.to_string()))?;
    *LAST.lock().unwrap_or_else(|e| e.into_inner()) = result.findings.clone();
    state.touch();
    Ok(result)
}

fn last(id: &str) -> AppResult<Finding> {
    LAST.lock().unwrap_or_else(|e| e.into_inner()).iter().find(|f| f.id == id).cloned().ok_or(AppError::NotFound)
}

/// The secret again, read from its file now: it must still be the one found.
fn secret_of(finding: &Finding) -> AppResult<Zeroizing<String>> {
    let path = Path::new(&finding.path);
    let gone = || AppError::Invalid(Msg::new("dev_secret_changed"));
    let text = read_small(path).ok_or_else(gone)?;
    if finding.format == "ssh_key" {
        return (finding_id(path, 0, "ssh_key", &text) == finding.id).then_some(text).ok_or_else(gone);
    }
    let line = text.lines().nth(finding.line.wrapping_sub(1)).ok_or_else(gone)?;
    let (name, value) = assignment(line).unwrap_or(("", line));
    let candidates: Vec<&str> = if finding.format == "secret_variable" {
        (!name.is_empty()).then_some(value).into_iter().collect()
    } else {
        secret_patterns::find(value).into_iter().filter(|s| s.id == finding.format).map(|s| if s.id == "private_key" { value } else { s.value }).collect()
    };
    candidates
        .into_iter()
        .find(|value| finding_id(path, finding.line, &finding.format, value) == finding.id)
        .map(|value| Zeroizing::new(value.replace("\\n", "\n")))
        .ok_or_else(gone)
}

fn field(label: &str, kind: FieldKind, value: &str, purpose: Option<FieldPurpose>) -> Field {
    Field { id: new_field_id(), label: label.into(), kind, value: value.into(), purpose, extra: Default::default() }
}

/// Saves a finding as an item: an SSH key item for a key, an API credential
/// otherwise, noting where it was found. `label` is what the UI calls it.
pub async fn save(app: &AppHandle, id: &str, vault_id: &str, label: &str, notes: &str) -> AppResult<ItemSummary> {
    let finding = last(id)?;
    let secret = secret_of(&finding)?;
    let folder = Path::new(&finding.path).parent().and_then(|p| p.file_name()).map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let draft = if finding.format == "ssh_key" {
        let fields = crate::ssh_keys::import(&secret, None, &finding.key)?;
        ItemDraft {
            id: None,
            vault_id: vault_id.into(),
            title: finding.key.clone(),
            category: Category::SshKey,
            fields: vec![
                field("private key", FieldKind::Concealed, &fields.private_key, None),
                field("public key", FieldKind::Multiline, &fields.public_key, None),
                field("fingerprint", FieldKind::Text, &fields.fingerprint, None),
            ],
            notes: notes.into(),
            ..Default::default()
        }
    } else {
        let title = match (finding.key.is_empty(), folder.is_empty()) {
            (false, false) => format!("{} ({folder})", finding.key),
            (false, true) => finding.key.clone(),
            _ if !label.is_empty() => label.to_string(),
            _ => folder.clone(),
        };
        let mut fields = vec![field("credential", FieldKind::Concealed, &secret, Some(FieldPurpose::Password))];
        if !label.trim().is_empty() {
            fields.push(field("type", FieldKind::Text, label.trim(), None));
        }
        ItemDraft { id: None, vault_id: vault_id.into(), title, category: Category::ApiCredential, fields, notes: notes.into(), ..Default::default() }
    };
    items::save_item(app, draft).await
}

/// Moves the file a secret was found in to the system's trash.
pub fn trash(id: &str) -> AppResult<()> {
    let finding = last(id)?;
    trash::delete(&finding.path).map_err(|e| AppError::Invalid(Msg::new("dev_trash_failed").with("detail", e)))?;
    LAST.lock().unwrap_or_else(|e| e.into_inner()).retain(|f| f.path != finding.path);
    Ok(())
}

/// Shows the file in the system's file manager.
pub fn reveal(app: &AppHandle, id: &str) -> AppResult<()> {
    use tauri_plugin_opener::OpenerExt;
    let finding = last(id)?;
    app.opener().reveal_item_in_dir(&finding.path).map_err(|e| AppError::Store(e.to_string()))
}

/// Ignores a finding (or not), from now on.
pub async fn set_ignored(app: &AppHandle, id: &str, ignored: bool) -> AppResult<()> {
    let state = app.state::<AppState>();
    let mut set: BTreeSet<String> = crate::health::load_private(&state, IGNORED_ROW).await?.unwrap_or_default();
    if ignored {
        set.insert(id.to_string());
    } else {
        set.remove(id);
    }
    crate::health::save_private(&state, IGNORED_ROW, &set).await?;
    if let Some(finding) = LAST.lock().unwrap_or_else(|e| e.into_inner()).iter_mut().find(|f| f.id == id) {
        finding.ignored = ignored;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_files() {
        for name in [".env", ".env.local", ".env.production", "prod.env"] {
            assert!(is_env_file(name), "{name}");
        }
        for name in [".env.example", ".env.sample", ".env.template", "env", ".envrc", ".environment"] {
            assert!(!is_env_file(name), "{name}");
        }
    }

    #[test]
    fn assignments() {
        assert_eq!(assignment("export API_KEY=\"abc\""), Some(("API_KEY", "abc")));
        assert_eq!(assignment("token = 'x y'"), Some(("token", "x y")));
        assert_eq!(assignment("  \"auth\": \"value\","), Some(("auth", "value")));
        assert_eq!(assignment("# SECRET=nope"), None);
    }

    #[test]
    fn finds_secrets_in_a_file() {
        let token = ["gh", "p_", &"Z9y8".repeat(9)].concat();
        let text = format!("# config\nGITHUB_TOKEN={token}\nJWT_SECRET=q8Zr2Lm9Vx4Tb7Np\nAPP_SECRET=changeme\nPORT=3000\n");
        let mut out = Vec::new();
        scan_text(Path::new("/tmp/app/.env"), &text, &mut out);
        let kinds: Vec<(&str, usize, &str)> = out.iter().map(|f| (f.format.as_str(), f.line, f.key.as_str())).collect();
        assert_eq!(kinds, vec![("github_token", 2, "GITHUB_TOKEN"), ("secret_variable", 3, "JWT_SECRET")]);
        assert!(!out[0].preview.contains(&token[8..]));
    }
}
