//! Sentinel for developers: secrets left in files on this computer. It looks
//! in `.env` files (outside hidden folders, dependency folders and the like),
//! in the usual credential files (`~/.git-credentials`, `~/.npmrc`,
//! `~/.aws/credentials`…), and at the SSH private keys in `~/.ssh`: keys
//! without a passphrase, of an outdated type (DSA) or too short (RSA under
//! 2048 bits), and keys already saved in a Keyless SSH key item (compared by
//! fingerprint), whose copy on disk is not needed. What it finds can be
//! saved in Keyless, after which the file can go to the trash. It only runs
//! when the user asks, reads at most a few hundred kilobytes per file, and
//! never sends anything anywhere (no secret is ever tried against its
//! service).

use std::{
    collections::{BTreeSet, HashMap},
    path::{Path, PathBuf},
    sync::Mutex,
    time::{Duration, Instant},
};

use keyless_core::item::{Category, Field, FieldKind, FieldPurpose, new_field_id};
use serde::Serialize;
use sha2::{Digest, Sha256};
use ssh_key::{HashAlg, PrivateKey, PublicKey, public::KeyData};
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

/// One finding: a secret, or an SSH key that needs attention.
#[derive(Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    /// Stable for the same secret in the same place.
    pub id: String,
    /// The format's id ("github_token"…), "ssh_key" or "secret_variable".
    pub format: String,
    /// What it is, for the UI to word: "token", "key", "secret", "webhook",
    /// "webhook_secret", "private_key", "database_password",
    /// "url_password", "jwt", "secret_variable", or for SSH keys: "ssh_key"
    /// (no passphrase), "ssh_key_outdated" (DSA), "ssh_key_short" (RSA
    /// under 2048 bits) or "ssh_key_saved" (already in Keyless).
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
    /// A key too short: its length in bits.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bits: Option<u32>,
    /// A key already saved in Keyless: the item it is in.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub saved_in: Option<SavedKey>,
    /// A key without a passphrase: the command that adds one, to copy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
}

/// An SSH key item.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SavedKey {
    pub item_id: String,
    pub title: String,
}

/// The SSH keys saved in Keyless: fingerprint (SHA-256) -> its item.
type SavedKeys = HashMap<String, SavedKey>;

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
                ..Default::default()
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
                ..Default::default()
            });
        }
    }
}

/// RSA keys shorter than this are too short.
const MIN_RSA_BITS: u32 = 2048;

/// Why an SSH key should be replaced.
#[derive(Debug, PartialEq)]
enum WeakKey {
    /// DSA: outdated, and refused by current OpenSSH.
    Dsa,
    /// RSA shorter than 2048 bits: its length.
    ShortRsa(u32),
}

fn weak_key(key: &KeyData) -> Option<WeakKey> {
    match key {
        KeyData::Dsa(_) => Some(WeakKey::Dsa),
        KeyData::Rsa(rsa) => {
            let n = rsa.n.as_positive_bytes().unwrap_or_default();
            let bits = n.first().map_or(0, |first| n.len() as u32 * 8 - first.leading_zeros());
            (bits < MIN_RSA_BITS).then_some(WeakKey::ShortRsa(bits))
        }
        _ => None,
    }
}

/// What a private key file tells without its passphrase.
struct KeyFile {
    /// The key, when the file has no passphrase.
    open: Option<PrivateKey>,
    /// The public key of the private key in the file itself: the key, or
    /// what an OpenSSH key keeps in clear beside its encrypted part. Only
    /// this says which key the file holds (whether Keyless has it).
    own: Option<PublicKey>,
    /// A public key to describe it with: its own, or else the `.pub` file
    /// beside it (an older encrypted key keeps none in clear). Unverified:
    /// good for a warning, never for "already saved".
    public: Option<PublicKey>,
    weak: Option<WeakKey>,
}

/// The public key a private key text holds without its passphrase: from the
/// key when it has none, or the part an OpenSSH key keeps in clear.
fn own_public_key(text: &str) -> Option<PublicKey> {
    // OpenSSH keys say whether they are encrypted only once parsed.
    let open = if text.contains("ENCRYPTED") { None } else { crate::ssh_keys::parse_private(text, None).ok() };
    match open {
        Some(key) => Some(key.public_key().clone()),
        None => PrivateKey::from_openssh(crate::ssh_keys::normalize_pem(text).as_bytes()).ok().map(|key| key.public_key().clone()),
    }
}

fn key_file(path: &Path, text: &str) -> KeyFile {
    let open = if text.contains("ENCRYPTED") { None } else { crate::ssh_keys::parse_private(text, None).ok() };
    let own = match &open {
        Some(key) => Some(key.public_key().clone()),
        None => PrivateKey::from_openssh(crate::ssh_keys::normalize_pem(text).as_bytes()).ok().map(|key| key.public_key().clone()),
    };
    let public = own.clone().or_else(|| {
        let mut pub_path = path.as_os_str().to_owned();
        pub_path.push(".pub");
        read_small(Path::new(&pub_path)).and_then(|text| PublicKey::from_openssh(text.trim()).ok())
    });
    let weak = match &public {
        Some(public) => weak_key(public.key_data()),
        // Old PEM keys with no public key beside them.
        None if text.contains("BEGIN DSA PRIVATE KEY") => Some(WeakKey::Dsa),
        None if text.contains("BEGIN RSA PRIVATE KEY") && !text.contains("ENCRYPTED") => {
            use rsa::{pkcs1::DecodeRsaPrivateKey, traits::PublicKeyParts};
            let bits = rsa::RsaPrivateKey::from_pkcs1_pem(&crate::ssh_keys::normalize_pem(text)).ok().map(|key| key.n().bits() as u32);
            bits.filter(|bits| *bits < MIN_RSA_BITS).map(WeakKey::ShortRsa)
        }
        None => None,
    };
    KeyFile { open, own, public, weak }
}

/// The command that adds a passphrase to a key file (`ssh-keygen` asks for
/// it), for the user to copy and run; the path quoted for the shell when it
/// needs to be.
fn passphrase_command(path: &str, windows: bool) -> String {
    format!("ssh-keygen -p -f {}", if windows { powershell_quote(path) } else { posix_quote(path) })
}

/// A path for PowerShell (the Windows terminal's shell): in single quotes,
/// where nothing expands (`$`, backticks; `,` would split it), with `'`
/// doubled; plain when it has only letters, digits and `\:._-`.
fn powershell_quote(path: &str) -> String {
    let plain = |c: char| c.is_ascii_alphanumeric() || "\\:._-".contains(c);
    if !path.is_empty() && path.chars().all(plain) {
        return path.to_string();
    }
    format!("'{}'", path.replace('\'', "''"))
}

/// A path for bash, zsh and fish alike: runs of ordinary characters in
/// single quotes, and `'` and `\` outside them, escaped with a backslash
/// (fish reads `\\` and `\'` as escapes even inside single quotes); plain
/// when it has only letters, digits and `/._-+,@`.
fn posix_quote(path: &str) -> String {
    let plain = |c: char| c.is_ascii_alphanumeric() || "/._-+,@".contains(c);
    if !path.is_empty() && path.chars().all(plain) {
        return path.to_string();
    }
    let mut out = String::new();
    let mut open = false;
    for c in path.chars() {
        if c == '\'' || c == '\\' {
            if open {
                out.push('\'');
                open = false;
            }
            out.push('\\');
        } else if !open {
            out.push('\'');
            open = true;
        }
        out.push(c);
    }
    if open {
        out.push('\'');
    }
    if out.is_empty() { "''".into() } else { out }
}

/// The fingerprints of the private keys an SSH key item holds. Only a
/// private key counts: an item with just a public key or a fingerprint
/// cannot stand in for the file.
fn item_fingerprints<'a>(fields: impl Iterator<Item = &'a Field>) -> BTreeSet<String> {
    fields
        .filter(|field| field.value.contains("-----BEGIN ") && field.value.contains("PRIVATE KEY-----"))
        .filter_map(|field| own_public_key(&field.value))
        .map(|public| public.fingerprint(HashAlg::Sha256).to_string())
        .collect()
}

/// The SSH keys in Keyless's SSH key items (not in Recently Deleted).
async fn saved_keys(state: &AppState) -> AppResult<SavedKeys> {
    let guard = state.session.lock().await;
    let session = guard.as_ref().ok_or(AppError::Locked)?;
    let store = state.store();
    let mut saved = SavedKeys::new();
    for (id, cached) in &session.items {
        let o = &cached.overview;
        if o.category != Category::SshKey || o.trashed_at.is_some() {
            continue;
        }
        let Ok(Some(local)) = store.item(id) else { continue };
        let (Some(enc), Ok(vault)) = (local.enc_details.as_deref(), session.vault(&local.vault_id)) else { continue };
        let Ok(details) = vault.key.open_details(&local.vault_id, id, enc) else { continue };
        for fingerprint in item_fingerprints(details.all_fields()) {
            saved.entry(fingerprint).or_insert_with(|| SavedKey { item_id: id.clone(), title: o.title.clone() });
        }
    }
    Ok(saved)
}

/// The private keys in `~/.ssh`: without a passphrase (anyone who reads the
/// file can use them), of an outdated type or too short, or already saved in
/// Keyless (the copy on disk is not needed). Returns how many files it read.
fn scan_ssh(home: &Path, saved: &SavedKeys, out: &mut Vec<Finding>) -> usize {
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
        if !text.contains("PRIVATE KEY-----") {
            continue;
        }
        let key = key_file(&path, &text);
        let fingerprint = |public: &Option<PublicKey>| public.as_ref().map(|public| public.fingerprint(HashAlg::Sha256).to_string());
        // Which key the file holds, from the file itself; to show, the
        // `.pub` file beside it will do.
        let (own, shown) = (fingerprint(&key.own), fingerprint(&key.public));
        let finding = |kind: &str| Finding {
            id: finding_id(&path, 0, kind, &text),
            format: kind.into(),
            kind: kind.into(),
            path: path.to_string_lossy().into_owned(),
            key: name.clone(),
            preview: shown.clone().unwrap_or_default(),
            ..Default::default()
        };
        if key.open.is_some() {
            out.push(Finding { command: Some(passphrase_command(&path.to_string_lossy(), cfg!(windows))), ..finding("ssh_key") });
        }
        match key.weak {
            Some(WeakKey::Dsa) => out.push(finding("ssh_key_outdated")),
            Some(WeakKey::ShortRsa(bits)) => out.push(Finding { bits: Some(bits), ..finding("ssh_key_short") }),
            None => {}
        }
        if let Some(item) = own.as_ref().and_then(|f| saved.get(f)) {
            out.push(Finding { saved_in: Some(item.clone()), ..finding("ssh_key_saved") });
        }
    }
    files
}

/// Looks for secrets under the home folder (blocking: run it on a thread).
fn scan_blocking(ignored: &BTreeSet<String>, saved: &SavedKeys) -> ScanResult {
    let mut findings = Vec::new();
    let mut files = 0;
    let mut walker = Walker { started: Instant::now(), entries: 0, partial: false };
    let home = home();
    if let Some(home) = &home {
        files += scan_ssh(home, saved, &mut findings);
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
    let saved = saved_keys(&state).await?;
    let result = tauri::async_runtime::spawn_blocking(move || scan_blocking(&ignored, &saved)).await.map_err(|e| AppError::Store(e.to_string()))?;
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
    // A key's other findings (outdated, short, saved) have nothing new to save.
    if finding.format.starts_with("ssh_key_") {
        return Err(AppError::Invalid(Msg::new("invalid_request")));
    }
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

    use ssh_key::{
        Algorithm, LineEnding, Mpint,
        public::{DsaPublicKey, RsaPublicKey},
        rand_core::OsRng,
    };

    fn rsa(modulus: &[u8]) -> KeyData {
        KeyData::Rsa(RsaPublicKey { e: Mpint::from_positive_bytes(&[1, 0, 1]).unwrap(), n: Mpint::from_positive_bytes(modulus).unwrap() })
    }

    fn dsa() -> KeyData {
        let n = |byte: u8| Mpint::from_positive_bytes(&[byte; 128]).unwrap();
        KeyData::Dsa(DsaPublicKey { p: n(0xd1), q: n(0xd2), g: n(0x03), y: n(0x44) })
    }

    fn temp_home() -> PathBuf {
        let home = std::env::temp_dir().join(format!("keyless-dev-scan-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(home.join(".ssh")).unwrap();
        home
    }

    #[test]
    fn ssh_key_strength() {
        assert_eq!(weak_key(&dsa()), Some(WeakKey::Dsa));
        assert_eq!(weak_key(&rsa(&[0xc5; 128])), Some(WeakKey::ShortRsa(1024)));
        // One bit short of 2048.
        assert_eq!(weak_key(&rsa(&[0x45; 256])), Some(WeakKey::ShortRsa(2047)));
        assert_eq!(weak_key(&rsa(&[0xc5; 256])), None);
        assert_eq!(weak_key(&rsa(&[0xc5; 512])), None);
        let ed25519 = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        assert_eq!(weak_key(ed25519.public_key().key_data()), None);

        // Old PEM keys: by their header, or by the public key beside them.
        let home = temp_home();
        let pem = |kind: &str| format!("-----BEGIN {kind} PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nAAAA\n-----END {kind} PRIVATE KEY-----\n");
        assert_eq!(key_file(&home.join(".ssh/id_dsa"), &pem("DSA")).weak, Some(WeakKey::Dsa));
        let id_rsa = home.join(".ssh/id_rsa");
        assert_eq!(key_file(&id_rsa, &pem("RSA")).weak, None);
        std::fs::write(home.join(".ssh/id_rsa.pub"), PublicKey::new(rsa(&[0xc5; 96]), "old").to_openssh().unwrap()).unwrap();
        let old = key_file(&id_rsa, &pem("RSA"));
        assert_eq!(old.weak, Some(WeakKey::ShortRsa(768)));
        assert!(old.open.is_none());
        std::fs::remove_dir_all(&home).unwrap();
    }

    #[test]
    fn keys_already_saved() {
        let home = temp_home();
        let ssh = home.join(".ssh");
        let field = |value: &str| Field { id: "f".into(), label: "key".into(), kind: FieldKind::Concealed, value: value.into(), purpose: None, extra: Default::default() };
        let mut saved = SavedKeys::new();
        let mut save = |id: &str, fields: Vec<Field>| {
            for fingerprint in item_fingerprints(fields.iter()) {
                saved.insert(fingerprint, SavedKey { item_id: id.into(), title: id.to_uppercase() });
            }
        };
        // Without a passphrase, its private key in an item.
        let in_item = crate::ssh_keys::generate("saved").unwrap();
        std::fs::write(ssh.join("id_saved"), &in_item.private_key).unwrap();
        std::fs::write(ssh.join("id_saved.pub"), &in_item.public_key).unwrap();
        save("a", vec![field(&in_item.private_key)]);
        // With a passphrase: its public part is in the file, in clear.
        let protected = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        std::fs::write(ssh.join("id_protected"), protected.encrypt(&mut OsRng, "correct horse").unwrap().to_openssh(LineEnding::LF).unwrap()).unwrap();
        save("b", vec![field(&protected.to_openssh(LineEnding::LF).unwrap())]);
        // Only its public key and fingerprint in an item: not a copy of it.
        let public_only = crate::ssh_keys::generate("public only").unwrap();
        std::fs::write(ssh.join("id_public_only"), &public_only.private_key).unwrap();
        save("c", vec![field(&public_only.public_key), field(&public_only.fingerprint)]);
        // An older encrypted key: which key it holds is unknown without its
        // passphrase, whatever the `.pub` beside it says.
        let beside = crate::ssh_keys::generate("old").unwrap();
        std::fs::write(ssh.join("id_old"), "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nAAAA\n-----END RSA PRIVATE KEY-----\n").unwrap();
        std::fs::write(ssh.join("id_old.pub"), &beside.public_key).unwrap();
        save("d", vec![field(&beside.private_key)]);
        // Not in Keyless.
        std::fs::write(ssh.join("id_other"), crate::ssh_keys::generate("other").unwrap().private_key).unwrap();
        std::fs::write(ssh.join("known_hosts"), "github.com ssh-ed25519 AAAA").unwrap();

        assert!(item_fingerprints([field(&public_only.public_key), field(&public_only.fingerprint)].iter()).is_empty());
        let mut out = Vec::new();
        // known_hosts and public keys are not read.
        assert_eq!(scan_ssh(&home, &saved, &mut out), 5);
        let mut found: Vec<(&str, &str, Option<&str>)> = out.iter().map(|f| (f.key.as_str(), f.kind.as_str(), f.saved_in.as_ref().map(|s| s.item_id.as_str()))).collect();
        found.sort();
        assert_eq!(
            found,
            [
                ("id_other", "ssh_key", None),
                ("id_protected", "ssh_key_saved", Some("b")),
                ("id_public_only", "ssh_key", None),
                ("id_saved", "ssh_key", None),
                ("id_saved", "ssh_key_saved", Some("a")),
            ]
        );
        let unprotected = out.iter().find(|f| f.key == "id_saved" && f.kind == "ssh_key").unwrap();
        assert_eq!(unprotected.preview, in_item.fingerprint);
        assert!(unprotected.command.as_deref().unwrap().starts_with("ssh-keygen -p -f "));
        // Each finding of a file has its own id, so each can be ignored.
        assert_eq!(out.iter().map(|f| &f.id).collect::<BTreeSet<_>>().len(), out.len());
        std::fs::remove_dir_all(&home).unwrap();
    }

    #[test]
    fn passphrase_commands() {
        // bash, zsh and fish.
        assert_eq!(passphrase_command("/home/ana/.ssh/id_rsa", false), "ssh-keygen -p -f /home/ana/.ssh/id_rsa");
        assert_eq!(passphrase_command("/home/ana/my keys/id", false), "ssh-keygen -p -f '/home/ana/my keys/id'");
        assert_eq!(passphrase_command("/home/ana/it's/id", false), r"ssh-keygen -p -f '/home/ana/it'\''s/id'");
        assert_eq!(passphrase_command("/home/ana/$HOME/`x`/id", false), "ssh-keygen -p -f '/home/ana/$HOME/`x`/id'");
        assert_eq!(passphrase_command(r"/home/ana/a\b/id", false), r"ssh-keygen -p -f '/home/ana/a'\\'b/id'");
        // PowerShell: nothing expands in single quotes, and `,` stays inside.
        assert_eq!(passphrase_command(r"C:\Users\ana\.ssh\id_rsa", true), r"ssh-keygen -p -f C:\Users\ana\.ssh\id_rsa");
        assert_eq!(passphrase_command(r"C:\Users\Ana Maria\.ssh\id_rsa", true), r"ssh-keygen -p -f 'C:\Users\Ana Maria\.ssh\id_rsa'");
        assert_eq!(passphrase_command(r"C:\Users\O'Brien\$x,y`z\%TEMP%\id", true), r"ssh-keygen -p -f 'C:\Users\O''Brien\$x,y`z\%TEMP%\id'");
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
