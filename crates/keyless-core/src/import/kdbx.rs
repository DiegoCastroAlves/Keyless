//! KeePass databases (`.kdbx`, as KeePass 2, KeePassXC and their kin write
//! them), versions 3.1 and 4.x, opened with the master password, a key file,
//! or both.
//!
//! - Key: SHA-256 of the password's SHA-256 and the key file's 32 bytes; then
//!   the database's key derivation (AES-KDF, or Argon2d/Argon2id in 4.x); the
//!   cipher's key is SHA-256(master seed ‖ derived key).
//! - 3.1: the payload is AES-256-CBC, and starts with the header's "stream
//!   start bytes"; inside, blocks with a SHA-256 each.
//! - 4.x: the header is checked with an HMAC-SHA256, the payload is in blocks
//!   with an HMAC-SHA256 each, then AES-256-CBC or ChaCha20; an inner header
//!   holds the key of the inner stream (and attached files).
//! - The XML's protected values (passwords and the like) are XORed with the
//!   inner stream (Salsa20 or ChaCha20), value after value in file order.
//!
//! Twofish databases and attached files are not read (the files are counted
//! as missing).

use std::io::Read;

use base64::{Engine, engine::general_purpose::STANDARD};
use hmac::{Hmac, KeyInit, Mac};
use quick_xml::{Reader, events::Event};
use sha2::{Digest, Sha256, Sha512};
use zeroize::{Zeroize, Zeroizing};

use super::{ImportResult, ImportWarning, ImportedItem, ImportedVault, decrypt};
use crate::{
    Error, Result,
    item::{Category, Field, FieldKind, FieldPurpose, ItemDetails, ItemOverview, ItemUrl, PasswordHistoryEntry, new_field_id},
};

const SIGNATURE_1: u32 = 0x9AA2_D903;
const SIGNATURE_2: u32 = 0xB54B_FB67;
const CIPHER_AES256: [u8; 16] = hex16("31c1f2e6bf714350be5805216afc5aff");
const CIPHER_CHACHA20: [u8; 16] = hex16("d6038a2b8b6f4cb5a524339a31dbb59a");
const KDF_AES: [u8; 16] = hex16("c9d9f39a628a4460bf740d08c18a4fea");
const KDF_ARGON2D: [u8; 16] = hex16("ef636ddf8c29444b91f7a9a403e30a0c");
const KDF_ARGON2ID: [u8; 16] = hex16("9e298b1956db4773b23dfc3ec6f0a1e6");
/// The fixed nonce of the Salsa20 inner stream.
const SALSA20_NONCE: [u8; 8] = [0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A];
/// Refuse larger databases and payloads (decompressed).
const MAX_FILE_BYTES: usize = 256 * 1024 * 1024;
const MAX_XML_BYTES: u64 = 512 * 1024 * 1024;

const fn hex_digit(c: u8) -> u8 {
    if c <= b'9' { c - b'0' } else { c - b'a' + 10 }
}

const fn hex16(text: &str) -> [u8; 16] {
    let bytes = text.as_bytes();
    let mut out = [0u8; 16];
    let mut i = 0;
    while i < 16 {
        out[i] = hex_digit(bytes[i * 2]) << 4 | hex_digit(bytes[i * 2 + 1]);
        i += 1;
    }
    out
}

/// Whether `bytes` start like a KeePass database.
pub fn detect(bytes: &[u8]) -> bool {
    bytes.len() >= 8 && u32::from_le_bytes(bytes[0..4].try_into().unwrap()) == SIGNATURE_1 && u32::from_le_bytes(bytes[4..8].try_into().unwrap()) == SIGNATURE_2
}

fn damaged() -> Error {
    Error::Import("this KeePass database is damaged or not supported".into())
}

/// Reads little-endian numbers and byte runs from a slice.
struct Cursor<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.at.checked_add(n).filter(|&e| e <= self.data.len()).ok_or_else(damaged)?;
        let out = &self.data[self.at..end];
        self.at = end;
        Ok(out)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
}

/// The 32 bytes a key file stands for: an XML key file (versions 1 and 2),
/// 32 raw bytes, 64 hexadecimal digits, or the SHA-256 of anything else.
pub fn key_file_key(contents: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    let text = std::str::from_utf8(contents).unwrap_or("");
    if text.contains("<KeyFile") {
        let data = text.split("<Data").nth(1).and_then(|rest| rest.split_once('>')).map(|(_, rest)| rest.split("</Data>").next().unwrap_or("").trim());
        if let Some(data) = data {
            // Version 2: hexadecimal digits (in groups); version 1: base64.
            let hex: String = data.chars().filter(|c| !c.is_whitespace()).collect();
            let decoded = if text.contains("<Version>2.0") { decode_hex(&hex) } else { STANDARD.decode(&hex).ok() };
            if let Some(bytes) = decoded.filter(|b| b.len() == 32) {
                out.copy_from_slice(&bytes);
                return out;
            }
        }
    }
    if contents.len() == 32 {
        out.copy_from_slice(contents);
    } else if let Some(bytes) = (contents.len() == 64).then(|| decode_hex(text.trim())).flatten().filter(|b| b.len() == 32) {
        out.copy_from_slice(&bytes);
    } else {
        out.copy_from_slice(&Sha256::digest(contents));
    }
    out
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    text.len().is_multiple_of(2).then(|| (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok()).collect()).flatten()
}

/// The composite key: password and key file.
fn composite_key(password: Option<&str>, key_file: Option<&[u8]>) -> Result<Zeroizing<[u8; 32]>> {
    if password.is_none() && key_file.is_none() {
        return Err(Error::PasswordRequired);
    }
    let mut hasher = Sha256::new();
    if let Some(password) = password {
        hasher.update(Sha256::digest(password.as_bytes()));
    }
    if let Some(file) = key_file {
        hasher.update(key_file_key(file).as_ref());
    }
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&hasher.finalize());
    Ok(out)
}

/// KDBX 4's VariantDictionary (the key derivation's parameters).
fn variant_dictionary(data: &[u8]) -> Result<std::collections::HashMap<String, Vec<u8>>> {
    let mut cursor = Cursor { data, at: 0 };
    let _version = cursor.u16()?;
    let mut out = std::collections::HashMap::new();
    loop {
        let kind = cursor.u8()?;
        if kind == 0 {
            break;
        }
        let key_len = cursor.u32()? as usize;
        let key = String::from_utf8_lossy(cursor.take(key_len)?).into_owned();
        let value_len = cursor.u32()? as usize;
        out.insert(key, cursor.take(value_len)?.to_vec());
    }
    Ok(out)
}

fn le_u64(bytes: Option<&Vec<u8>>) -> Option<u64> {
    let b = bytes?;
    match b.len() {
        8 => Some(u64::from_le_bytes(b.as_slice().try_into().ok()?)),
        4 => Some(u32::from_le_bytes(b.as_slice().try_into().ok()?) as u64),
        _ => None,
    }
}

fn derive(kdf: &std::collections::HashMap<String, Vec<u8>>, composite: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
    let uuid = kdf.get("$UUID").ok_or_else(damaged)?;
    if uuid.as_slice() == KDF_AES {
        let rounds = le_u64(kdf.get("R")).ok_or_else(damaged)?;
        if rounds > 200_000_000 {
            return Err(Error::UnsafeKdfParams);
        }
        let derived = decrypt::aes_kdf(composite, kdf.get("S").ok_or_else(damaged)?, rounds)?;
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(&Sha256::digest(derived.as_ref()));
        return Ok(out);
    }
    let algorithm = match uuid.as_slice() {
        u if u == KDF_ARGON2D => argon2::Algorithm::Argon2d,
        u if u == KDF_ARGON2ID => argon2::Algorithm::Argon2id,
        _ => return Err(Error::Import("this KeePass database uses an unknown key derivation".into())),
    };
    let memory_kib = le_u64(kdf.get("M")).ok_or_else(damaged)? / 1024;
    let iterations = le_u64(kdf.get("I")).ok_or_else(damaged)?;
    let parallelism = le_u64(kdf.get("P")).ok_or_else(damaged)?;
    if memory_kib > 4 * 1024 * 1024 || iterations > 100_000 || parallelism > 256 {
        return Err(Error::UnsafeKdfParams);
    }
    let version = match le_u64(kdf.get("V")) {
        Some(0x10) => argon2::Version::V0x10,
        _ => argon2::Version::V0x13,
    };
    let params = argon2::Params::new(memory_kib as u32, iterations as u32, parallelism as u32, Some(32)).map_err(|_| Error::UnsafeKdfParams)?;
    let mut out = Zeroizing::new([0u8; 32]);
    argon2::Argon2::new(algorithm, version, params)
        .hash_password_into(composite, kdf.get("S").ok_or_else(damaged)?, out.as_mut())
        .map_err(|_| Error::Kdf)?;
    Ok(out)
}

fn sha256_of(parts: &[&[u8]]) -> Zeroizing<[u8; 32]> {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&hasher.finalize());
    out
}

/// The inner stream that hides protected values.
enum InnerStream {
    Salsa20(decrypt::Salsa20),
    ChaCha20(chacha20::ChaCha20),
    None,
}

impl InnerStream {
    fn new(id: u32, key: &[u8]) -> Result<Self> {
        use chacha20::cipher::KeyIvInit;
        match id {
            0 => Ok(Self::None),
            2 => Ok(Self::Salsa20(decrypt::Salsa20::new(&Sha256::digest(key).into(), &SALSA20_NONCE))),
            3 => {
                let hash = Sha512::digest(key);
                Ok(Self::ChaCha20(chacha20::ChaCha20::new_from_slices(&hash[..32], &hash[32..44]).map_err(|_| Error::InvalidKey)?))
            }
            _ => Err(Error::Import("this KeePass database uses an unknown inner stream".into())),
        }
    }

    fn apply(&mut self, data: &mut [u8]) {
        use chacha20::cipher::StreamCipher;
        match self {
            Self::Salsa20(s) => s.apply(data),
            Self::ChaCha20(c) => c.apply_keystream(data),
            Self::None => {}
        }
    }
}

/// The header fields both versions share, and the payload's place.
struct Header {
    cipher: Vec<u8>,
    compressed: bool,
    master_seed: Vec<u8>,
    iv: Vec<u8>,
    kdf: std::collections::HashMap<String, Vec<u8>>,
    // 3.1 only:
    protected_stream_key: Vec<u8>,
    stream_start: Vec<u8>,
    inner_stream: u32,
    /// Where the header ends.
    end: usize,
}

fn read_header(data: &[u8], major: u16) -> Result<Header> {
    let mut cursor = Cursor { data, at: 12 };
    let mut header = Header {
        cipher: Vec::new(),
        compressed: false,
        master_seed: Vec::new(),
        iv: Vec::new(),
        kdf: std::collections::HashMap::new(),
        protected_stream_key: Vec::new(),
        stream_start: Vec::new(),
        inner_stream: 0,
        end: 0,
    };
    loop {
        let id = cursor.u8()?;
        let len = if major >= 4 { cursor.u32()? as usize } else { cursor.u16()? as usize };
        let value = cursor.take(len)?;
        match id {
            0 => break,
            2 => header.cipher = value.to_vec(),
            3 => header.compressed = value.first().copied().unwrap_or(0) != 0,
            4 => header.master_seed = value.to_vec(),
            5 => {
                header.kdf.insert("$UUID".into(), KDF_AES.to_vec());
                header.kdf.insert("S".into(), value.to_vec());
            }
            6 => {
                header.kdf.insert("R".into(), value.to_vec());
            }
            7 => header.iv = value.to_vec(),
            8 => header.protected_stream_key = value.to_vec(),
            9 => header.stream_start = value.to_vec(),
            10 => header.inner_stream = value.get(..4).map(|b| u32::from_le_bytes(b.try_into().unwrap())).unwrap_or(0),
            11 => header.kdf = variant_dictionary(value)?,
            _ => {}
        }
    }
    header.end = cursor.at;
    Ok(header)
}

fn decrypt_payload(header: &Header, key: &[u8; 32], data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if header.cipher.as_slice() == CIPHER_AES256 {
        decrypt::aes256_cbc_decrypt(key, &header.iv, data)
    } else if header.cipher.as_slice() == CIPHER_CHACHA20 {
        let mut out = Zeroizing::new(data.to_vec());
        decrypt::chacha20_xor(key, &header.iv, &mut out)?;
        Ok(out)
    } else {
        Err(Error::Import("this KeePass database uses a cipher Keyless cannot read (Twofish)".into()))
    }
}

fn gunzip(data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::new());
    flate2::read::GzDecoder::new(data).take(MAX_XML_BYTES + 1).read_to_end(&mut out).map_err(|_| damaged())?;
    if out.len() as u64 > MAX_XML_BYTES {
        return Err(Error::Import("this KeePass database is too large".into()));
    }
    Ok(out)
}

/// Opens the database: its XML and the inner stream.
fn open(data: &[u8], composite: &[u8; 32]) -> Result<(Zeroizing<Vec<u8>>, InnerStream, usize)> {
    if !detect(data) || data.len() > MAX_FILE_BYTES {
        return Err(Error::Import("not a KeePass database".into()));
    }
    let major = u16::from_le_bytes([data[10], data[11]]);
    if !(3..=4).contains(&major) {
        return Err(Error::Import("this KeePass database's version is not supported (1.x or 2.x before 2.20?)".into()));
    }
    let header = read_header(data, major)?;
    let derived = derive(&header.kdf, composite)?;
    let key = sha256_of(&[&header.master_seed, derived.as_ref()]);
    if major == 3 {
        let plain = decrypt_payload(&header, &key, &data[header.end..])?;
        if header.stream_start.len() != 32 || plain.get(..32) != Some(header.stream_start.as_slice()) {
            return Err(Error::Decryption);
        }
        // Hashed blocks: index, SHA-256, size, data; size 0 ends.
        let mut cursor = Cursor { data: &plain[32..], at: 0 };
        let mut payload = Zeroizing::new(Vec::new());
        loop {
            let _index = cursor.u32()?;
            let hash = cursor.take(32)?;
            let size = cursor.u32()? as usize;
            if size == 0 {
                break;
            }
            let block = cursor.take(size)?;
            if Sha256::digest(block).as_slice() != hash {
                return Err(damaged());
            }
            payload.extend_from_slice(block);
        }
        let xml = if header.compressed { gunzip(&payload)? } else { payload };
        let stream = InnerStream::new(header.inner_stream, &header.protected_stream_key)?;
        return Ok((xml, stream, 0));
    }
    // 4.x: the header's SHA-256 and HMAC, then HMAC-checked blocks.
    let mut cursor = Cursor { data, at: header.end };
    let header_hash = cursor.take(32)?;
    if Sha256::digest(&data[..header.end]).as_slice() != header_hash {
        return Err(damaged());
    }
    let mut hmac_base = Sha512::new();
    hmac_base.update(&header.master_seed);
    hmac_base.update(derived.as_ref());
    hmac_base.update([1u8]);
    let mut hmac_key = Zeroizing::new([0u8; 64]);
    hmac_key.copy_from_slice(&hmac_base.finalize());
    let block_key = |index: u64| {
        let mut h = Sha512::new();
        h.update(index.to_le_bytes());
        h.update(hmac_key.as_ref());
        let mut k = Zeroizing::new([0u8; 64]);
        k.copy_from_slice(&h.finalize());
        k
    };
    let header_hmac = cursor.take(32)?;
    let mut check = Hmac::<Sha256>::new_from_slice(block_key(u64::MAX).as_ref()).map_err(|_| Error::InvalidKey)?;
    check.update(&data[..header.end]);
    // A wrong password or key file shows here first.
    check.verify_slice(header_hmac).map_err(|_| Error::Decryption)?;
    let mut sealed = Vec::new();
    for index in 0u64.. {
        let mac = cursor.take(32)?;
        let size_bytes = cursor.take(4)?;
        let size = u32::from_le_bytes(size_bytes.try_into().unwrap()) as usize;
        let block = cursor.take(size)?;
        let mut check = Hmac::<Sha256>::new_from_slice(block_key(index).as_ref()).map_err(|_| Error::InvalidKey)?;
        check.update(&index.to_le_bytes());
        check.update(size_bytes);
        check.update(block);
        check.verify_slice(mac).map_err(|_| damaged())?;
        if size == 0 {
            break;
        }
        sealed.extend_from_slice(block);
    }
    let plain = decrypt_payload(&header, &key, &sealed)?;
    let inner = if header.compressed { gunzip(&plain)? } else { plain };
    // Inner header: the stream's kind and key, and the attached files.
    let mut cursor = Cursor { data: &inner, at: 0 };
    let (mut stream_id, mut stream_key, mut files) = (0u32, Zeroizing::new(Vec::new()), 0usize);
    loop {
        let id = cursor.u8()?;
        let len = cursor.u32()? as usize;
        let value = cursor.take(len)?;
        match id {
            0 => break,
            1 => stream_id = value.get(..4).map(|b| u32::from_le_bytes(b.try_into().unwrap())).unwrap_or(0),
            2 => *stream_key = value.to_vec(),
            3 => files += 1,
            _ => {}
        }
    }
    let xml = Zeroizing::new(inner[cursor.at..].to_vec());
    Ok((xml, InnerStream::new(stream_id, &stream_key)?, files))
}

// ----- the XML ----------------------------------------------------------------------

#[derive(Default)]
struct Entry {
    uuid: String,
    strings: Vec<(String, Zeroizing<String>, bool)>,
    tags: String,
    created: i64,
    modified: i64,
    history: Vec<(Zeroizing<String>, i64)>,
    files: usize,
}

/// .NET ticks (seconds since 0001-01-01, base64 of 8 bytes in KDBX 4) or an
/// ISO date (KDBX 3) as Unix seconds.
fn time(text: &str) -> i64 {
    if let Ok(bytes) = STANDARD.decode(text.trim())
        && bytes.len() == 8
    {
        return i64::from_le_bytes(bytes.try_into().unwrap()) - 62_135_596_800;
    }
    super::bitwarden::date(Some(&serde_json::Value::String(text.trim().to_string())))
}

fn entity(name: &str) -> Option<char> {
    Some(match name {
        "amp" => '&',
        "lt" => '<',
        "gt" => '>',
        "quot" => '"',
        "apos" => '\'',
        _ => return None,
    })
}

/// The entries found, each with the names of the groups it is in.
type Entries = Vec<(Vec<String>, Entry)>;

fn parse_xml(xml: &[u8], stream: &mut InnerStream) -> Result<(Entries, usize)> {
    let text = std::str::from_utf8(xml).map_err(|_| damaged())?;
    let mut reader = Reader::from_str(text);
    let mut path: Vec<String> = Vec::new();
    // The group names on the way, and whether each is the recycle bin.
    let mut groups: Vec<(String, String)> = Vec::new();
    let mut recycle_bin = String::new();
    let mut entries = Vec::new();
    let mut entry: Option<Entry> = None;
    let mut in_history = 0usize;
    let mut history_entry: Option<Entry> = None;
    let mut text_buf = Zeroizing::new(String::new());
    let mut protected = false;
    let mut key = String::new();
    let mut value = Zeroizing::new(String::new());
    let mut value_protected = false;
    let mut missing_files = 0;
    loop {
        let event = reader.read_event().map_err(|_| damaged())?;
        match event {
            Event::Start(start) => {
                let name = start.local_name().as_ref().to_string();
                text_buf.clear();
                protected = start
                    .try_get_attribute("Protected")
                    .ok()
                    .flatten()
                    .map(|a| a.value.trim().eq_ignore_ascii_case("true"))
                    .unwrap_or(false);
                match name.as_str() {
                    "Group" if in_history == 0 => groups.push((String::new(), String::new())),
                    "Entry" if in_history > 0 => history_entry = Some(Entry::default()),
                    "Entry" => entry = Some(Entry::default()),
                    "History" => in_history += 1,
                    _ => {}
                }
                path.push(name);
            }
            Event::Empty(start) => {
                let name = start.local_name().as_ref().to_string();
                // An empty protected value still uses none of the stream.
                if name == "Value" && path.last().map(String::as_str) == Some("String") {
                    value.clear();
                    value_protected = false;
                }
                if name == "Value"
                    && path.last().map(String::as_str) == Some("Binary")
                    && let Some(e) = history_entry.as_mut().or(entry.as_mut())
                {
                    e.files += 1;
                }
            }
            Event::Text(t) => text_buf.push_str(&t.xml10_content()),
            Event::CData(c) => text_buf.push_str(&c.into_inner()),
            Event::GeneralRef(r) => {
                if let Ok(Some(c)) = r.resolve_char_ref() {
                    text_buf.push(c);
                } else if let Some(c) = entity(&r.xml10_content()) {
                    text_buf.push(c);
                }
            }
            Event::End(_) => {
                let name = path.pop().unwrap_or_default();
                let parent = path.last().map(String::as_str).unwrap_or("");
                let mut content = std::mem::take(&mut *text_buf);
                if name == "Value" && protected && !content.is_empty() {
                    // Hidden by the inner stream, in file order.
                    let mut bytes = Zeroizing::new(STANDARD.decode(content.trim()).map_err(|_| damaged())?);
                    stream.apply(&mut bytes);
                    content.zeroize();
                    content = String::from_utf8_lossy(&bytes).into_owned();
                }
                let current = if in_history > 0 { history_entry.as_mut() } else { entry.as_mut() };
                match (name.as_str(), parent) {
                    ("RecycleBinUUID", "Meta") => recycle_bin = content.trim().to_string(),
                    ("Name", "Group") => {
                        if let Some(group) = groups.last_mut() {
                            group.0 = content.trim().to_string();
                        }
                    }
                    ("UUID", "Group") => {
                        if let Some(group) = groups.last_mut() {
                            group.1 = content.trim().to_string();
                        }
                    }
                    ("Group", _) if in_history == 0 => {
                        groups.pop();
                    }
                    ("UUID", "Entry") => {
                        if let Some(e) = current {
                            e.uuid = content.trim().to_string();
                        }
                    }
                    ("Tags", "Entry") => {
                        if let Some(e) = current {
                            e.tags = content.trim().to_string();
                        }
                    }
                    ("CreationTime", "Times") => {
                        if let Some(e) = current {
                            e.created = time(&content);
                        }
                    }
                    ("LastModificationTime", "Times") => {
                        if let Some(e) = current {
                            e.modified = time(&content);
                        }
                    }
                    ("Key", "String") => key = content.trim().to_string(),
                    ("Value", "String") => {
                        *value = content.clone();
                        value_protected = protected;
                    }
                    ("String", _) => {
                        if let Some(e) = current {
                            e.strings.push((std::mem::take(&mut key), Zeroizing::new(std::mem::take(&mut *value)), value_protected));
                        }
                        value_protected = false;
                    }
                    ("Value", "Binary") => {
                        if let Some(e) = current {
                            e.files += 1;
                        }
                    }
                    ("Entry", _) if in_history > 0 => {
                        if let (Some(old), Some(e)) = (history_entry.take(), entry.as_mut()) {
                            let password = old.strings.iter().find(|(k, _, _)| k == "Password").map(|(_, v, _)| v.clone()).unwrap_or_default();
                            if !password.is_empty() {
                                e.history.push((password, old.modified));
                            }
                        }
                    }
                    ("History", _) => in_history = in_history.saturating_sub(1),
                    ("Entry", _) => {
                        if let Some(done) = entry.take() {
                            let in_bin = !recycle_bin.is_empty() && groups.iter().any(|(_, uuid)| *uuid == recycle_bin);
                            if !in_bin {
                                missing_files += done.files;
                                // The groups below the root one.
                                let names: Vec<String> = groups.iter().skip(1).map(|(n, _)| n.clone()).filter(|n| !n.is_empty()).collect();
                                entries.push((names, done));
                            }
                        }
                    }
                    _ => {}
                }
                content.zeroize();
            }
            Event::Eof => break,
            _ => {}
        }
    }
    Ok((entries, missing_files))
}

/// A one-time password from KeePassXC ("otp") or KeePass 2.47+
/// ("TimeOtp-Secret-Base32" and the like).
fn totp_of(strings: &[(String, Zeroizing<String>, bool)]) -> Option<String> {
    let get = |name: &str| strings.iter().find(|(k, v, _)| k == name && !v.trim().is_empty()).map(|(_, v, _)| v.trim().to_string());
    if let Some(uri) = get("otp") {
        return Some(uri);
    }
    let secret = get("TimeOtp-Secret-Base32")?;
    let mut uri = format!("otpauth://totp/KeePass?secret={}", secret.replace(' ', ""));
    if let Some(period) = get("TimeOtp-Period") {
        uri.push_str(&format!("&period={period}"));
    }
    if let Some(digits) = get("TimeOtp-Length") {
        uri.push_str(&format!("&digits={digits}"));
    }
    if let Some(algorithm) = get("TimeOtp-Algorithm") {
        uri.push_str(&format!("&algorithm={}", algorithm.replace("HMAC-", "")));
    }
    Some(uri)
}

/// Strings Keyless reads as something else (or that hold settings).
const KNOWN: [&str; 5] = ["Title", "UserName", "Password", "URL", "Notes"];

fn convert(groups: Vec<String>, entry: Entry) -> Option<ImportedItem> {
    let get = |name: &str| entry.strings.iter().find(|(k, _, _)| k == name).map(|(_, v, _)| v.trim().to_string()).unwrap_or_default();
    let (title, username, url) = (get("Title"), get("UserName"), get("URL"));
    let password = entry.strings.iter().find(|(k, _, _)| k == "Password").map(|(_, v, _)| v.to_string()).unwrap_or_default();
    let mut details = ItemDetails::default();
    details.notes = entry.strings.iter().find(|(k, _, _)| k == "Notes").map(|(_, v, _)| v.to_string()).unwrap_or_default();
    let field = |label: &str, kind: FieldKind, value: String, purpose: Option<FieldPurpose>| Field { id: new_field_id(), label: label.into(), kind, value, purpose, extra: Default::default() };
    if !username.is_empty() {
        details.fields.push(field("username", FieldKind::Text, username.clone(), Some(FieldPurpose::Username)));
    }
    if !password.is_empty() {
        details.fields.push(field("password", FieldKind::Concealed, password.clone(), Some(FieldPurpose::Password)));
    }
    if let Some(uri) = totp_of(&entry.strings) {
        details.fields.push(field("one-time password", FieldKind::Totp, uri, None));
    }
    for (key, value, protected) in &entry.strings {
        if KNOWN.contains(&key.as_str()) || key == "otp" || key.starts_with("TimeOtp-") || key.starts_with("HmacOtp-") || key.starts_with("KPEX_") || value.trim().is_empty() {
            continue;
        }
        details.fields.push(field(key, if *protected { FieldKind::Concealed } else { FieldKind::Text }, value.to_string(), None));
    }
    for (old, at) in &entry.history {
        if old.as_str() != password {
            details.password_history.push(PasswordHistoryEntry { value: old.to_string(), changed_at: *at });
        }
    }
    if title.is_empty() && username.is_empty() && password.is_empty() && url.is_empty() && details.notes.is_empty() && details.fields.is_empty() {
        return None;
    }
    let category = if username.is_empty() && password.is_empty() && url.is_empty() { Category::SecureNote } else { Category::Login };
    let mut tags = groups;
    tags.extend(entry.tags.split([';', ',']).map(str::trim).filter(|t| !t.is_empty()).map(String::from));
    tags.dedup();
    details.sort_main_fields();
    let overview = ItemOverview {
        title: if title.is_empty() { "Untitled".into() } else { title },
        subtitle: username,
        category,
        urls: Some(url).filter(|u| !u.is_empty()).map(|href| ItemUrl { href, ..Default::default() }).into_iter().collect(),
        tags,
        created_at: entry.created.max(0),
        updated_at: entry.modified.max(0),
        ..Default::default()
    };
    Some(ImportedItem::new(entry.uuid.clone(), overview, details, Vec::new()))
}

/// Opens and reads a KeePass database with its password and/or key file.
pub fn parse_kdbx(data: &[u8], password: Option<&str>, key_file: Option<&[u8]>, vault_name: &str) -> Result<ImportResult> {
    let composite = composite_key(password.filter(|p| !p.is_empty()), key_file)?;
    let (xml, mut stream, _) = open(data, &composite)?;
    let (entries, missing) = parse_xml(&xml, &mut stream)?;
    let items: Vec<ImportedItem> = entries.into_iter().filter_map(|(groups, entry)| convert(groups, entry)).collect();
    let mut warnings = Vec::new();
    if missing > 0 {
        warnings.push(ImportWarning::new("files_missing", missing));
    }
    Ok(ImportResult { vaults: vec![ImportedVault { name: vault_name.to_string(), items }], warnings })
}

#[cfg(test)]
mod tests;
