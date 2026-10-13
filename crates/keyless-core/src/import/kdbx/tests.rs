//! Databases written here the way KeePass writes them (version 4 with
//! Argon2id and ChaCha20, version 3.1 with AES-KDF, AES and Salsa20), then
//! read back.

use std::io::Write;

use cbc::cipher::{BlockModeEncrypt, KeyIvInit, block_padding::Pkcs7};

use super::*;

const PASSWORD: &str = "correct horse";

/// The XML of a small database: a login (with a protected password, an old
/// password and a one-time password), a note in a subgroup, and one in the
/// recycle bin. `seal` hides each protected value, in file order.
fn xml(seal: &mut dyn FnMut(&str) -> String) -> String {
    // In the order they appear in the file.
    let pw = seal("p&ss<word>");
    let pin = seal("4321");
    let old = seal("old-pass");
    format!(
        r#"<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<KeePassFile>
  <Meta><RecycleBinUUID>YmluYmluYmluYmluYmluMQ==</RecycleBinUUID></Meta>
  <Root>
    <Group>
      <UUID>cm9vdHJvb3Ryb290cm9vdA==</UUID><Name>Root</Name>
      <Entry>
        <UUID>ZW50cnllbnRyeWVudHJ5MQ==</UUID>
        <Tags>work;mail</Tags>
        <Times><CreationTime>2024-01-01T00:00:00Z</CreationTime><LastModificationTime>2024-05-01T12:00:00Z</LastModificationTime></Times>
        <String><Key>Title</Key><Value>Mail &amp; more</Value></String>
        <String><Key>UserName</Key><Value>me@example.com</Value></String>
        <String><Key>Password</Key><Value Protected="True">{pw}</Value></String>
        <String><Key>URL</Key><Value>https://mail.example</Value></String>
        <String><Key>Notes</Key><Value>line 1&#10;line 2</Value></String>
        <String><Key>otp</Key><Value>otpauth://totp/x?secret=JBSWY3DPEHPK3PXP</Value></String>
        <String><Key>PIN</Key><Value Protected="True">{pin}</Value></String>
        <String><Key>Empty</Key><Value Protected="True"/></String>
        <Binary><Key>scan.png</Key><Value Ref="0"/></Binary>
        <History>
          <Entry>
            <UUID>ZW50cnllbnRyeWVudHJ5MQ==</UUID>
            <Times><LastModificationTime>2023-01-01T00:00:00Z</LastModificationTime></Times>
            <String><Key>Password</Key><Value Protected="True">{old}</Value></String>
          </Entry>
        </History>
      </Entry>
      <Group>
        <UUID>c3ViZ3JvdXBzdWJncm91cA==</UUID><Name>Home</Name>
        <Entry>
          <UUID>bm90ZW5vdGVub3Rlbm90ZQ==</UUID>
          <String><Key>Title</Key><Value>Wi-Fi</Value></String>
          <String><Key>Notes</Key><Value>in the hall</Value></String>
        </Entry>
      </Group>
      <Group>
        <UUID>YmluYmluYmluYmluYmluMQ==</UUID><Name>Recycle Bin</Name>
        <Entry><UUID>Z29uZWdvbmVnb25lZ29uZQ==</UUID><String><Key>Title</Key><Value>Gone</Value></String></Entry>
      </Group>
    </Group>
  </Root>
</KeePassFile>"#
    )
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

fn field(out: &mut Vec<u8>, id: u8, value: &[u8], wide: bool) {
    out.push(id);
    if wide {
        out.extend_from_slice(&(value.len() as u32).to_le_bytes());
    } else {
        out.extend_from_slice(&(value.len() as u16).to_le_bytes());
    }
    out.extend_from_slice(value);
}

fn variant(entries: &[(u8, &str, Vec<u8>)]) -> Vec<u8> {
    let mut out = 0x0100u16.to_le_bytes().to_vec();
    for (kind, key, value) in entries {
        out.push(*kind);
        out.extend_from_slice(&(key.len() as u32).to_le_bytes());
        out.extend_from_slice(key.as_bytes());
        out.extend_from_slice(&(value.len() as u32).to_le_bytes());
        out.extend_from_slice(value);
    }
    out.push(0);
    out
}

fn signature(major: u16, minor: u16) -> Vec<u8> {
    let mut out = SIGNATURE_1.to_le_bytes().to_vec();
    out.extend_from_slice(&SIGNATURE_2.to_le_bytes());
    out.extend_from_slice(&minor.to_le_bytes());
    out.extend_from_slice(&major.to_le_bytes());
    out
}

/// A version 4.1 database, Argon2id and ChaCha20 (key file optional).
fn kdbx4(key_file: Option<&[u8]>) -> Vec<u8> {
    let (seed, salt, nonce, stream_key) = ([1u8; 32], [2u8; 32], [3u8; 12], [4u8; 64]);
    let kdf = variant(&[
        (0x42, "$UUID", KDF_ARGON2ID.to_vec()),
        (0x05, "M", (1024u64 * 1024).to_le_bytes().to_vec()),
        (0x05, "I", 2u64.to_le_bytes().to_vec()),
        (0x04, "P", 1u32.to_le_bytes().to_vec()),
        (0x04, "V", 0x13u32.to_le_bytes().to_vec()),
        (0x42, "S", salt.to_vec()),
    ]);
    let mut header = signature(4, 1);
    field(&mut header, 2, &CIPHER_CHACHA20, true);
    field(&mut header, 3, &1u32.to_le_bytes(), true);
    field(&mut header, 4, &seed, true);
    field(&mut header, 7, &nonce, true);
    field(&mut header, 11, &kdf, true);
    field(&mut header, 0, b"\r\n\r\n", true);

    let composite = composite_key(Some(PASSWORD), key_file).unwrap();
    let kdf_map = variant_dictionary(&kdf).unwrap();
    let derived = derive(&kdf_map, &composite).unwrap();
    let key = sha256_of(&[&seed, derived.as_ref()]);
    let mut base = Sha512::new();
    base.update(seed);
    base.update(derived.as_ref());
    base.update([1u8]);
    let hmac_key = base.finalize();
    let block_key = |index: u64| {
        let mut h = Sha512::new();
        h.update(index.to_le_bytes());
        h.update(hmac_key);
        h.finalize()
    };

    let mut stream = InnerStream::new(3, &stream_key).unwrap();
    let xml = xml(&mut |plain: &str| {
        let mut bytes = plain.as_bytes().to_vec();
        stream.apply(&mut bytes);
        STANDARD.encode(bytes)
    });
    let mut inner = Vec::new();
    field(&mut inner, 1, &3u32.to_le_bytes(), true);
    field(&mut inner, 2, &stream_key, true);
    field(&mut inner, 3, b"\x01PNG", true);
    field(&mut inner, 0, b"", true);
    inner.extend_from_slice(xml.as_bytes());
    let mut sealed = gzip(&inner);
    decrypt::chacha20_xor(key.as_ref(), &nonce, &mut sealed).unwrap();

    let mut out = header.clone();
    out.extend_from_slice(&Sha256::digest(&header));
    let mut mac = Hmac::<Sha256>::new_from_slice(&block_key(u64::MAX)).unwrap();
    mac.update(&header);
    out.extend_from_slice(&mac.finalize().into_bytes());
    for (index, block) in [(0u64, sealed.as_slice()), (1, &[][..])] {
        let size = (block.len() as u32).to_le_bytes();
        let mut mac = Hmac::<Sha256>::new_from_slice(&block_key(index)).unwrap();
        mac.update(&index.to_le_bytes());
        mac.update(&size);
        mac.update(block);
        out.extend_from_slice(&mac.finalize().into_bytes());
        out.extend_from_slice(&size);
        out.extend_from_slice(block);
    }
    out
}

/// A version 3.1 database: AES-KDF, AES-256-CBC, Salsa20.
fn kdbx3() -> Vec<u8> {
    let (seed, transform_seed, iv, stream_key, start) = ([5u8; 32], [6u8; 32], [7u8; 16], [8u8; 32], [9u8; 32]);
    let rounds = 1000u64;
    let mut header = signature(3, 1);
    field(&mut header, 2, &CIPHER_AES256, false);
    field(&mut header, 3, &1u32.to_le_bytes(), false);
    field(&mut header, 4, &seed, false);
    field(&mut header, 5, &transform_seed, false);
    field(&mut header, 6, &rounds.to_le_bytes(), false);
    field(&mut header, 7, &iv, false);
    field(&mut header, 8, &stream_key, false);
    field(&mut header, 9, &start, false);
    field(&mut header, 10, &2u32.to_le_bytes(), false);
    field(&mut header, 0, b"\r\n\r\n", false);

    let composite = composite_key(Some(PASSWORD), None).unwrap();
    let derived = decrypt::aes_kdf(&composite, &transform_seed, rounds).unwrap();
    let derived = sha256_of(&[derived.as_ref()]);
    let key = sha256_of(&[&seed, derived.as_ref()]);

    let mut stream = InnerStream::new(2, &stream_key).unwrap();
    let xml = xml(&mut |plain: &str| {
        let mut bytes = plain.as_bytes().to_vec();
        stream.apply(&mut bytes);
        STANDARD.encode(bytes)
    });
    let payload = gzip(xml.as_bytes());
    let mut blocks = start.to_vec();
    for (index, block) in [(0u32, payload.as_slice()), (1, &[][..])] {
        blocks.extend_from_slice(&index.to_le_bytes());
        blocks.extend_from_slice(&if block.is_empty() { [0u8; 32] } else { Sha256::digest(block).into() });
        blocks.extend_from_slice(&(block.len() as u32).to_le_bytes());
        blocks.extend_from_slice(block);
    }
    let sealed = cbc::Encryptor::<aes::Aes256>::new_from_slices(key.as_ref(), &iv).unwrap().encrypt_padded_vec::<Pkcs7>(&blocks);
    let mut out = header;
    out.extend_from_slice(&sealed);
    out
}

fn check(result: &ImportResult) {
    let items = &result.vaults[0].items;
    assert_eq!(items.len(), 2, "the recycle bin stays out");
    let mail = &items[0];
    assert_eq!(mail.overview.title, "Mail & more");
    assert_eq!(mail.details.username(), Some("me@example.com"));
    assert_eq!(mail.details.password(), Some("p&ss<word>"));
    assert_eq!(mail.details.notes, "line 1\nline 2");
    assert!(mail.details.fields.iter().any(|f| f.kind == FieldKind::Totp));
    assert!(mail.details.fields.iter().any(|f| f.label == "PIN" && f.kind == FieldKind::Concealed && f.value == "4321"));
    assert!(!mail.details.fields.iter().any(|f| f.label == "Empty"));
    assert_eq!(mail.details.password_history[0].value, "old-pass");
    assert_eq!(mail.overview.tags, vec!["work", "mail"]);
    assert_eq!(mail.overview.updated_at, 1_714_564_800);
    let wifi = &items[1];
    assert_eq!(wifi.overview.category, Category::SecureNote);
    assert_eq!(wifi.overview.tags, vec!["Home"]);
    assert_eq!(result.warnings, vec![ImportWarning::new("files_missing", 1)]);
}

#[test]
fn reads_version_4() {
    let file = kdbx4(None);
    assert!(detect(&file));
    check(&parse_kdbx(&file, Some(PASSWORD), None, "KeePass").unwrap());
    assert!(matches!(parse_kdbx(&file, Some("wrong"), None, "KeePass"), Err(Error::Decryption)));
    assert!(matches!(parse_kdbx(&file, None, None, "KeePass"), Err(Error::PasswordRequired)));
}

#[test]
fn reads_version_4_with_a_key_file() {
    let key_file = br#"<?xml version="1.0" encoding="UTF-8"?>
<KeyFile><Meta><Version>2.0</Version></Meta><Key><Data Hash="00000000">
  0102 0304 0506 0708 090A 0B0C 0D0E 0F10
  1112 1314 1516 1718 191A 1B1C 1D1E 1F20
</Data></Key></KeyFile>"#;
    let file = kdbx4(Some(key_file));
    check(&parse_kdbx(&file, Some(PASSWORD), Some(key_file), "KeePass").unwrap());
    assert!(matches!(parse_kdbx(&file, Some(PASSWORD), None, "KeePass"), Err(Error::Decryption)));
}

#[test]
fn reads_version_3() {
    let file = kdbx3();
    check(&parse_kdbx(&file, Some(PASSWORD), None, "KeePass").unwrap());
    assert!(matches!(parse_kdbx(&file, Some("wrong"), None, "KeePass"), Err(Error::Decryption)));
}

#[test]
fn key_files() {
    assert_eq!(key_file_key(&[7u8; 32]).as_ref(), &[7u8; 32]);
    assert_eq!(key_file_key("ab".repeat(32).as_bytes()).as_ref(), &[0xab; 32]);
    let v1 = format!("<KeyFile><Meta><Version>1.00</Version></Meta><Key><Data>{}</Data></Key></KeyFile>", STANDARD.encode([9u8; 32]));
    assert_eq!(key_file_key(v1.as_bytes()).as_ref(), &[9u8; 32]);
    assert_eq!(key_file_key(b"anything").as_ref(), Sha256::digest(b"anything").as_slice());
}
