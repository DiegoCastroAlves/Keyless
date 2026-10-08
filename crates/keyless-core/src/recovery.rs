//! Account recovery keys, like 1Password's recovery codes.
//!
//! A recovery key is 248 random bits the user keeps printed or saved. It
//! gets them back into their account when the master password is forgotten
//! or the Secret Key lost: whoever has it and knows the account's email gets
//! in, so it is optional, can be removed, and is replaced after each use.
//!
//! ```text
//! proof = HKDF(ikm = recovery key, salt = "keyless/v1/recovery", info = "proof")[32]
//! kek   = HKDF(ikm = recovery key, salt = "keyless/v1/recovery", info = "key encryption key")[32]
//! enc_recovery_user_key = seal(kek, user key, "recovery-user-key" | user id)
//! ```
//!
//! The server keeps a SHA-256 hash of the proof and the user key encrypted
//! with the kek. To recover, the device sends the proof; the server hands out
//! the encrypted user key and then accepts a new sign-in secret and key
//! wrapping (a new master password and Secret Key). The server never sees the
//! recovery key, the kek or the user key.
//!
//! Shown as `KLRK-` and 13 groups of 4 Crockford symbols: 50 for the key and
//! 2 for a checksum that catches most typos.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{
    Error, Result,
    account::{AccountBundle, UnlockedAccount, open_with_user_key},
    crypto::{SymmetricKey, context, random_array},
    encoding::{crockford_decode, crockford_encode},
};

const KEY_LEN: usize = 31;
const PREFIX: &str = "KLRK";
const DATA_SYMBOLS: usize = 50;
const CHECK_SYMBOLS: usize = 2;
const GROUP: usize = 4;

fn user_key_context(user_id: &str) -> Vec<u8> {
    context("recovery-user-key", &[user_id])
}

pub struct RecoveryKey(Zeroizing<[u8; KEY_LEN]>);

impl RecoveryKey {
    pub fn generate() -> Result<Self> {
        Ok(Self(random_array::<KEY_LEN>()?))
    }

    /// e.g. `KLRK-ABCD-EFGH-…` (14 groups of 4).
    pub fn to_display(&self) -> Zeroizing<String> {
        let mut symbols = crockford_encode(self.0.as_ref());
        symbols.push_str(&checksum(&self.0));
        let mut out = Zeroizing::new(String::from(PREFIX));
        for group in symbols.as_bytes().chunks(GROUP) {
            out.push('-');
            out.push_str(std::str::from_utf8(group).expect("base32 is ASCII"));
        }
        out
    }

    /// Parses the display form, tolerating case, spaces, missing dashes, a
    /// missing prefix and common look-alike characters.
    pub fn parse(input: &str) -> Result<Self> {
        let compact = Zeroizing::new(
            input
                .chars()
                .filter(|c| !c.is_whitespace() && *c != '-')
                .collect::<String>()
                .to_ascii_uppercase(),
        );
        let body = compact.strip_prefix(PREFIX).unwrap_or(&compact);
        if body.len() != DATA_SYMBOLS + CHECK_SYMBOLS || !body.is_ascii() {
            return Err(Error::InvalidRecoveryKey);
        }
        let (data, check) = body.split_at(DATA_SYMBOLS);
        let bytes = crockford_decode(data, KEY_LEN).ok_or(Error::InvalidRecoveryKey)?;
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        key.copy_from_slice(&bytes);
        let given: String = check.chars().map(normalize_symbol).collect();
        if checksum(&key).as_bytes().ct_eq(given.as_bytes()).into() {
            Ok(Self(key))
        } else {
            Err(Error::InvalidRecoveryKey)
        }
    }

    fn derive(&self, info: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        let mut out = Zeroizing::new([0u8; 32]);
        Hkdf::<Sha256>::new(Some(b"keyless/v1/recovery"), self.0.as_ref())
            .expand(info, out.as_mut())
            .map_err(|_| Error::Kdf)?;
        Ok(out)
    }

    /// What the server checks (it keeps only its hash), base64url.
    pub fn proof(&self) -> Result<Zeroizing<String>> {
        Ok(Zeroizing::new(URL_SAFE_NO_PAD.encode(self.derive(b"proof")?.as_ref())))
    }

    fn kek(&self) -> Result<SymmetricKey> {
        SymmetricKey::from_slice(self.derive(b"key encryption key")?.as_ref())
    }

    /// The account's user key, encrypted for the server to keep.
    pub fn wrap_user_key(&self, account: &UnlockedAccount, user_id: &str) -> Result<String> {
        self.kek()?.seal(account.user_key().as_bytes(), &user_key_context(user_id))
    }

    /// Opens the account with the user key the server kept
    /// (`enc_recovery_user_key`). `bundle` supplies the key pair; its user
    /// key wrapping is not used. Fails with [`Error::Decryption`] for another
    /// key or account.
    pub fn open_account(&self, bundle: &AccountBundle, enc_recovery_user_key: &str, user_id: &str) -> Result<UnlockedAccount> {
        let bytes = self.kek()?.open(enc_recovery_user_key, &user_key_context(user_id))?;
        open_with_user_key(bundle, SymmetricKey::from_slice(&bytes)?, user_id)
    }
}

impl std::fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryKey(<redacted>)")
    }
}

fn checksum(bytes: &[u8; KEY_LEN]) -> String {
    let digest = Sha256::new()
        .chain_update(b"keyless/v1/recovery-key-checksum")
        .chain_update(bytes)
        .finalize();
    crockford_encode(&digest[..2]).chars().take(CHECK_SYMBOLS).collect()
}

fn normalize_symbol(c: char) -> char {
    match c {
        'O' => '0',
        'I' | 'L' => '1',
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        account::{create_account, rewrap_account, unlock_account},
        keys::KdfParams,
    };

    #[test]
    fn display_round_trip() {
        let key = RecoveryKey::generate().unwrap();
        let display = key.to_display();
        assert!(display.starts_with("KLRK-"));
        let groups: Vec<&str> = display.split('-').collect();
        assert_eq!(groups.len(), 14);
        assert!(groups.iter().all(|g| g.len() == 4));
        assert_eq!(RecoveryKey::parse(&display).unwrap().0.as_ref(), key.0.as_ref());
        // Typed loosely: lowercase, spaces, no prefix, look-alikes.
        let sloppy = display.trim_start_matches("KLRK-").to_lowercase().replace('-', " ").replace('0', "o").replace('1', "l");
        assert_eq!(RecoveryKey::parse(&sloppy).unwrap().0.as_ref(), key.0.as_ref());
    }

    #[test]
    fn checksum_catches_typos() {
        let key = RecoveryKey::generate().unwrap();
        let display = key.to_display();
        let mut rejected = 0;
        for i in (5..display.len()).filter(|&i| display.as_bytes()[i] != b'-') {
            let mut typo = display.to_string().into_bytes();
            typo[i] = if typo[i] == b'A' { b'B' } else { b'A' };
            if RecoveryKey::parse(std::str::from_utf8(&typo).unwrap()).is_err() {
                rejected += 1;
            }
        }
        assert!(rejected >= 48, "{rejected}");
        assert!(RecoveryKey::parse("KLRK-ABCD").is_err());
        assert!(RecoveryKey::parse("").is_err());
    }

    #[test]
    fn recovers_the_account() {
        let kek = SymmetricKey::generate().unwrap();
        let (bundle, account) = create_account(&kek, KdfParams::recommended(), "u1").unwrap();
        let key = RecoveryKey::generate().unwrap();
        let enc = key.wrap_user_key(&account, "u1").unwrap();
        let proof = key.proof().unwrap();
        assert_eq!(proof.len(), 43);

        // Typed back in on another device.
        let typed = RecoveryKey::parse(&key.to_display()).unwrap();
        assert_eq!(typed.proof().unwrap(), proof);
        let recovered = typed.open_account(&bundle, &enc, "u1").unwrap();
        assert_eq!(recovered.user_key().as_bytes(), account.user_key().as_bytes());

        // A new master password and Secret Key wrap the same user key.
        let new_kek = SymmetricKey::generate().unwrap();
        let new_bundle = rewrap_account(&bundle, &recovered, &new_kek, KdfParams::recommended(), "u1").unwrap();
        assert_eq!(unlock_account(&new_bundle, &new_kek, "u1").unwrap().user_key().as_bytes(), account.user_key().as_bytes());
    }

    #[test]
    fn other_keys_or_accounts_fail() {
        let kek = SymmetricKey::generate().unwrap();
        let (bundle, account) = create_account(&kek, KdfParams::recommended(), "u1").unwrap();
        let key = RecoveryKey::generate().unwrap();
        let enc = key.wrap_user_key(&account, "u1").unwrap();
        let other = RecoveryKey::generate().unwrap();
        assert_ne!(other.proof().unwrap(), key.proof().unwrap());
        assert!(matches!(other.open_account(&bundle, &enc, "u1"), Err(Error::Decryption)));
        assert!(key.open_account(&bundle, &enc, "u2").is_err());
        // Another account's key pair is noticed.
        let (foreign, _) = create_account(&kek, KdfParams::recommended(), "u1").unwrap();
        assert!(key.open_account(&foreign, &enc, "u1").is_err());
    }
}
