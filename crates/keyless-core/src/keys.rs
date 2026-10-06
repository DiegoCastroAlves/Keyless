//! Account key derivation ("two-secret key derivation").
//!
//! An account is protected by two secrets:
//!
//! - the **master password**, which the user memorises, and
//! - the **Secret Key**, 128 random bits generated on the user's first device
//!   and kept on their devices and in their Emergency Kit. It never reaches
//!   the server.
//!
//! Both are required to derive the account keys:
//!
//! ```text
//! salt   = HKDF(ikm = secret_key, salt = "keyless/v1/kdf-salt", info = "argon2id salt")[16]
//! k_mp   = Argon2id(NFKD(trim(master_password)), salt, m, t, p)[32]
//! k_sk   = HKDF(ikm = secret_key, salt = "keyless/v1/secret-key", info = "2skd")[32]
//! root   = HKDF-Extract(salt = k_sk, ikm = k_mp)
//! auth   = HKDF-Expand(root, "keyless/v1 auth secret")[32]   -> sent to the server to sign in
//! kek    = HKDF-Expand(root, "keyless/v1 key encryption key")[32] -> never leaves the device
//! ```
//!
//! The server stores only a password hash of `auth`, which reveals nothing
//! about `kek`. Because of the Secret Key, a stolen server database cannot be
//! attacked by guessing master passwords: each guess would also need 128
//! unknown random bits.

use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::{
    Error, Result,
    crypto::{SymmetricKey, random_array},
    encoding::{crockford_decode, crockford_encode},
};

pub const SECRET_KEY_LEN: usize = 16;
const SECRET_KEY_VERSION: &str = "K1";
/// 26 data symbols + 1 checksum symbol.
const SECRET_KEY_SYMBOLS: usize = 27;
const SECRET_KEY_GROUPS: [usize; 5] = [6, 6, 5, 5, 5];

/// Argon2id parameters. Stored with the account so they can be raised later.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    pub alg: String,
    /// Memory in KiB.
    pub m: u32,
    /// Iterations.
    pub t: u32,
    /// Lanes.
    pub p: u32,
}

impl KdfParams {
    /// Canonical text form, bound into the encryption of the user key so the
    /// parameters cannot be swapped without detection.
    pub fn canonical(&self) -> String {
        format!("{}:m={}:t={}:p={}", self.alg, self.m, self.t, self.p)
    }

    /// 64 MiB, 3 iterations, 4 lanes. Chosen to stay usable on phones (iOS
    /// autofill extensions are memory constrained) while being far above the
    /// OWASP minimum. The Secret Key already makes offline guessing infeasible;
    /// Argon2id is the second line of defence if a device is stolen.
    pub fn recommended() -> Self {
        Self { alg: "argon2id".into(), m: 64 * 1024, t: 3, p: 4 }
    }

    /// Rejects parameters below our floor (protects against a malicious server
    /// trying to weaken derivation) and absurdly high ones (protects against a
    /// server trying to exhaust the device's memory).
    pub fn validate(&self) -> Result<()> {
        // Upper bounds: 1 GiB, 10 passes, 8 lanes.
        let ok = self.alg == "argon2id"
            && (64 * 1024..=1024 * 1024).contains(&self.m)
            && (3..=10).contains(&self.t)
            && (1..=8).contains(&self.p);
        if ok { Ok(()) } else { Err(Error::UnsafeKdfParams) }
    }
}

/// The account Secret Key. Wiped on drop, never printed by `Debug`.
pub struct SecretKey(Zeroizing<[u8; SECRET_KEY_LEN]>);

impl SecretKey {
    pub fn generate() -> Result<Self> {
        Ok(Self(random_array()?))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let array: [u8; SECRET_KEY_LEN] = bytes.try_into().map_err(|_| Error::InvalidSecretKey)?;
        Ok(Self(Zeroizing::new(array)))
    }

    pub fn as_bytes(&self) -> &[u8; SECRET_KEY_LEN] {
        &self.0
    }

    /// Human-readable form, e.g. `K1-ABCDEF-GHJKMN-PQRST-VWXYZ-01234`.
    pub fn to_display(&self) -> Zeroizing<String> {
        let mut symbols = crockford_encode(self.0.as_ref());
        symbols.push(checksum_symbol(&self.0));

        let mut out = Zeroizing::new(String::from(SECRET_KEY_VERSION));
        let mut start = 0;
        for len in SECRET_KEY_GROUPS {
            out.push('-');
            out.push_str(&symbols[start..start + len]);
            start += len;
        }
        out
    }

    /// Parses the display form, tolerating case, spaces, missing dashes and
    /// common look-alike characters. The checksum catches most typos.
    pub fn parse(input: &str) -> Result<Self> {
        let compact = Zeroizing::new(
            input
                .chars()
                .filter(|c| !c.is_whitespace() && *c != '-')
                .collect::<String>()
                .to_ascii_uppercase(),
        );
        let body = compact
            .strip_prefix(SECRET_KEY_VERSION)
            .ok_or(Error::InvalidSecretKey)?;
        if body.len() != SECRET_KEY_SYMBOLS || !body.is_ascii() {
            return Err(Error::InvalidSecretKey);
        }
        let (data, check) = body.split_at(SECRET_KEY_SYMBOLS - 1);
        let bytes = crockford_decode(data, SECRET_KEY_LEN).ok_or(Error::InvalidSecretKey)?;
        let key = Self::from_bytes(&bytes)?;

        let expected = checksum_symbol(&key.0);
        let given = normalize_symbol(check.chars().next().ok_or(Error::InvalidSecretKey)?);
        if (expected as u8).ct_eq(&(given as u8)).into() {
            Ok(key)
        } else {
            Err(Error::InvalidSecretKey)
        }
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretKey(<redacted>)")
    }
}

fn checksum_symbol(bytes: &[u8; SECRET_KEY_LEN]) -> char {
    let digest = Sha256::new()
        .chain_update(b"keyless/v1/secret-key-checksum")
        .chain_update(bytes)
        .finalize();
    crockford_encode(&[digest[0] & 0xF8])
        .chars()
        .next()
        .expect("one byte encodes to two symbols")
}

fn normalize_symbol(c: char) -> char {
    match c.to_ascii_uppercase() {
        'O' => '0',
        'I' | 'L' => '1',
        other => other,
    }
}

/// Keys derived from the master password and Secret Key.
pub struct AccountKeys {
    /// Sent to the server as the sign-in password (base64url, 43 chars).
    pub auth_secret: Zeroizing<String>,
    /// Wraps the account's user key. Never leaves the device.
    pub kek: SymmetricKey,
}

impl std::fmt::Debug for AccountKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AccountKeys(<redacted>)")
    }
}

/// Normalises a master password the same way on every platform.
pub fn normalize_master_password(master_password: &str) -> Zeroizing<String> {
    Zeroizing::new(master_password.trim().nfkd().collect())
}

pub fn derive_account_keys(
    master_password: &str,
    secret_key: &SecretKey,
    params: &KdfParams,
) -> Result<AccountKeys> {
    params.validate()?;
    let password = normalize_master_password(master_password);
    if password.is_empty() {
        return Err(Error::EmptyPassword);
    }

    let mut salt = Zeroizing::new([0u8; 16]);
    Hkdf::<Sha256>::new(Some(b"keyless/v1/kdf-salt"), secret_key.as_bytes())
        .expand(b"argon2id salt", salt.as_mut())
        .map_err(|_| Error::Kdf)?;

    let argon_params = Params::new(params.m, params.t, params.p, Some(32)).map_err(|_| Error::Kdf)?;
    let mut k_mp = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params)
        .hash_password_into(password.as_bytes(), salt.as_ref(), k_mp.as_mut())
        .map_err(|_| Error::Kdf)?;

    let mut k_sk = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(b"keyless/v1/secret-key"), secret_key.as_bytes())
        .expand(b"2skd", k_sk.as_mut())
        .map_err(|_| Error::Kdf)?;

    let root = Hkdf::<Sha256>::new(Some(k_sk.as_ref()), k_mp.as_ref());

    let mut auth = Zeroizing::new([0u8; 32]);
    root.expand(b"keyless/v1 auth secret", auth.as_mut())
        .map_err(|_| Error::Kdf)?;
    let mut kek = Zeroizing::new([0u8; 32]);
    root.expand(b"keyless/v1 key encryption key", kek.as_mut())
        .map_err(|_| Error::Kdf)?;

    Ok(AccountKeys {
        auth_secret: Zeroizing::new(URL_SAFE_NO_PAD.encode(auth.as_ref())),
        kek: SymmetricKey::from_slice(kek.as_ref())?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast_params() -> KdfParams {
        KdfParams::recommended()
    }

    #[test]
    fn secret_key_display_roundtrip() {
        let key = SecretKey::generate().unwrap();
        let display = key.to_display();
        assert!(display.starts_with("K1-"));
        assert_eq!(display.len(), 2 + 5 + SECRET_KEY_SYMBOLS);
        let parsed = SecretKey::parse(&display).unwrap();
        assert_eq!(parsed.as_bytes(), key.as_bytes());

        let sloppy = display.to_lowercase().replace('-', " ");
        assert_eq!(SecretKey::parse(&sloppy).unwrap().as_bytes(), key.as_bytes());
    }

    #[test]
    fn secret_key_checksum_catches_typos() {
        let key = SecretKey::generate().unwrap();
        let display = key.to_display();
        let mut rejected = 0;
        let mut total = 0;
        for (i, c) in display.char_indices().skip(3) {
            if c == '-' {
                continue;
            }
            let replacement = if c == 'Z' { 'Y' } else { 'Z' };
            let mut typo = display.to_string();
            typo.replace_range(i..i + 1, &replacement.to_string());
            total += 1;
            if SecretKey::parse(&typo).is_err() {
                rejected += 1;
            }
        }
        // A 5-bit checksum misses roughly 1 in 32 single-symbol typos.
        assert!(rejected * 10 >= total * 8, "{rejected}/{total}");
    }

    #[test]
    fn secret_key_rejects_garbage() {
        for bad in ["", "K1", "K2-AAAAAA-AAAAAA-AAAAA-AAAAA-AAAAA", "K1-AAAAAA-AAAAAA-AAAAA-AAAAA-AAAA"] {
            assert!(SecretKey::parse(bad).is_err(), "{bad} accepted");
        }
    }

    #[test]
    fn derivation_is_deterministic_and_separated() {
        let sk = SecretKey::from_bytes(&[7u8; 16]).unwrap();
        let a = derive_account_keys("correct horse", &sk, &fast_params()).unwrap();
        let b = derive_account_keys("  correct horse ", &sk, &fast_params()).unwrap();
        assert_eq!(a.auth_secret, b.auth_secret);
        assert_eq!(a.kek.as_bytes(), b.kek.as_bytes());
        assert_eq!(a.auth_secret.len(), 43);
        assert_ne!(URL_SAFE_NO_PAD.decode(a.auth_secret.as_bytes()).unwrap(), a.kek.as_bytes());

        let other_password = derive_account_keys("correct horsf", &sk, &fast_params()).unwrap();
        assert_ne!(a.kek.as_bytes(), other_password.kek.as_bytes());

        let other_sk = SecretKey::from_bytes(&[8u8; 16]).unwrap();
        let other_key = derive_account_keys("correct horse", &other_sk, &fast_params()).unwrap();
        assert_ne!(a.kek.as_bytes(), other_key.kek.as_bytes());
        assert_ne!(a.auth_secret, other_key.auth_secret);
    }

    #[test]
    fn unicode_passwords_are_normalized() {
        let sk = SecretKey::from_bytes(&[1u8; 16]).unwrap();
        // "é" precomposed vs. "e" + combining acute accent.
        let a = derive_account_keys("caf\u{00e9}", &sk, &fast_params()).unwrap();
        let b = derive_account_keys("cafe\u{0301}", &sk, &fast_params()).unwrap();
        assert_eq!(a.kek.as_bytes(), b.kek.as_bytes());
    }

    #[test]
    fn weak_or_absurd_params_are_rejected() {
        let sk = SecretKey::generate().unwrap();
        let mut weak = KdfParams::recommended();
        weak.m = 1024;
        assert!(matches!(derive_account_keys("pw", &sk, &weak), Err(Error::UnsafeKdfParams)));
        let mut huge = KdfParams::recommended();
        huge.m = 2 * 1024 * 1024;
        assert!(matches!(derive_account_keys("pw", &sk, &huge), Err(Error::UnsafeKdfParams)));
        let mut other_alg = KdfParams::recommended();
        other_alg.alg = "pbkdf2".into();
        assert!(other_alg.validate().is_err());
    }

    #[test]
    fn empty_password_is_rejected() {
        let sk = SecretKey::generate().unwrap();
        assert!(matches!(
            derive_account_keys("   ", &sk, &fast_params()),
            Err(Error::EmptyPassword)
        ));
    }
}
