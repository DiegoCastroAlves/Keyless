//! Account key hierarchy.
//!
//! ```text
//! kek (from master password + Secret Key)
//!  └─ user key (random, 256-bit)            enc_user_key    = seal(kek, user_key, "user-key" | user id | kdf)
//!      ├─ X25519 private key (for sharing)  enc_private_key = seal(user_key, private_key, "private-key" | user id)
//!      └─ vault keys                        enc_vault_key   = seal(user_key, vault_key, "vault-key" | vault id)
//! ```
//!
//! The user id and the Argon2id parameters are bound into the encryption of
//! the user key, so a server cannot swap in another account's bundle or
//! change the parameters (e.g. to make every unlock take minutes) without
//! decryption failing.
//!
//! Changing the master password only re-wraps the user key; nothing else has
//! to be re-encrypted.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::{
    Error, Result,
    crypto::{SymmetricKey, context, random_array},
    keys::KdfParams,
};

pub const ACCOUNT_FORMAT: u16 = 2;

fn user_key_context(user_id: &str, kdf: &KdfParams) -> Vec<u8> {
    context("user-key", &[user_id, &kdf.canonical()])
}

fn private_key_context(user_id: &str) -> Vec<u8> {
    context("private-key", &[user_id])
}

/// Everything the server stores about an account's keys. All secret parts are
/// encrypted; the public key is public by design.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountBundle {
    pub format: u16,
    pub kdf: KdfParams,
    pub enc_user_key: String,
    pub public_key: String,
    pub enc_private_key: String,
}

/// An unlocked account: the decrypted user key and key pair.
pub struct UnlockedAccount {
    user_key: SymmetricKey,
    private_key: StaticSecret,
    public_key: PublicKey,
}

impl UnlockedAccount {
    pub fn user_key(&self) -> &SymmetricKey {
        &self.user_key
    }

    pub fn private_key(&self) -> &StaticSecret {
        &self.private_key
    }

    pub fn public_key_encoded(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.public_key.as_bytes())
    }
}

impl std::fmt::Debug for UnlockedAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UnlockedAccount(<redacted>)")
    }
}

/// Creates the key hierarchy for a new account.
pub fn create_account(kek: &SymmetricKey, kdf: KdfParams, user_id: &str) -> Result<(AccountBundle, UnlockedAccount)> {
    kdf.validate()?;
    let user_key = SymmetricKey::generate()?;
    let private_bytes = random_array::<32>()?;
    let private_key = StaticSecret::from(*private_bytes);
    let public_key = PublicKey::from(&private_key);

    let bundle = AccountBundle {
        format: ACCOUNT_FORMAT,
        enc_user_key: kek.seal(user_key.as_bytes(), &user_key_context(user_id, &kdf))?,
        kdf,
        public_key: URL_SAFE_NO_PAD.encode(public_key.as_bytes()),
        enc_private_key: user_key.seal(private_bytes.as_ref(), &private_key_context(user_id))?,
    };
    Ok((bundle, UnlockedAccount { user_key, private_key, public_key }))
}

/// Decrypts the account keys. Fails with [`Error::Decryption`] when the master
/// password or Secret Key is wrong, or the bundle was tampered with.
pub fn unlock_account(bundle: &AccountBundle, kek: &SymmetricKey, user_id: &str) -> Result<UnlockedAccount> {
    if bundle.format != ACCOUNT_FORMAT {
        return Err(Error::Serialization(format!("unsupported account format {}", bundle.format)));
    }
    bundle.kdf.validate()?;
    let user_key_bytes = kek.open(&bundle.enc_user_key, &user_key_context(user_id, &bundle.kdf))?;
    let user_key = SymmetricKey::from_slice(&user_key_bytes)?;

    let private_bytes = user_key.open(&bundle.enc_private_key, &private_key_context(user_id))?;
    let private_array: Zeroizing<[u8; 32]> =
        Zeroizing::new(private_bytes.as_slice().try_into().map_err(|_| Error::InvalidKey)?);
    let private_key = StaticSecret::from(*private_array);
    let public_key = PublicKey::from(&private_key);

    // The public key is stored unencrypted on the server. Make sure it still
    // matches our private key so a tampered value is noticed immediately.
    if URL_SAFE_NO_PAD.encode(public_key.as_bytes()) != bundle.public_key {
        return Err(Error::InvalidKey);
    }
    Ok(UnlockedAccount { user_key, private_key, public_key })
}

/// Re-wraps the user key under a new kek (master password change). Returns
/// the bundle to upload; the user key and everything below it is unchanged.
pub fn rewrap_account(
    bundle: &AccountBundle,
    account: &UnlockedAccount,
    new_kek: &SymmetricKey,
    new_kdf: KdfParams,
    user_id: &str,
) -> Result<AccountBundle> {
    new_kdf.validate()?;
    Ok(AccountBundle {
        format: ACCOUNT_FORMAT,
        enc_user_key: new_kek.seal(account.user_key.as_bytes(), &user_key_context(user_id, &new_kdf))?,
        kdf: new_kdf,
        public_key: bundle.public_key.clone(),
        enc_private_key: bundle.enc_private_key.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_unlock() {
        let kek = SymmetricKey::generate().unwrap();
        let (bundle, account) = create_account(&kek, KdfParams::recommended(), "u1").unwrap();
        let unlocked = unlock_account(&bundle, &kek, "u1").unwrap();
        assert_eq!(unlocked.user_key().as_bytes(), account.user_key().as_bytes());
        assert_eq!(unlocked.public_key_encoded(), bundle.public_key);
    }

    #[test]
    fn wrong_kek_fails() {
        let kek = SymmetricKey::generate().unwrap();
        let (bundle, _) = create_account(&kek, KdfParams::recommended(), "u1").unwrap();
        let wrong = SymmetricKey::generate().unwrap();
        assert!(matches!(unlock_account(&bundle, &wrong, "u1"), Err(Error::Decryption)));
    }

    #[test]
    fn bundle_is_bound_to_user_and_kdf() {
        let kek = SymmetricKey::generate().unwrap();
        let (bundle, _) = create_account(&kek, KdfParams::recommended(), "u1").unwrap();
        // Another account id.
        assert!(unlock_account(&bundle, &kek, "u2").is_err());
        // Server-side change of the KDF parameters.
        let mut tampered = bundle.clone();
        tampered.kdf.t = 4;
        assert!(matches!(unlock_account(&tampered, &kek, "u1"), Err(Error::Decryption)));
    }

    #[test]
    fn swapped_public_key_is_detected() {
        let kek = SymmetricKey::generate().unwrap();
        let (mut bundle, _) = create_account(&kek, KdfParams::recommended(), "u1").unwrap();
        let (other, _) = create_account(&kek, KdfParams::recommended(), "u1").unwrap();
        bundle.public_key = other.public_key;
        assert!(unlock_account(&bundle, &kek, "u1").is_err());
    }

    #[test]
    fn rewrap_keeps_user_key() {
        let kek = SymmetricKey::generate().unwrap();
        let (bundle, account) = create_account(&kek, KdfParams::recommended(), "u1").unwrap();
        let new_kek = SymmetricKey::generate().unwrap();
        let rewrapped = rewrap_account(&bundle, &account, &new_kek, KdfParams::recommended(), "u1").unwrap();
        assert!(unlock_account(&rewrapped, &kek, "u1").is_err());
        let unlocked = unlock_account(&rewrapped, &new_kek, "u1").unwrap();
        assert_eq!(unlocked.user_key().as_bytes(), account.user_key().as_bytes());
    }
}
