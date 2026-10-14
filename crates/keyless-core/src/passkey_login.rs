//! Signing in to Keyless with a passkey, like 1Password's "unlock with a
//! passkey": the WebAuthn PRF extension gives a secret only the
//! authenticator can produce (after the user unlocks it), from which come a
//! proof for the server and a key that opens what signing in needs.
//!
//! ```text
//! salt   = SHA-256("keyless/v1/passkey-prf")          (the same for every passkey)
//! prf    = WebAuthn PRF(credential, salt)              (32 bytes, never leaves the device)
//! proof  = HKDF(ikm = prf, salt = "keyless/v1/passkey", info = "proof" | credential id)[32]
//! key    = HKDF(ikm = prf, salt = "keyless/v1/passkey", info = "key" | credential id)[32]
//! bundle = seal(key, {email, auth secret, user key, Secret Key}, "passkey-bundle" | user id | credential id)
//! ```
//!
//! The server keeps the SHA-256 of the proof and the bundle. To sign in, the
//! device asks the authenticator for the PRF output, sends the proof, gets
//! the bundle back, signs in with the auth secret and opens the account with
//! the user key, and keeps the Secret Key so the master password unlocks it
//! from then on. The salt is fixed (as Bitwarden's) so a passkey can be
//! chosen before the account is known; the output still differs for every
//! passkey.
//!
//! A bundle holds the auth secret of its time: changing the master password
//! or the Secret Key makes the server drop the account's passkeys.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    Error, Result,
    crypto::{SymmetricKey, context},
};

/// The PRF input every Keyless passkey is asked with.
pub fn prf_salt() -> [u8; 32] {
    Sha256::digest(b"keyless/v1/passkey-prf").into()
}

/// What signing in with a passkey opens.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyBundle {
    pub email: String,
    pub auth_secret: Zeroizing<String>,
    /// base64url.
    pub user_key: Zeroizing<String>,
    pub secret_key: Zeroizing<String>,
}

impl std::fmt::Debug for PasskeyBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasskeyBundle").field("email", &self.email).finish_non_exhaustive()
    }
}

/// The proof and key derived from a passkey's PRF output.
pub struct PasskeyKeys {
    proof: Zeroizing<String>,
    key: SymmetricKey,
    credential_id: String,
}

impl PasskeyKeys {
    /// From the PRF output (32 bytes) of the passkey `credential_id`
    /// (base64url, as WebAuthn gives it).
    pub fn derive(prf_output: &[u8], credential_id: &str) -> Result<Self> {
        if prf_output.len() != 32 || credential_id.is_empty() {
            return Err(Error::InvalidKey);
        }
        let hkdf = Hkdf::<Sha256>::new(Some(b"keyless/v1/passkey"), prf_output);
        let expand = |label: &[u8]| -> Result<Zeroizing<[u8; 32]>> {
            let mut out = Zeroizing::new([0u8; 32]);
            hkdf.expand(&[label, b"|", credential_id.as_bytes()].concat(), out.as_mut()).map_err(|_| Error::Kdf)?;
            Ok(out)
        };
        Ok(Self {
            proof: Zeroizing::new(URL_SAFE_NO_PAD.encode(expand(b"proof")?.as_ref())),
            key: SymmetricKey::from_slice(expand(b"key")?.as_ref())?,
            credential_id: credential_id.to_string(),
        })
    }

    /// Sent to the server (which keeps only its hash).
    pub fn proof(&self) -> &str {
        &self.proof
    }

    fn context(&self, user_id: &str) -> Vec<u8> {
        context("passkey-bundle", &[user_id, &self.credential_id])
    }

    pub fn seal(&self, user_id: &str, bundle: &PasskeyBundle) -> Result<String> {
        let json = Zeroizing::new(serde_json::to_vec(bundle)?);
        self.key.seal(&json, &self.context(user_id))
    }

    pub fn open(&self, user_id: &str, envelope: &str) -> Result<PasskeyBundle> {
        let json = self.key.open(envelope, &self.context(user_id))?;
        serde_json::from_slice(&json).map_err(Error::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle() -> PasskeyBundle {
        PasskeyBundle {
            email: "me@example.com".into(),
            auth_secret: Zeroizing::new("a".repeat(43)),
            user_key: Zeroizing::new("k".repeat(43)),
            secret_key: Zeroizing::new("K1-AAAAAA-BBBBBB-CCCCC-DDDDD-EEEEE".into()),
        }
    }

    #[test]
    fn round_trip_bound_to_the_passkey_and_account() {
        let prf = [7u8; 32];
        let keys = PasskeyKeys::derive(&prf, "cred-1").unwrap();
        assert_eq!(keys.proof().len(), 43);
        let sealed = keys.seal("user-1", &bundle()).unwrap();
        assert_eq!(PasskeyKeys::derive(&prf, "cred-1").unwrap().open("user-1", &sealed).unwrap().email, "me@example.com");
        // Another passkey, account or PRF output opens nothing.
        assert!(PasskeyKeys::derive(&prf, "cred-2").unwrap().open("user-1", &sealed).is_err());
        assert!(keys.open("user-2", &sealed).is_err());
        assert!(PasskeyKeys::derive(&[8u8; 32], "cred-1").unwrap().open("user-1", &sealed).is_err());
        // Proofs differ per passkey.
        assert_ne!(PasskeyKeys::derive(&prf, "cred-2").unwrap().proof(), keys.proof());
        assert!(PasskeyKeys::derive(&[1u8; 16], "cred-1").is_err());
    }

    #[test]
    fn the_salt_is_fixed() {
        assert_eq!(prf_salt(), prf_salt());
        assert_eq!(prf_salt().len(), 32);
    }
}
