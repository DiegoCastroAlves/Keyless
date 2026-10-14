//! SSH keys kept in items (the "SSH key" category): reading the private key
//! the user pasted or generated, its public key and fingerprint, and signing
//! for the SSH agent (see `ssh_agent`).
//!
//! Reading and making keys is `keyless_core::ssh`, shared with the Android
//! app.

use rsa::{
    pkcs1v15::SigningKey,
    sha2::{Sha256, Sha512},
    signature::{SignatureEncoding, Signer as _},
};
use ssh_key::{Algorithm, PrivateKey, Signature, private::KeypairData};

use crate::error::{AppError, AppResult, Msg};

/// Flags of an agent sign request (draft-miller-ssh-agent, 3.6.1).
#[cfg_attr(not(unix), allow(dead_code))]
const RSA_SHA2_256: u32 = 2;
#[cfg_attr(not(unix), allow(dead_code))]
const RSA_SHA2_512: u32 = 4;

pub use keyless_core::ssh::{SshKeyFields, normalize_pem};

fn invalid(err: keyless_core::ssh::SshKeyError) -> AppError {
    AppError::Invalid(Msg::new(err.0))
}

/// Reads a private key: OpenSSH format (decrypted with `passphrase` when it
/// has one) or a PKCS#1 RSA key.
pub fn parse_private(text: &str, passphrase: Option<&str>) -> AppResult<PrivateKey> {
    keyless_core::ssh::parse_private(text, passphrase).map_err(invalid)
}

/// The fields of an SSH key item for a pasted private key.
pub fn import(text: &str, passphrase: Option<&str>, comment: &str) -> AppResult<SshKeyFields> {
    keyless_core::ssh::import(text, passphrase, comment).map_err(invalid)
}

/// A new Ed25519 key.
pub fn generate(comment: &str) -> AppResult<SshKeyFields> {
    keyless_core::ssh::generate(comment).map_err(invalid)
}

/// Signs for the agent. RSA keys sign with SHA-256 or SHA-512 as the client
/// asks; SHA-1 (`ssh-rsa`) is refused.
#[cfg_attr(not(unix), allow(dead_code))]
pub fn sign(key: &PrivateKey, data: &[u8], flags: u32) -> AppResult<Signature> {
    let failed = |e: String| AppError::Server(format!("ssh signature: {e}"));
    match key.key_data() {
        KeypairData::Rsa(keypair) => {
            let private = rsa::RsaPrivateKey::try_from(keypair).map_err(|e| failed(e.to_string()))?;
            let (name, bytes) = if flags & RSA_SHA2_512 != 0 {
                ("rsa-sha2-512", SigningKey::<Sha512>::new(private).sign(data).to_vec())
            } else if flags & RSA_SHA2_256 != 0 {
                ("rsa-sha2-256", SigningKey::<Sha256>::new(private).sign(data).to_vec())
            } else {
                return Err(failed("ssh-rsa (SHA-1) signatures are not supported".into()));
            };
            Signature::new(Algorithm::new(name).map_err(|e| failed(e.to_string()))?, bytes).map_err(|e| failed(e.to_string()))
        }
        _ => key.try_sign(data).map_err(|e| failed(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use ssh_key::{HashAlg, LineEnding, PublicKey, SshSig, rand_core::OsRng};

    use super::*;

    #[test]
    fn generate_import_and_sign() {
        let generated = generate("ana@laptop").unwrap();
        assert!(generated.public_key.starts_with("ssh-ed25519 "));
        assert!(generated.public_key.ends_with(" ana@laptop"));
        assert!(generated.fingerprint.starts_with("SHA256:"));
        // Pasted into a single-line field: line breaks became spaces.
        let flattened = generated.private_key.replace('\n', " ");
        let again = import(&flattened, None, "").unwrap();
        assert_eq!(again.fingerprint, generated.fingerprint);

        let key = parse_private(&generated.private_key, None).unwrap();
        let signature = sign(&key, b"data", 0).unwrap();
        let public = PublicKey::from_openssh(&generated.public_key).unwrap();
        assert!(public.key_data().ed25519().is_some());
        assert_eq!(signature.algorithm(), Algorithm::Ed25519);
        let _ = SshSig::new(public.key_data().clone(), "test", HashAlg::Sha512, signature);
    }

    #[test]
    fn passphrase_protected_keys() {
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let encrypted = key.encrypt(&mut OsRng, "correct horse").unwrap().to_openssh(LineEnding::LF).unwrap();
        assert!(matches!(parse_private(&encrypted, None), Err(AppError::Invalid(m)) if m.key == "ssh_key_passphrase"));
        assert!(matches!(parse_private(&encrypted, Some("wrong")), Err(AppError::Invalid(m)) if m.key == "ssh_key_wrong_passphrase"));
        let opened = parse_private(&encrypted, Some("correct horse")).unwrap();
        assert_eq!(opened.fingerprint(HashAlg::Sha256), key.fingerprint(HashAlg::Sha256));
        assert!(parse_private("not a key", None).is_err());
    }
}
