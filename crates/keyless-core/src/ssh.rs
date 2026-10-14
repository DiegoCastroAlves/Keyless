//! SSH keys kept in items (the "SSH key" category): putting back a private
//! key's line breaks, and, with the `ssh` feature, reading a pasted key
//! (decrypting it once when it has a passphrase) and making new ones, with
//! the public key and fingerprint the item shows.
//!
//! Private keys are stored unencrypted inside the item, which the vault
//! encrypts like any other secret.

use zeroize::Zeroizing;

/// A PEM block typed or pasted where line breaks were lost (single-line
/// fields turn them into spaces): puts them back.
pub fn normalize_pem(text: &str) -> Zeroizing<String> {
    let text = text.trim();
    let Some(begin_end) = text.find("-----BEGIN ").and_then(|b| text[b + 11..].find("-----").map(|e| b + 11 + e + 5)) else {
        return Zeroizing::new(text.to_string());
    };
    let Some(end_start) = text.find("-----END ") else { return Zeroizing::new(text.to_string()) };
    let header = &text[..begin_end];
    let footer = &text[end_start..];
    let body: String = text[begin_end..end_start].split_whitespace().collect();
    let mut lines = Zeroizing::new(String::new());
    lines.push_str(header.trim());
    lines.push('\n');
    for chunk in body.as_bytes().chunks(70) {
        lines.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        lines.push('\n');
    }
    lines.push_str(footer.trim());
    lines.push('\n');
    lines
}

#[cfg(feature = "ssh")]
pub use keys::*;

#[cfg(feature = "ssh")]
mod keys {
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use serde::Serialize;
    use ssh_key::{
        Algorithm, HashAlg, LineEnding, PrivateKey,
        private::{KeypairData, RsaKeypair},
        rand_core::OsRng,
    };

    use super::normalize_pem;

    /// Why a key cannot be read: a key the apps translate
    /// (`ssh_key_invalid`, `ssh_key_unsupported`, `ssh_key_passphrase`,
    /// `ssh_key_wrong_passphrase`).
    #[derive(Debug, PartialEq, Eq)]
    pub struct SshKeyError(pub &'static str);

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct SshKeyFields {
        /// OpenSSH private key, unencrypted.
        pub private_key: String,
        /// `ssh-ed25519 AAAA… comment`.
        pub public_key: String,
        /// `SHA256:…`.
        pub fingerprint: String,
    }

    /// Reads a private key: OpenSSH format (decrypted with `passphrase` when
    /// it has one) or a PKCS#1 RSA key.
    pub fn parse_private(text: &str, passphrase: Option<&str>) -> Result<PrivateKey, SshKeyError> {
        let invalid = |_| SshKeyError("ssh_key_invalid");
        let pem = normalize_pem(text);
        if pem.contains("BEGIN RSA PRIVATE KEY") {
            if pem.contains("ENCRYPTED") {
                return Err(SshKeyError("ssh_key_unsupported"));
            }
            let rsa = rsa::RsaPrivateKey::from_pkcs1_pem(&pem).map_err(|_| SshKeyError("ssh_key_invalid"))?;
            let keypair = RsaKeypair::try_from(rsa).map_err(invalid)?;
            return PrivateKey::new(KeypairData::Rsa(keypair), "").map_err(invalid);
        }
        let key = PrivateKey::from_openssh(pem.as_bytes()).map_err(invalid)?;
        if !key.is_encrypted() {
            return Ok(key);
        }
        let passphrase = passphrase.filter(|p| !p.is_empty()).ok_or(SshKeyError("ssh_key_passphrase"))?;
        key.decrypt(passphrase).map_err(|_| SshKeyError("ssh_key_wrong_passphrase"))
    }

    fn fields(key: &PrivateKey) -> Result<SshKeyFields, SshKeyError> {
        let invalid = |_| SshKeyError("ssh_key_invalid");
        let private_key = key.to_openssh(LineEnding::LF).map_err(invalid)?;
        Ok(SshKeyFields {
            private_key: private_key.to_string(),
            public_key: key.public_key().to_openssh().map_err(invalid)?,
            fingerprint: key.fingerprint(HashAlg::Sha256).to_string(),
        })
    }

    /// The fields of an SSH key item for a pasted private key.
    pub fn import(text: &str, passphrase: Option<&str>, comment: &str) -> Result<SshKeyFields, SshKeyError> {
        let mut key = parse_private(text, passphrase)?;
        if key.comment().is_empty() && !comment.trim().is_empty() {
            key.set_comment(comment.trim());
        }
        fields(&key)
    }

    /// A new Ed25519 key.
    pub fn generate(comment: &str) -> Result<SshKeyFields, SshKeyError> {
        let mut key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).map_err(|_| SshKeyError("ssh_key_invalid"))?;
        key.set_comment(comment.trim());
        fields(&key)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn generates_and_imports() {
            let generated = generate("ana@laptop").unwrap();
            assert!(generated.public_key.starts_with("ssh-ed25519 "));
            assert!(generated.public_key.ends_with(" ana@laptop"));
            assert!(generated.fingerprint.starts_with("SHA256:"));
            // Pasted into a single-line field: line breaks became spaces.
            let flattened = generated.private_key.replace('\n', " ");
            let again = import(&flattened, None, "").unwrap();
            assert_eq!(again.fingerprint, generated.fingerprint);
            assert_eq!(again.private_key, generated.private_key);
        }

        #[test]
        fn passphrase_protected_keys() {
            let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
            let encrypted = key.encrypt(&mut OsRng, "correct horse").unwrap().to_openssh(LineEnding::LF).unwrap();
            assert_eq!(parse_private(&encrypted, None).unwrap_err(), SshKeyError("ssh_key_passphrase"));
            assert_eq!(parse_private(&encrypted, Some("wrong")).unwrap_err(), SshKeyError("ssh_key_wrong_passphrase"));
            let opened = parse_private(&encrypted, Some("correct horse")).unwrap();
            assert_eq!(opened.fingerprint(HashAlg::Sha256), key.fingerprint(HashAlg::Sha256));
            assert!(parse_private("not a key", None).is_err());
        }
    }
}
