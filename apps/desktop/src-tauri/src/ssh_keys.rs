//! SSH keys kept in items (the "SSH key" category): reading the private key
//! the user pasted or generated, its public key and fingerprint, and signing
//! for the SSH agent (see `ssh_agent`).
//!
//! Private keys are stored unencrypted inside the item, which the vault
//! encrypts like any other secret; a passphrase-protected key is decrypted
//! once, when it is added.

use rsa::{
    pkcs1::DecodeRsaPrivateKey,
    pkcs1v15::SigningKey,
    sha2::{Sha256, Sha512},
    signature::{SignatureEncoding, Signer as _},
};
use serde::Serialize;
use ssh_key::{
    Algorithm, HashAlg, LineEnding, PrivateKey, Signature,
    private::{KeypairData, RsaKeypair},
    rand_core::OsRng,
};
use zeroize::Zeroizing;

use crate::error::{AppError, AppResult, Msg};

/// Flags of an agent sign request (draft-miller-ssh-agent, 3.6.1).
const RSA_SHA2_256: u32 = 2;
const RSA_SHA2_512: u32 = 4;

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

fn invalid(key: &'static str) -> AppError {
    AppError::Invalid(Msg::new(key))
}

/// A PEM block typed or pasted where line breaks were lost (single-line
/// fields turn them into spaces): puts them back.
pub(crate) fn normalize_pem(text: &str) -> Zeroizing<String> {
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

/// Reads a private key: OpenSSH format (decrypted with `passphrase` when it
/// has one) or a PKCS#1 RSA key.
pub fn parse_private(text: &str, passphrase: Option<&str>) -> AppResult<PrivateKey> {
    let pem = normalize_pem(text);
    if pem.contains("BEGIN RSA PRIVATE KEY") {
        if pem.contains("ENCRYPTED") {
            return Err(invalid("ssh_key_unsupported"));
        }
        let rsa = rsa::RsaPrivateKey::from_pkcs1_pem(&pem).map_err(|_| invalid("ssh_key_invalid"))?;
        let keypair = RsaKeypair::try_from(rsa).map_err(|_| invalid("ssh_key_invalid"))?;
        return PrivateKey::new(KeypairData::Rsa(keypair), "").map_err(|_| invalid("ssh_key_invalid"));
    }
    let key = PrivateKey::from_openssh(pem.as_bytes()).map_err(|_| invalid("ssh_key_invalid"))?;
    if !key.is_encrypted() {
        return Ok(key);
    }
    let passphrase = passphrase.filter(|p| !p.is_empty()).ok_or_else(|| invalid("ssh_key_passphrase"))?;
    key.decrypt(passphrase).map_err(|_| invalid("ssh_key_wrong_passphrase"))
}

fn fields(key: &PrivateKey) -> AppResult<SshKeyFields> {
    let private_key = key.to_openssh(LineEnding::LF).map_err(|_| invalid("ssh_key_invalid"))?;
    Ok(SshKeyFields {
        private_key: private_key.to_string(),
        public_key: key.public_key().to_openssh().map_err(|_| invalid("ssh_key_invalid"))?,
        fingerprint: key.fingerprint(HashAlg::Sha256).to_string(),
    })
}

/// The fields of an SSH key item for a pasted private key.
pub fn import(text: &str, passphrase: Option<&str>, comment: &str) -> AppResult<SshKeyFields> {
    let mut key = parse_private(text, passphrase)?;
    if key.comment().is_empty() && !comment.trim().is_empty() {
        key.set_comment(comment.trim());
    }
    fields(&key)
}

/// A new Ed25519 key.
pub fn generate(comment: &str) -> AppResult<SshKeyFields> {
    let mut key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).map_err(|e| AppError::Server(e.to_string()))?;
    key.set_comment(comment.trim());
    fields(&key)
}

/// Signs for the agent. RSA keys sign with SHA-256 or SHA-512 as the client
/// asks; SHA-1 (`ssh-rsa`) is refused.
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
    use ssh_key::{PublicKey, SshSig};

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
