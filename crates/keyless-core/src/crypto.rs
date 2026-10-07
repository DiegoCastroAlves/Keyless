//! Symmetric encryption primitives.
//!
//! Every ciphertext Keyless produces is an XChaCha20-Poly1305 "envelope":
//!
//! ```text
//! k1.<base64url(nonce[24] || ciphertext || tag[16])>
//! ```
//!
//! The 24-byte nonce is random per message, which is safe for XChaCha20 at any
//! realistic volume. Each envelope is bound to a *context* (passed as AAD) that
//! names what the ciphertext is and which objects it belongs to, so a server
//! cannot swap ciphertexts between items, vaults or purposes without the
//! decryption failing.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use zeroize::Zeroizing;

use crate::{Error, Result};

pub const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const ENVELOPE_V1_PREFIX: &str = "k1.";
const AAD_DOMAIN: &[u8] = b"keyless/k1/";
/// Plaintexts encrypted with padding are rounded up to a multiple of this many
/// bytes, so ciphertext sizes leak less about their contents.
const PAD_BLOCK: usize = 64;

/// Fills `buf` with bytes from the operating system CSPRNG.
pub fn random_bytes(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf).map_err(|_| Error::Rng)
}

/// Returns `N` random bytes that are wiped from memory when dropped.
pub fn random_array<const N: usize>() -> Result<Zeroizing<[u8; N]>> {
    let mut out = Zeroizing::new([0u8; N]);
    random_bytes(out.as_mut())?;
    Ok(out)
}

/// A 256-bit key for XChaCha20-Poly1305. Wiped from memory on drop and never
/// printed by `Debug`.
pub struct SymmetricKey(Zeroizing<[u8; KEY_LEN]>);

impl SymmetricKey {
    pub fn generate() -> Result<Self> {
        Ok(Self(random_array()?))
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let array: [u8; KEY_LEN] = bytes.try_into().map_err(|_| Error::InvalidKey)?;
        Ok(Self(Zeroizing::new(array)))
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// Duplicates the key. Kept explicit (no `Clone`) so copies of key material
    /// are always deliberate.
    pub fn duplicate(&self) -> Self {
        Self(Zeroizing::new(*self.0))
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new_from_slice(self.0.as_ref()).expect("key is always 32 bytes")
    }

    /// Encrypts `plaintext`, binding the result to `context`.
    pub fn seal(&self, plaintext: &[u8], context: &[u8]) -> Result<String> {
        let raw = self.seal_raw(plaintext, context)?;
        Ok(format!("{ENVELOPE_V1_PREFIX}{}", URL_SAFE_NO_PAD.encode(raw)))
    }

    /// Decrypts an envelope produced by [`SymmetricKey::seal`] with the same
    /// `context`. Fails if the key, the context or any byte is wrong.
    pub fn open(&self, envelope: &str, context: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let body = envelope
            .strip_prefix(ENVELOPE_V1_PREFIX)
            .ok_or(Error::InvalidEnvelope)?;
        let raw = URL_SAFE_NO_PAD
            .decode(body)
            .map_err(|_| Error::InvalidEnvelope)?;
        self.open_raw(&raw, context)
    }

    /// Like [`SymmetricKey::seal`], but returns raw bytes (nonce, ciphertext
    /// and tag) instead of an envelope string: for large binary data.
    pub fn seal_raw(&self, plaintext: &[u8], context: &[u8]) -> Result<Vec<u8>> {
        let mut nonce = [0u8; NONCE_LEN];
        random_bytes(&mut nonce)?;
        let aad = full_aad(context);
        let ciphertext = self
            .cipher()
            .encrypt(&XNonce::from(nonce), Payload { msg: plaintext, aad: &aad })
            .map_err(|_| Error::Encryption)?;
        let mut raw = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        raw.extend_from_slice(&nonce);
        raw.extend_from_slice(&ciphertext);
        Ok(raw)
    }

    /// Decrypts bytes produced by [`SymmetricKey::seal_raw`].
    pub fn open_raw(&self, raw: &[u8], context: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if raw.len() < NONCE_LEN + TAG_LEN {
            return Err(Error::InvalidEnvelope);
        }
        let (nonce, ciphertext) = raw.split_at(NONCE_LEN);
        let nonce = XNonce::try_from(nonce).map_err(|_| Error::InvalidEnvelope)?;
        let aad = full_aad(context);
        let plaintext = self
            .cipher()
            .decrypt(&nonce, Payload { msg: ciphertext, aad: &aad })
            .map_err(|_| Error::Decryption)?;
        Ok(Zeroizing::new(plaintext))
    }

    /// Like [`SymmetricKey::seal`], but pads the plaintext first to hide its
    /// exact length. Use for variable-length data such as item contents.
    pub fn seal_padded(&self, plaintext: &[u8], context: &[u8]) -> Result<String> {
        let padded = pad(plaintext);
        self.seal(&padded, context)
    }

    pub fn open_padded(&self, envelope: &str, context: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let padded = self.open(envelope, context)?;
        unpad(&padded)
    }
}

impl std::fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SymmetricKey(<redacted>)")
    }
}

/// Builds an AAD context string from a purpose and the ids it is bound to.
///
/// Parts are joined with a NUL byte, which cannot appear in ids, so distinct
/// part lists always produce distinct contexts.
pub fn context(purpose: &str, ids: &[&str]) -> Vec<u8> {
    let mut out = purpose.as_bytes().to_vec();
    for id in ids {
        out.push(0);
        out.extend_from_slice(id.as_bytes());
    }
    out
}

fn full_aad(context: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_DOMAIN.len() + context.len());
    aad.extend_from_slice(AAD_DOMAIN);
    aad.extend_from_slice(context);
    aad
}

/// ISO/IEC 7816-4 padding: append 0x80, then zeros up to a block boundary.
fn pad(data: &[u8]) -> Zeroizing<Vec<u8>> {
    let padded_len = (data.len() / PAD_BLOCK + 1) * PAD_BLOCK;
    let mut out = Zeroizing::new(Vec::with_capacity(padded_len));
    out.extend_from_slice(data);
    out.push(0x80);
    out.resize(padded_len, 0);
    out
}

fn unpad(data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let marker = data
        .iter()
        .rposition(|&b| b != 0)
        .ok_or(Error::InvalidEnvelope)?;
    if data[marker] != 0x80 {
        return Err(Error::InvalidEnvelope);
    }
    Ok(Zeroizing::new(data[..marker].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let key = SymmetricKey::generate().unwrap();
        let envelope = key.seal(b"hello", b"ctx").unwrap();
        assert!(envelope.starts_with("k1."));
        assert_eq!(key.open(&envelope, b"ctx").unwrap().as_slice(), b"hello");
    }

    #[test]
    fn nonces_are_unique() {
        let key = SymmetricKey::generate().unwrap();
        let a = key.seal(b"same", b"ctx").unwrap();
        let b = key.seal(b"same", b"ctx").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn wrong_context_fails() {
        let key = SymmetricKey::generate().unwrap();
        let envelope = key.seal(b"hello", b"item/1").unwrap();
        assert!(matches!(key.open(&envelope, b"item/2"), Err(Error::Decryption)));
    }

    #[test]
    fn wrong_key_fails() {
        let key = SymmetricKey::generate().unwrap();
        let other = SymmetricKey::generate().unwrap();
        let envelope = key.seal(b"hello", b"ctx").unwrap();
        assert!(matches!(other.open(&envelope, b"ctx"), Err(Error::Decryption)));
    }

    #[test]
    fn tampering_is_detected() {
        let key = SymmetricKey::generate().unwrap();
        let envelope = key.seal(b"hello world", b"ctx").unwrap();
        let mut raw = URL_SAFE_NO_PAD.decode(&envelope[3..]).unwrap();
        for i in 0..raw.len() {
            raw[i] ^= 1;
            let tampered = format!("k1.{}", URL_SAFE_NO_PAD.encode(&raw));
            assert!(key.open(&tampered, b"ctx").is_err(), "byte {i} flip not detected");
            raw[i] ^= 1;
        }
    }

    #[test]
    fn malformed_envelopes_are_rejected() {
        let key = SymmetricKey::generate().unwrap();
        for bad in ["", "k1.", "k2.AAAA", "k1.!!!", "k1.AAAA"] {
            assert!(key.open(bad, b"ctx").is_err(), "{bad:?} accepted");
        }
    }

    #[test]
    fn padding_hides_length_and_roundtrips() {
        let key = SymmetricKey::generate().unwrap();
        let short = key.seal_padded(b"a", b"ctx").unwrap();
        let longer = key.seal_padded(&[b'a'; 40], b"ctx").unwrap();
        assert_eq!(short.len(), longer.len());
        for len in [0usize, 1, 63, 64, 65, 200] {
            let data = vec![0u8; len];
            let envelope = key.seal_padded(&data, b"ctx").unwrap();
            assert_eq!(key.open_padded(&envelope, b"ctx").unwrap().as_slice(), &data[..]);
        }
    }

    #[test]
    fn context_parts_are_unambiguous() {
        assert_ne!(context("a", &["b", "c"]), context("a", &["bc"]));
        assert_ne!(context("a", &["b"]), context("a", &["b", ""]));
    }

    #[test]
    fn debug_does_not_leak() {
        let key = SymmetricKey::generate().unwrap();
        assert_eq!(format!("{key:?}"), "SymmetricKey(<redacted>)");
    }
}
