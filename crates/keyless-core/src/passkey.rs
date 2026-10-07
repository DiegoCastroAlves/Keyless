//! Passkeys (WebAuthn credentials) kept in items. Keyless acts as the
//! authenticator: it creates an ES256 key pair for a site, answers with
//! "none" attestation and the backup flags of a synced passkey, and signs
//! the site's challenge when the user signs in.
//!
//! The browser extension builds nothing secret: the app checks the site's
//! origin against the relying party id, builds `clientDataJSON` itself from
//! the origin the browser reported, and signs here.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{Error, Result};

/// Identifies Keyless as the authenticator (a random, fixed UUID).
pub const AAGUID: [u8; 16] = [0x6b, 0x65, 0x79, 0x6c, 0x65, 0x73, 0x73, 0x2d, 0x9e, 0x51, 0x4c, 0x0f, 0xa3, 0x2b, 0x71, 0xd4];
/// COSE algorithm ES256 (ECDSA with P-256 and SHA-256), the only one.
pub const ES256: i64 = -7;

const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
/// Backup eligible and backed up: the passkey syncs with the vault.
const FLAG_BE: u8 = 0x08;
const FLAG_BS: u8 = 0x10;
const FLAG_AT: u8 = 0x40;

/// A passkey as stored in an item. Binary values are base64url.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct Passkey {
    pub credential_id: String,
    pub rp_id: String,
    #[serde(default)]
    pub rp_name: String,
    pub user_handle: String,
    #[serde(default)]
    pub user_name: String,
    #[serde(default)]
    pub user_display_name: String,
    /// The private key, PKCS#8 DER.
    pub key: String,
    /// Unix seconds.
    #[serde(default)]
    pub created_at: i64,
}

pub struct Created {
    pub passkey: Passkey,
    pub credential_id: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub attestation_object: Vec<u8>,
    /// SubjectPublicKeyInfo DER, for `getPublicKey()`.
    pub public_key: Vec<u8>,
}

pub struct Assertion {
    pub credential_id: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    /// DER-encoded ECDSA signature over authenticatorData || SHA-256(clientDataJSON).
    pub signature: Vec<u8>,
    pub user_handle: Vec<u8>,
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn unb64(text: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(text.trim_end_matches('=')).map_err(|_| Error::Serialization("bad base64url".into()))
}

/// `clientDataJSON` as browsers write it: these members, in this order.
pub fn client_data_json(kind: &str, challenge: &[u8], origin: &str, cross_origin: bool) -> String {
    let quote = |s: &str| serde_json::to_string(s).unwrap_or_else(|_| "\"\"".into());
    format!(
        "{{\"type\":{},\"challenge\":{},\"origin\":{},\"crossOrigin\":{}}}",
        quote(kind),
        quote(&b64(challenge)),
        quote(origin),
        cross_origin
    )
}

// ----- CBOR (only what WebAuthn needs, in canonical order) ---------------------

fn cbor_head(out: &mut Vec<u8>, major: u8, value: u64) {
    let major = major << 5;
    match value {
        0..=23 => out.push(major | value as u8),
        24..=0xff => out.extend_from_slice(&[major | 24, value as u8]),
        0x100..=0xffff => {
            out.push(major | 25);
            out.extend_from_slice(&(value as u16).to_be_bytes());
        }
        _ => {
            out.push(major | 26);
            out.extend_from_slice(&(value as u32).to_be_bytes());
        }
    }
}

fn cbor_int(out: &mut Vec<u8>, value: i64) {
    if value >= 0 {
        cbor_head(out, 0, value as u64);
    } else {
        cbor_head(out, 1, (-1 - value) as u64);
    }
}

fn cbor_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    cbor_head(out, 2, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

fn cbor_text(out: &mut Vec<u8>, text: &str) {
    cbor_head(out, 3, text.len() as u64);
    out.extend_from_slice(text.as_bytes());
}

/// The public key as a COSE_Key (EC2, P-256, ES256).
fn cose_key(key: &SigningKey) -> Vec<u8> {
    let point = key.verifying_key().to_encoded_point(false);
    let (x, y) = (point.x().map(|x| x.to_vec()).unwrap_or_default(), point.y().map(|y| y.to_vec()).unwrap_or_default());
    let mut out = Vec::new();
    cbor_head(&mut out, 5, 5);
    cbor_int(&mut out, 1);
    cbor_int(&mut out, 2); // kty: EC2
    cbor_int(&mut out, 3);
    cbor_int(&mut out, ES256); // alg
    cbor_int(&mut out, -1);
    cbor_int(&mut out, 1); // crv: P-256
    cbor_int(&mut out, -2);
    cbor_bytes(&mut out, &x);
    cbor_int(&mut out, -3);
    cbor_bytes(&mut out, &y);
    out
}

fn authenticator_data(rp_id: &str, user_verified: bool, attested: Option<(&[u8], &SigningKey)>) -> Vec<u8> {
    let mut data = Sha256::digest(rp_id.as_bytes()).to_vec();
    let mut flags = FLAG_UP | FLAG_BE | FLAG_BS;
    if user_verified {
        flags |= FLAG_UV;
    }
    if attested.is_some() {
        flags |= FLAG_AT;
    }
    data.push(flags);
    // The signature counter stays 0: a synced passkey cannot keep one.
    data.extend_from_slice(&0u32.to_be_bytes());
    if let Some((credential_id, key)) = attested {
        data.extend_from_slice(&AAGUID);
        data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
        data.extend_from_slice(credential_id);
        data.extend_from_slice(&cose_key(key));
    }
    data
}

fn random_key() -> Result<SigningKey> {
    loop {
        let mut bytes = Zeroizing::new([0u8; 32]);
        getrandom::fill(bytes.as_mut()).map_err(|_| Error::Rng)?;
        // Practically always a valid scalar; a value out of range is retried.
        if let Ok(key) = SigningKey::from_slice(bytes.as_ref()) {
            return Ok(key);
        }
    }
}

/// A new passkey for `rp_id` (already checked against the site's origin).
pub fn create(rp_id: &str, rp_name: &str, user_handle: &[u8], user_name: &str, user_display_name: &str, user_verified: bool, now: i64) -> Result<Created> {
    let key = random_key()?;
    let mut credential_id = vec![0u8; 16];
    getrandom::fill(&mut credential_id).map_err(|_| Error::Rng)?;
    let authenticator_data = authenticator_data(rp_id, user_verified, Some((&credential_id, &key)));

    let mut attestation_object = Vec::new();
    cbor_head(&mut attestation_object, 5, 3);
    cbor_text(&mut attestation_object, "fmt");
    cbor_text(&mut attestation_object, "none");
    cbor_text(&mut attestation_object, "attStmt");
    cbor_head(&mut attestation_object, 5, 0);
    cbor_text(&mut attestation_object, "authData");
    cbor_bytes(&mut attestation_object, &authenticator_data);

    let pkcs8 = key.to_pkcs8_der().map_err(|_| Error::InvalidKey)?;
    let public_key = key.verifying_key().to_public_key_der().map_err(|_| Error::InvalidKey)?.into_vec();
    Ok(Created {
        passkey: Passkey {
            credential_id: b64(&credential_id),
            rp_id: rp_id.to_string(),
            rp_name: rp_name.to_string(),
            user_handle: b64(user_handle),
            user_name: user_name.to_string(),
            user_display_name: user_display_name.to_string(),
            key: b64(pkcs8.as_bytes()),
            created_at: now,
        },
        credential_id,
        authenticator_data,
        attestation_object,
        public_key,
    })
}

/// Signs in with `passkey`: signs the site's challenge (through the hash of
/// `clientDataJSON`).
pub fn assert(passkey: &Passkey, client_data_json: &str, user_verified: bool) -> Result<Assertion> {
    let der = Zeroizing::new(unb64(&passkey.key)?);
    let key = SigningKey::from_pkcs8_der(&der).map_err(|_| Error::InvalidKey)?;
    let authenticator_data = authenticator_data(&passkey.rp_id, user_verified, None);
    let mut signed = authenticator_data.clone();
    signed.extend_from_slice(&Sha256::digest(client_data_json.as_bytes()));
    let signature: Signature = key.sign(&signed);
    Ok(Assertion {
        credential_id: unb64(&passkey.credential_id)?,
        authenticator_data,
        signature: signature.to_der().as_bytes().to_vec(),
        user_handle: unb64(&passkey.user_handle)?,
    })
}

#[cfg(test)]
mod tests {
    use p256::{
        ecdsa::{VerifyingKey, signature::Verifier},
        pkcs8::DecodePublicKey,
    };

    use super::*;

    #[test]
    fn create_and_sign_in() {
        let created = create("example.com", "Example", b"user-1", "ana@example.com", "Ana", true, 1).unwrap();
        let data = &created.authenticator_data;
        assert_eq!(&data[..32], Sha256::digest(b"example.com").as_slice());
        assert_eq!(data[32], FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS | FLAG_AT);
        assert_eq!(&data[33..37], &[0, 0, 0, 0]);
        assert_eq!(&data[37..53], &AAGUID);
        assert_eq!(&data[53..55], &16u16.to_be_bytes());
        assert_eq!(&data[55..71], created.credential_id.as_slice());
        // COSE_Key: a 5-entry map starting with kty = EC2 and alg = ES256.
        assert_eq!(&data[71..76], &[0xa5, 0x01, 0x02, 0x03, 0x26]);
        // attestationObject: {"fmt": "none", "attStmt": {}, "authData": ...}.
        assert_eq!(&created.attestation_object[..18], b"\xa3cfmtdnonegattStmt");

        let client_data = client_data_json("webauthn.get", b"challenge", "https://example.com", false);
        assert_eq!(client_data, r#"{"type":"webauthn.get","challenge":"Y2hhbGxlbmdl","origin":"https://example.com","crossOrigin":false}"#);
        let assertion = assert(&created.passkey, &client_data, false).unwrap();
        assert_eq!(assertion.authenticator_data.len(), 37);
        assert_eq!(assertion.authenticator_data[32], FLAG_UP | FLAG_BE | FLAG_BS);
        assert_eq!(assertion.user_handle, b"user-1");

        let verifying = VerifyingKey::from_public_key_der(&created.public_key).unwrap();
        let mut signed = assertion.authenticator_data.clone();
        signed.extend_from_slice(&Sha256::digest(client_data.as_bytes()));
        let signature = Signature::from_der(&assertion.signature).unwrap();
        assert!(verifying.verify(&signed, &signature).is_ok());

        // Stored and read back.
        let json = serde_json::to_string(&created.passkey).unwrap();
        let back: Passkey = serde_json::from_str(&json).unwrap();
        assert_eq!(back, created.passkey);
    }

    #[test]
    fn cbor_lengths() {
        let mut out = Vec::new();
        cbor_bytes(&mut out, &[0u8; 300]);
        assert_eq!(&out[..3], &[0x59, 0x01, 0x2c]);
        let mut out = Vec::new();
        cbor_int(&mut out, -7);
        assert_eq!(out, [0x26]);
    }
}
