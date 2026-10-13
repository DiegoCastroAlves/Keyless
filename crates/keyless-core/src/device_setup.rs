//! Signing in on a new device with the help of one already signed in, like
//! 1Password's "Sign in with another device".
//!
//! The new device asks the server to pass a request on to the account's
//! signed-in devices. One of them approves it once the user types there the
//! code the new device shows, and sends back the account's email and Secret
//! Key, encrypted so only the new device can read them. The master password
//! is still typed on the new device: approving never signs it in alone.
//!
//! The server relays every message, so it must not be able to read the
//! Secret Key or put its own key in the middle. The code is a short
//! authentication string over the whole exchange, with the new device's
//! nonce committed before the other device answers (as in Bluetooth's
//! numeric comparison):
//!
//! ```text
//! new device                                  signed-in device
//!   a, A = X25519;  Na = 16 random bytes
//!   C = SHA-256("…commitment" | A | Na)
//!                   --- A, C --->
//!                                             b, B = X25519;  Nb = 16 random bytes
//!                   <--- B, Nb ---
//!                   --- Na --->               checks C
//!   code = SHA-256("…code" | A | B | Na | Nb), 6 digits, shown on the new device
//!                                             and typed on the signed-in one
//!   key = HKDF(X25519(a, B), salt = "keyless/v1/device-setup", info = A | B | Na | Nb)
//!                   <--- seal(key, {email, Secret Key}, "device-setup" | request id) ---
//! ```
//!
//! A relay that swaps the keys must choose what it hands the new device
//! (B', Nb') before it learns Na, so the two codes match by chance only: one
//! in a million per attempt. Requests expire after 10 minutes and the server
//! accepts only a few per account.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::{
    Error, Result,
    crypto::{SymmetricKey, context, random_array},
};

const NONCE_LEN: usize = 16;
/// Digits in the code the user types.
pub const CODE_DIGITS: usize = 6;

/// What the signed-in device sends: enough to sign in, except the master
/// password.
#[derive(Clone, Serialize, Deserialize)]
pub struct SetupPayload {
    pub email: String,
    pub secret_key: Zeroizing<String>,
}

impl std::fmt::Debug for SetupPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SetupPayload").field("email", &self.email).finish_non_exhaustive()
    }
}

fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn decode<const N: usize>(text: &str) -> Result<[u8; N]> {
    URL_SAFE_NO_PAD
        .decode(text.trim())
        .ok()
        .and_then(|bytes| <[u8; N]>::try_from(bytes.as_slice()).ok())
        .ok_or(Error::InvalidKey)
}

fn commitment(public: &[u8; 32], nonce: &[u8; NONCE_LEN]) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"keyless/v1/device-setup commitment")
        .chain_update(public)
        .chain_update(nonce)
        .finalize()
        .into()
}

/// Everything both sides bind the code and the key to.
struct Transcript<'a> {
    requester: &'a [u8; 32],
    approver: &'a [u8; 32],
    requester_nonce: &'a [u8; NONCE_LEN],
    approver_nonce: &'a [u8; NONCE_LEN],
}

impl Transcript<'_> {
    fn bytes(&self) -> Vec<u8> {
        [self.requester.as_slice(), self.approver, self.requester_nonce, self.approver_nonce].concat()
    }

    fn code(&self) -> String {
        let digest = Sha256::new()
            .chain_update(b"keyless/v1/device-setup code")
            .chain_update(self.bytes())
            .finalize();
        let value = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) % 10u32.pow(CODE_DIGITS as u32);
        format!("{value:0width$}", width = CODE_DIGITS)
    }

    fn key(&self, secret: &StaticSecret, peer: &[u8; 32]) -> Result<SymmetricKey> {
        let shared = secret.diffie_hellman(&PublicKey::from(*peer));
        // A low-order public key would make the shared secret predictable.
        if !shared.was_contributory() {
            return Err(Error::InvalidKey);
        }
        let mut key = Zeroizing::new([0u8; 32]);
        Hkdf::<Sha256>::new(Some(b"keyless/v1/device-setup"), shared.as_bytes())
            .expand(&self.bytes(), key.as_mut())
            .map_err(|_| Error::Kdf)?;
        SymmetricKey::from_slice(key.as_ref())
    }
}

fn payload_context(request_id: &str) -> Vec<u8> {
    context("device-setup", &[request_id])
}

/// The new device's side.
pub struct SetupRequest {
    secret: StaticSecret,
    public: [u8; 32],
    nonce: Zeroizing<[u8; NONCE_LEN]>,
}

impl SetupRequest {
    pub fn new() -> Result<Self> {
        let secret = StaticSecret::from(*random_array::<32>()?);
        let public = PublicKey::from(&secret).to_bytes();
        Ok(Self { secret, public, nonce: random_array()? })
    }

    /// Sent with the request (base64url).
    pub fn public_key(&self) -> String {
        encode(&self.public)
    }

    /// Sent with the request (base64url): binds the nonce revealed later.
    pub fn commitment(&self) -> String {
        encode(&commitment(&self.public, &self.nonce))
    }

    /// Revealed once the other device has answered (base64url).
    pub fn nonce(&self) -> String {
        encode(self.nonce.as_ref())
    }

    /// The code to show, once the other device has answered with its public
    /// key and nonce.
    pub fn code(&self, approver_key: &str, approver_nonce: &str) -> Result<String> {
        let (approver, approver_nonce) = (decode::<32>(approver_key)?, decode::<NONCE_LEN>(approver_nonce)?);
        Ok(self.transcript(&approver, &approver_nonce).code())
    }

    fn transcript<'a>(&'a self, approver: &'a [u8; 32], approver_nonce: &'a [u8; NONCE_LEN]) -> Transcript<'a> {
        Transcript { requester: &self.public, approver, requester_nonce: &self.nonce, approver_nonce }
    }

    /// Opens what the other device sent once the user approved.
    pub fn open(&self, request_id: &str, approver_key: &str, approver_nonce: &str, envelope: &str) -> Result<SetupPayload> {
        let (approver, approver_nonce) = (decode::<32>(approver_key)?, decode::<NONCE_LEN>(approver_nonce)?);
        let key = self.transcript(&approver, &approver_nonce).key(&self.secret, &approver)?;
        let bytes = key.open(envelope, &payload_context(request_id))?;
        serde_json::from_slice(&bytes).map_err(Error::from)
    }
}

/// The signed-in device's side, kept from its answer until the user approves.
pub struct SetupApproval {
    secret: StaticSecret,
    public: [u8; 32],
    nonce: Zeroizing<[u8; NONCE_LEN]>,
    requester: [u8; 32],
    requester_commitment: [u8; 32],
}

impl SetupApproval {
    /// Answers a request made with `requester_key` and `requester_commitment`.
    pub fn new(requester_key: &str, requester_commitment: &str) -> Result<Self> {
        let secret = StaticSecret::from(*random_array::<32>()?);
        let public = PublicKey::from(&secret).to_bytes();
        Ok(Self {
            secret,
            public,
            nonce: random_array()?,
            requester: decode(requester_key)?,
            requester_commitment: decode(requester_commitment)?,
        })
    }

    /// Sent with the answer (base64url).
    pub fn public_key(&self) -> String {
        encode(&self.public)
    }

    /// Sent with the answer (base64url).
    pub fn nonce(&self) -> String {
        encode(self.nonce.as_ref())
    }

    /// Checks the nonce the new device revealed against its commitment.
    fn revealed(&self, requester_nonce: &str) -> Result<[u8; NONCE_LEN]> {
        let nonce = decode::<NONCE_LEN>(requester_nonce)?;
        let expected = commitment(&self.requester, &nonce);
        if expected.ct_eq(&self.requester_commitment).into() { Ok(nonce) } else { Err(Error::InvalidKey) }
    }

    fn transcript<'a>(&'a self, requester_nonce: &'a [u8; NONCE_LEN]) -> Transcript<'a> {
        Transcript { requester: &self.requester, approver: &self.public, requester_nonce, approver_nonce: &self.nonce }
    }

    /// The code the new device shows, once it revealed its nonce.
    pub fn code(&self, requester_nonce: &str) -> Result<String> {
        let nonce = self.revealed(requester_nonce)?;
        Ok(self.transcript(&nonce).code())
    }

    /// Whether `typed` (spaces allowed) is the code the new device shows.
    pub fn code_matches(&self, requester_nonce: &str, typed: &str) -> Result<bool> {
        let code = self.code(requester_nonce)?;
        let typed: String = typed.chars().filter(|c| !c.is_whitespace() && *c != '-').collect();
        Ok(typed.len() == code.len() && bool::from(typed.as_bytes().ct_eq(code.as_bytes())))
    }

    /// Encrypts `payload` for the new device.
    pub fn seal(&self, request_id: &str, requester_nonce: &str, payload: &SetupPayload) -> Result<String> {
        let nonce = self.revealed(requester_nonce)?;
        let key = self.transcript(&nonce).key(&self.secret, &self.requester)?;
        let json = Zeroizing::new(serde_json::to_vec(payload)?);
        key.seal(&json, &payload_context(request_id))
    }
}

/// Formats a code for display: `123 456`.
pub fn display_code(code: &str) -> String {
    let (head, tail) = code.split_at(code.len() / 2);
    format!("{head} {tail}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload() -> SetupPayload {
        SetupPayload { email: "me@example.com".into(), secret_key: Zeroizing::new("K1-AAAAAA-BBBBBB-CCCCC-DDDDD-EEEEE".into()) }
    }

    #[test]
    fn both_sides_agree() {
        let request = SetupRequest::new().unwrap();
        let approval = SetupApproval::new(&request.public_key(), &request.commitment()).unwrap();
        let code = request.code(&approval.public_key(), &approval.nonce()).unwrap();
        assert_eq!(code.len(), CODE_DIGITS);
        assert_eq!(approval.code(&request.nonce()).unwrap(), code);
        assert!(approval.code_matches(&request.nonce(), &display_code(&code)).unwrap());
        assert!(!approval.code_matches(&request.nonce(), "000000x").unwrap());

        let envelope = approval.seal("req-1", &request.nonce(), &payload()).unwrap();
        let opened = request.open("req-1", &approval.public_key(), &approval.nonce(), &envelope).unwrap();
        assert_eq!(opened.email, "me@example.com");
        assert_eq!(opened.secret_key.as_str(), payload().secret_key.as_str());
        // Bound to the request.
        assert!(request.open("req-2", &approval.public_key(), &approval.nonce(), &envelope).is_err());
    }

    #[test]
    fn a_wrong_nonce_is_refused() {
        let request = SetupRequest::new().unwrap();
        let approval = SetupApproval::new(&request.public_key(), &request.commitment()).unwrap();
        let other = SetupRequest::new().unwrap();
        assert!(approval.code(&other.nonce()).is_err());
        assert!(approval.seal("r", &other.nonce(), &payload()).is_err());
    }

    #[test]
    fn a_relay_in_the_middle_cannot_read_or_match() {
        // The relay answers the new device with its own key and forwards the
        // request with its own key and commitment to the signed-in device.
        let request = SetupRequest::new().unwrap();
        let relay_as_requester = SetupRequest::new().unwrap();
        let approval = SetupApproval::new(&relay_as_requester.public_key(), &relay_as_requester.commitment()).unwrap();
        let relay_as_approver = SetupApproval::new(&request.public_key(), &request.commitment()).unwrap();

        let shown = request.code(&relay_as_approver.public_key(), &relay_as_approver.nonce()).unwrap();
        let expected = approval.code(&relay_as_requester.nonce()).unwrap();
        // (They match by chance once in a million runs.)
        assert_ne!(shown, expected);
        // What the signed-in device seals is for the relay's key, not the new device's.
        let envelope = approval.seal("r", &relay_as_requester.nonce(), &payload()).unwrap();
        assert!(request.open("r", &approval.public_key(), &approval.nonce(), &envelope).is_err());
    }

    #[test]
    fn low_order_keys_are_refused() {
        let zero = [0u8; 32];
        let nonce = [0u8; NONCE_LEN];
        let approval = SetupApproval::new(&encode(&zero), &encode(&commitment(&zero, &nonce))).unwrap();
        assert!(approval.code(&encode(&nonce)).is_ok());
        assert!(matches!(approval.seal("r", &encode(&nonce), &payload()), Err(Error::InvalidKey)));
        let request = SetupRequest::new().unwrap();
        assert!(matches!(request.open("r", &encode(&zero), &encode(&nonce), "k1.x"), Err(Error::InvalidKey)));
    }
}
