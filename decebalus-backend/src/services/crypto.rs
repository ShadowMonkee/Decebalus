//! Secrets-at-rest encryption for the credential store and loot files.
//!
//! A single master key — `DECEBALUS_MASTER_KEY` (hex-encoded, 32 bytes) if set,
//! otherwise an auto-generated `<data_dir>/master.key` (0600 perms) — is loaded
//! once at startup via [`init`]. Per-engagement keys are derived from it with
//! HKDF-SHA256 so a leaked derived key exposes only that engagement, not the
//! master key or other engagements. AES-256-GCM does the actual sealing; each
//! ciphertext is `nonce (12 bytes) || tag+ciphertext`.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use once_cell::sync::OnceCell;
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use std::path::Path;

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;

#[derive(Debug)]
pub struct CryptoError(String);

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "crypto error: {}", self.0)
    }
}
impl std::error::Error for CryptoError {}

impl From<std::io::Error> for CryptoError {
    fn from(e: std::io::Error) -> Self {
        CryptoError(e.to_string())
    }
}

struct MasterKey([u8; KEY_LEN]);

impl MasterKey {
    fn load_or_create(data_dir: &Path) -> Result<Self, CryptoError> {
        if let Ok(hex_key) = std::env::var("DECEBALUS_MASTER_KEY") {
            return Self::from_hex(hex_key.trim());
        }

        let key_path = data_dir.join("master.key");
        if key_path.exists() {
            let hex_key = std::fs::read_to_string(&key_path)?;
            return Self::from_hex(hex_key.trim());
        }

        let mut key = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut key);
        std::fs::create_dir_all(data_dir)?;
        std::fs::write(&key_path, hex::encode(key))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
        }
        tracing::info!("crypto: generated new master key at {}", key_path.display());
        Ok(Self(key))
    }

    fn from_hex(s: &str) -> Result<Self, CryptoError> {
        let bytes = hex::decode(s).map_err(|e| CryptoError(format!("master key must be hex: {}", e)))?;
        let arr: [u8; KEY_LEN] = bytes
            .try_into()
            .map_err(|_| CryptoError(format!("master key must decode to {} bytes", KEY_LEN)))?;
        Ok(Self(arr))
    }

    fn ephemeral() -> Self {
        let mut key = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut key);
        Self(key)
    }

    /// Derive a per-engagement key via HKDF-SHA256 ("" = the implicit global engagement).
    fn derive(&self, engagement_id: &str) -> [u8; KEY_LEN] {
        let hk = Hkdf::<Sha256>::new(None, &self.0);
        let mut okm = [0u8; KEY_LEN];
        hk.expand(engagement_id.as_bytes(), &mut okm)
            .expect("32 is a valid HKDF-SHA256 output length");
        okm
    }
}

static MASTER_KEY: OnceCell<MasterKey> = OnceCell::new();

/// Install the master key at startup, before any code touches the credential store
/// or loot. Safe to call once; a second call is a no-op.
pub fn init(data_dir: &Path) -> Result<(), CryptoError> {
    let key = MasterKey::load_or_create(data_dir)?;
    let _ = MASTER_KEY.set(key);
    Ok(())
}

/// The active master key. Falls back to a random in-process key if [`init`] was
/// never called (e.g. unit tests) — fine for round-tripping within one process,
/// but data sealed this way will not survive a restart, so real startup paths
/// must call [`init`] first.
fn current() -> &'static MasterKey {
    MASTER_KEY.get_or_init(MasterKey::ephemeral)
}

fn cipher_for(engagement_id: &str) -> Aes256Gcm {
    let key = current().derive(engagement_id);
    Aes256Gcm::new_from_slice(&key).expect("32-byte key is valid for AES-256-GCM")
}

/// Encrypt bytes for one engagement ("" = global). Output is `nonce || ciphertext`.
pub fn encrypt(engagement_id: &str, plaintext: &[u8]) -> Vec<u8> {
    let cipher = cipher_for(engagement_id);
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .expect("AES-256-GCM encryption does not fail for well-formed input");
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    out
}

/// Reverse of [`encrypt`]. Fails on the wrong engagement key or corrupted data.
pub fn decrypt(engagement_id: &str, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if data.len() < NONCE_LEN {
        return Err(CryptoError("ciphertext shorter than nonce".into()));
    }
    let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
    let cipher = cipher_for(engagement_id);
    cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
        .map_err(|_| CryptoError("decryption failed (wrong key or corrupted data)".into()))
}

/// Encrypt a UTF-8 string to a base64 blob, for storing in a SQLite TEXT column.
pub fn encrypt_str(engagement_id: &str, plaintext: &str) -> String {
    B64.encode(encrypt(engagement_id, plaintext.as_bytes()))
}

/// Reverse of [`encrypt_str`].
pub fn decrypt_str(engagement_id: &str, data: &str) -> Result<String, CryptoError> {
    let raw = B64.decode(data).map_err(|e| CryptoError(format!("invalid base64: {}", e)))?;
    let plain = decrypt(engagement_id, &raw)?;
    String::from_utf8(plain).map_err(|e| CryptoError(format!("decrypted data is not valid UTF-8: {}", e)))
}

/// Deterministic HMAC-SHA256 of a plaintext secret, keyed by the same per-engagement
/// key. Used as the credential-store dedup key since `encrypt_str`'s random nonce
/// makes the same secret encrypt differently every time.
pub fn secret_fingerprint(engagement_id: &str, plaintext: &str) -> String {
    let key = current().derive(engagement_id);
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key).expect("HMAC accepts any key length");
    mac.update(plaintext.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_a_string() {
        let enc = encrypt_str("eng-1", "hunter2");
        assert_ne!(enc, "hunter2");
        assert_eq!(decrypt_str("eng-1", &enc).unwrap(), "hunter2");
    }

    #[test]
    fn wrong_engagement_fails_to_decrypt() {
        let enc = encrypt_str("eng-1", "hunter2");
        assert!(decrypt_str("eng-2", &enc).is_err());
    }

    #[test]
    fn same_plaintext_encrypts_differently_each_time() {
        let a = encrypt_str("eng-1", "hunter2");
        let b = encrypt_str("eng-1", "hunter2");
        assert_ne!(a, b);
    }

    #[test]
    fn fingerprint_is_deterministic_and_engagement_scoped() {
        let a = secret_fingerprint("eng-1", "hunter2");
        let b = secret_fingerprint("eng-1", "hunter2");
        let c = secret_fingerprint("eng-2", "hunter2");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn round_trips_raw_bytes() {
        let enc = encrypt("global", b"\x00\x01binary loot");
        assert_eq!(decrypt("global", &enc).unwrap(), b"\x00\x01binary loot");
    }
}
