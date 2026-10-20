//! The RustCrypto calls the operation bridge, the `bridge` binary at
//! `rust/rustcrypto/v1/bridge/main.rs`, makes: the strict base64url field
//! reader, one HKDF-SHA-256 expansion, the AES-GCM carrier, P-256 key import,
//! agreement and point encoding, and RSA private-key import with one OAEP
//! decryption. One implementation, so a mistake cannot hide in a second copy.
//!
//! Nothing here reads a wire protocol, a request, a batch or a refusal code.
//! This file imports keys and calls primitives; `bridge/main.rs` decides what a
//! failure means for its own answer. Every crate below is pinned by
//! `v1/Cargo.lock`, and none of them is OpenSSL, `ring` or `aws-lc-rs`.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hkdf::Hkdf;
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::{FieldBytes, PublicKey, SecretKey};
use rsa::{BigUint, Oaep, RsaPrivateKey};
use sha2::Sha256;

/// The octets a P-256 scalar or coordinate carries.
pub const P256_FIELD_OCTETS: usize = 32;

// ---- base64url, unpadded -----------------------------------------------------

/// Canonical unpadded base64url to octets, or the reason it is not canonical.
///
/// The four rules of the contract's strict field are checked here rather than
/// left to the `base64` crate. Its `URL_SAFE_NO_PAD` engine already refuses
/// padding and non-zero trailing bits, and the alphabet, length and re-encode
/// checks below still run, so the answer stays the same if a later release of
/// the crate relaxes either default.
pub fn decode_strict_base64url(value: &str) -> Result<Vec<u8>, String> {
    for (position, character) in value.bytes().enumerate() {
        let in_alphabet = character.is_ascii_alphanumeric() || character == b'-' || character == b'_';
        if !in_alphabet {
            return Err(format!(
                "octet {position} is {:?}, outside the base64url alphabet, which is where padding is refused",
                char::from(character)
            ));
        }
    }
    if value.len() % 4 == 1 {
        return Err(format!("a length of {} encodes no whole octet count", value.len()));
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|error| format!("octets the base64url decoder would not read: {error}"))?;
    let spelling = URL_SAFE_NO_PAD.encode(&decoded);
    if spelling != value {
        return Err(format!("unused trailing bits: those octets are spelled {spelling:?}"));
    }
    Ok(decoded)
}

/// Octets to canonical unpadded base64url.
pub fn encode_base64url(octets: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(octets)
}

/// Left-pads a big-endian scalar or coordinate to the 32 octets P-256 carries.
///
/// It widens and never narrows: 33 octets is not a P-256 value with a leading
/// octet to drop, it is a different number, so an over-wide input answers
/// `None` and the caller refuses the key.
pub fn pad_p256_field(octets: &[u8]) -> Option<[u8; P256_FIELD_OCTETS]> {
    if octets.len() > P256_FIELD_OCTETS {
        return None;
    }
    let mut out = [0u8; P256_FIELD_OCTETS];
    out[P256_FIELD_OCTETS - octets.len()..].copy_from_slice(octets);
    Some(out)
}

// ---- HKDF --------------------------------------------------------------------

/// One HKDF-SHA-256 invocation (RFC 5869) with an empty salt, answering
/// `width` octets.
///
/// `Hkdf::new(None, ..)` extracts under a salt of one hash length of zero
/// octets, which RFC 5869 section 2.2 makes identical to an empty salt. `info`
/// is a byte slice all the way to the HMAC, so 0x00 and octets above 0x7f
/// reach the derivation unchanged.
pub fn hkdf_sha256(ikm: &[u8], info: &[u8], width: usize) -> Result<Vec<u8>, String> {
    let mut okm = vec![0u8; width];
    Hkdf::<Sha256>::new(None, ikm)
        .expand(info, &mut okm)
        .map_err(|error| format!("{error}"))?;
    Ok(okm)
}

// ---- AES-GCM -----------------------------------------------------------------

/// The ciphertext with the 16-octet tag appended. A 16-octet key selects
/// AES-128-GCM and a 32-octet key AES-256-GCM; any other width, or a nonce
/// that is not 12 octets, is an error.
pub fn gcm_seal(key: &[u8], nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    let nonce = gcm_nonce(nonce)?;
    let payload = Payload { msg: plaintext, aad };
    let sealed = match key.len() {
        16 => Aes128Gcm::new_from_slice(key).map_err(|e| format!("{e}"))?.encrypt(&nonce, payload),
        32 => Aes256Gcm::new_from_slice(key).map_err(|e| format!("{e}"))?.encrypt(&nonce, payload),
        other => return Err(format!("a {other}-octet key, and AES-GCM here takes 16 or 32")),
    };
    sealed.map_err(|error| format!("{error}"))
}

/// Opens one `ciphertext || tag` carrier. `Ok(None)` is a tag that does not
/// verify, and the crate's `decrypt` reports a carrier shorter than the tag
/// the same way. `Err` is a key or nonce width the cipher does not take.
pub fn gcm_open(key: &[u8], nonce: &[u8], carrier: &[u8], aad: &[u8]) -> Result<Option<Vec<u8>>, String> {
    let nonce = gcm_nonce(nonce)?;
    let payload = Payload { msg: carrier, aad };
    let opened = match key.len() {
        16 => Aes128Gcm::new_from_slice(key).map_err(|e| format!("{e}"))?.decrypt(&nonce, payload),
        32 => Aes256Gcm::new_from_slice(key).map_err(|e| format!("{e}"))?.decrypt(&nonce, payload),
        other => return Err(format!("a {other}-octet key, and AES-GCM here takes 16 or 32")),
    };
    Ok(opened.ok())
}

fn gcm_nonce(nonce: &[u8]) -> Result<Nonce<aes_gcm::aead::consts::U12>, String> {
    Nonce::try_from(nonce).map_err(|_| format!("a {}-octet nonce, and AES-GCM here takes 12", nonce.len()))
}

// ---- P-256 -------------------------------------------------------------------

/// The P-256 secret scalar `d`, left-padded to 32 octets and imported with
/// `SecretKey::from_bytes`, which refuses zero and a value at or above the
/// group order.
pub fn p256_secret_key(d: &[u8]) -> Result<SecretKey, String> {
    let padded = pad_p256_field(d).ok_or("d is wider than the 32 octets a P-256 scalar carries")?;
    SecretKey::from_bytes(&FieldBytes::from(padded)).map_err(|_| "d is not a P-256 scalar".to_string())
}

/// One SEC 1 encoded point imported with `PublicKey::from_sec1_bytes`, which
/// refuses a point off the curve and the identity.
pub fn p256_public_key(point: &[u8]) -> Result<PublicKey, String> {
    PublicKey::from_sec1_bytes(point).map_err(|_| "not a SEC 1 encoded P-256 point".to_string())
}

/// The 65-octet uncompressed SEC 1 point `0x04 || x || y` built from two JWK
/// coordinates, each left-padded to 32 octets, or `None` for a coordinate wider
/// than that.
pub fn p256_point_from_coordinates(x: &[u8], y: &[u8]) -> Option<Vec<u8>> {
    let x = pad_p256_field(x)?;
    let y = pad_p256_field(y)?;
    let mut out = Vec::with_capacity(1 + 2 * P256_FIELD_OCTETS);
    out.push(0x04);
    out.extend_from_slice(&x);
    out.extend_from_slice(&y);
    Some(out)
}

/// The key written back by the crate as an uncompressed SEC 1 point, each
/// coordinate at full width.
pub fn p256_uncompressed_point(key: &PublicKey) -> Vec<u8> {
    key.as_affine().to_sec1_point(false).as_bytes().to_vec()
}

/// One ECDH agreement: the agreed x-coordinate at the P-256 field width, 32
/// octets, with no KDF applied. `raw_secret_bytes` is a fixed-width field
/// element, so a leading zero octet stays.
pub fn p256_ecdh(secret: &SecretKey, peer: &PublicKey) -> Vec<u8> {
    let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
    shared.raw_secret_bytes().to_vec()
}

// ---- RSA ---------------------------------------------------------------------

/// An RSA private key from its big-endian `n`, `e`, `d`, `p` and `q`.
/// `from_components` validates the key and recomputes the CRT values, so the
/// JWK's `dp`, `dq` and `qi` are never read.
pub fn rsa_private_key(n: &[u8], e: &[u8], d: &[u8], p: &[u8], q: &[u8]) -> Result<RsaPrivateKey, String> {
    RsaPrivateKey::from_components(
        BigUint::from_bytes_be(n),
        BigUint::from_bytes_be(e),
        BigUint::from_bytes_be(d),
        vec![BigUint::from_bytes_be(p), BigUint::from_bytes_be(q)],
    )
    .map_err(|error| format!("{error}"))
}

/// One RSA-OAEP decryption with SHA-256 for the digest and for MGF1, and no
/// label. `Oaep::new` names one hash type for both. The error is returned as
/// text for stderr only; the caller reads every error as the one refusal OAEP
/// reports.
///
/// rsa 0.9 is built on the digest 0.10 traits, so the SHA-256 type it takes is
/// the sha2 0.10 one; both sha2 releases are pinned in Cargo.lock.
pub fn rsa_oaep_sha256_open(key: &RsaPrivateKey, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    key.decrypt(Oaep::new::<sha2_010::Sha256>(), ciphertext)
        .map_err(|error| format!("{error}"))
}
