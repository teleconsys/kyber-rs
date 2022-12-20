/// Package ecies implements the Elliptic Curve Integrated Encryption Scheme (ECIES).
// package ecies
use crate::{
    dh::{AEAD, NONCE_SIZE},
    encoding::{BinaryMarshaler, BinaryUnmarshaler, Marshaling},
    util::random::Randstream,
    Group, Point, Scalar,
};
use anyhow::{bail, Result};

/// Encrypt first computes a shared DH key using the given public key, then
/// HKDF-derives a symmetric key (and nonce) from that, and finally uses these
/// values to encrypt the given message via AES-GCM. If the hash input parameter
/// is nil then SHA256 is used as a default. Encrypt returns a byte slice
/// containing the ephemeral elliptic curve point of the DH key exchange and the
/// ciphertext or an error.
pub fn encrypt<GROUP: Group>(
    group: GROUP,
    public: GROUP::POINT,
    message: &[u8],
) -> Result<Vec<u8>> {
    // Generate an ephemeral elliptic curve scalar and point
    let r = group.scalar().pick(&mut Randstream::default());
    let r_caps = group.point().mul(&r, None);

    // Compute shared DH key
    let dh = group.point().mul(&r, Some(&public));

    // Derive symmetric key and nonce via HKDF (NOTE: Since we use a new
    // ephemeral key for every ECIES encryption and thus have a fresh
    // HKDF-derived key for AES-GCM, the nonce for AES-GCM can be an arbitrary
    // (even static) value. We derive it here simply via HKDF as well.)
    let len = 32 + NONCE_SIZE;
    let buf = derive_key::<GROUP>(&dh, len)?;

    let mut nonce = [0u8; NONCE_SIZE];
    nonce.copy_from_slice(&buf.clone()[32..len]);

    let gcm = AEAD::<GROUP>::new(r_caps.clone(), &buf)?;

    // Encrypt message using AES-GCM
    let c = gcm.seal(None, &nonce, message, None)?;

    // Serialize ephemeral elliptic curve point and ciphertext
    let mut ctx = Vec::new();
    r_caps.marshal_to(&mut ctx)?;
    for v in c {
        ctx.push(v.clone());
    }
    Ok(ctx)
}

/// Decrypt first computes a shared DH key using the received ephemeral elliptic
/// curve point (stored in the first part of ctx), then HKDF-derives a symmetric
/// key (and nonce) from that, and finally uses these values to decrypt the
/// given ciphertext (stored in the second part of ctx) via AES-GCM. If the hash
/// input parameter is nil then SHA256 is used as a default. Decrypt returns the
/// plaintext message or an error.
pub fn decrypt<GROUP: Group>(
    group: GROUP,
    private: <GROUP::POINT as Point>::SCALAR,
    ctx: &[u8],
) -> Result<Vec<u8>> {
    // Reconstruct the ephemeral elliptic curve point
    let mut r_caps = group.point();
    let l = group.point_len();
    r_caps.unmarshal_binary(&ctx[..l])?;

    // Compute shared DH key and derive the symmetric key and nonce via HKDF
    let dh = group.point().mul(&private, Some(&r_caps));
    let len = 32 + NONCE_SIZE;
    let buf = derive_key::<GROUP>(&dh, len)?;

    let mut nonce = [0u8; NONCE_SIZE];
    nonce.copy_from_slice(&buf.clone()[32..len]);

    // Decrypt message using AES-GCM
    let gcm = AEAD::<GROUP>::new(r_caps.clone(), &buf)?;
    return gcm.open(None, &nonce, &ctx[l..], None);
}

fn derive_key<GROUP: Group>(dh: &GROUP::POINT, len: usize) -> Result<Vec<u8>> {
    let dhb = dh.marshal_binary()?;
    let key = GROUP::hkdf(&dhb, &Vec::new(), Some(len))?;

    if key.len() < len {
        bail!("ecies: hkdf-derived key too short")
    }
    Ok(key)
}
