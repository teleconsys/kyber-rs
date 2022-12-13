use aes_gcm::{Aes256Gcm, aead::{Payload, Aead}, KeyInit};
use digest::{OutputSizeUser, generic_array::GenericArray};
use hkdf::{HmacImpl, Hkdf, hmac::Hmac};
use anyhow::{Result, Error};
use sha2::Sha256;

use crate::{Suite, Point, encoding::Marshaling};

/// dhExchange computes the shared key from a private key and a public key
pub fn dh_exchange<SUITE: Suite>(
    suite: SUITE,
    own_private: <SUITE::POINT as Point>::SCALAR,
    remote_public: SUITE::POINT,
) -> SUITE::POINT {
    let sk = suite.point();
    sk.mul(&own_private, Some(&remote_public))
}

/// context returns the context slice to be used when encrypting a share
pub fn context<SUITE: Suite>(
    suite: &SUITE,
    dealer: &SUITE::POINT,
    verifiers: &[SUITE::POINT],
) -> Vec<u8> {
    let mut h = suite.hash();
    h.write("vss-dealer".as_bytes()).unwrap();
    dealer.marshal_to(&mut h).unwrap();
    h.write("vss-verifiers".as_bytes()).unwrap();
    for v in verifiers {
        v.marshal_to(&mut h).unwrap();
    }
    h.finalize().to_vec()
}

pub fn hkdf<H, I>(buff: &[u8], info: &[u8]) -> Result<[u8; 32]>
where
    H: OutputSizeUser,
    I: HmacImpl<H>,
{
    let h = Hkdf::<H, I>::new(None, buff);
    let mut out = [0u8; 32];
    h.expand(info, &mut out)
        .map_err(|_| Error::msg("unexpected error in hkdf_sha256"))?;

    Ok(out)
}

pub const AES_NONCE_LENGTH: usize = 12;

pub fn aes_encrypt(
    key: &[u8; 32],
    nonce: &[u8; AES_NONCE_LENGTH],
    data: &[u8],
    additional_data: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let key = GenericArray::from_slice(key);
    let aead = Aes256Gcm::new(key);
    let nonce = GenericArray::from_slice(nonce);

    let payload: Payload = match additional_data {
        None => data.into(),
        Some(add_data) => Payload {
            aad: add_data,
            msg: data,
        },
    };

    let ciphertext = aead
        .encrypt(nonce, payload)
        .map_err(|_| Error::msg("aes encryption failed"))?;

    Ok(ciphertext)
}

pub fn aes_decrypt(
    key: &[u8; 32],
    nonce: &[u8; AES_NONCE_LENGTH],
    ciphertext: &[u8],
    additional_data: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let key = GenericArray::from_slice(key);
    let aead = Aes256Gcm::new(key);
    let nonce = GenericArray::from_slice(nonce);

    let payload: Payload = match additional_data {
        None => ciphertext.into(),
        Some(add_data) => Payload {
            aad: add_data,
            msg: ciphertext,
        },
    };

    let decrypted = aead
        .decrypt(nonce, payload)
        .map_err(|e| Error::msg(format!("aes decryption failed: {:#?}", e)))?;

    Ok(decrypted)
}

pub fn aead_encrypt<POINT: Point>(
    pre_key: &POINT,
    info: &[u8],
    nonce: &[u8; AES_NONCE_LENGTH],
    data: &[u8],
) -> Result<Vec<u8>> {
    let pre_buff = pre_key.marshal_binary()?;
    let key = hkdf::<Sha256, Hmac<Sha256>>(&pre_buff, info)?;
    let encrypted = aes_encrypt(&key, nonce, data, Some(info))?;

    Ok(encrypted)
}

pub fn aead_decrypt<POINT: Point>(
    pre_key: &POINT,
    info: &[u8],
    nonce: &[u8; AES_NONCE_LENGTH],
    cipher: &[u8],
) -> Result<Vec<u8>> {
    let pre_buff = pre_key.marshal_binary()?;
    let key = hkdf::<Sha256, Hmac<Sha256>>(&pre_buff, info)?;
    let decrypted = aes_decrypt(&key, nonce, cipher, Some(info))?;

    Ok(decrypted)
}

pub struct AEAD {
    key: [u8; 32],
}

impl AEAD {
    pub fn new<POINT: Point>(pre: POINT, hkfd_context: &Vec<u8>) -> Result<Self> {
        let pre_buff = pre.marshal_binary()?;
        let key = hkdf::<Sha256, Hmac<Sha256>>(&pre_buff, &hkfd_context)?;
        Ok(AEAD { key })
    }

    /// Seal encrypts and authenticates plaintext, authenticates the
    /// additional data and appends the result to dst, returning the updated
    /// slice. The nonce must be NonceSize() bytes long and unique for all
    /// time, for a given key.
    ///
    /// To reuse plaintext's storage for the encrypted output, use plaintext[:0]
    /// as dst. Otherwise, the remaining capacity of dst must not overlap plaintext.
    pub fn seal(
        &self,
        dst: Option<&mut [u8]>,
        nonce: &[u8; AES_NONCE_LENGTH],
        plaintext: &[u8],
        additional_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let encrypted = aes_encrypt(&self.key, nonce, plaintext, additional_data)?;
        Ok(encrypted)
    }

    /// Open decrypts and authenticates ciphertext, authenticates the
    /// additional data and, if successful, appends the resulting plaintext
    /// to dst, returning the updated slice. The nonce must be NonceSize()
    /// bytes long and both it and the additional data must match the
    /// value passed to Seal.
    ///
    /// To reuse ciphertext's storage for the decrypted output, use ciphertext[:0]
    /// as dst. Otherwise, the remaining capacity of dst must not overlap plaintext.
    ///
    /// Even if the function fails, the contents of dst, up to its capacity,
    /// may be overwritten.
    pub fn open(
        &self,
        dst: Option<&[u8]>,
        nonce: &[u8; AES_NONCE_LENGTH],
        ciphertext: &[u8],
        additional_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        aes_decrypt(&self.key, nonce, ciphertext, additional_data)
    }

    pub const fn nonce_size() -> usize {
        AES_NONCE_LENGTH
    }
}
