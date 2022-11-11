use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit,
};
use anyhow::{Error, Result};
use digest::{generic_array::GenericArray, OutputSizeUser};
use hkdf::{hmac::Hmac, Hkdf, HmacImpl};
use sha2::Sha256;

use crate::{Point, Scalar, Suite};

/// dhExchange computes the shared key from a private key and a public key
pub fn dhExchange<SCALAR, POINT, SUITE>(
    suite: SUITE,
    ownPrivate: SCALAR,
    remotePublic: POINT,
) -> POINT
where
    SCALAR: Scalar,
    POINT: Point<SCALAR>,
    SUITE: Suite<SCALAR, POINT>,
{
    let sk = suite.point();
    sk.mul(&ownPrivate, Some(&remotePublic))
}

// KEY_SIZE is arbitrary, make it long enough to seed the XOF
const KEY_SIZE: usize = 128;

/// context returns the context slice to be used when encrypting a share
pub fn context<SUITE, POINT, SCALAR>(
    suite: &SUITE,
    dealer: &POINT,
    verifiers: &Vec<POINT>,
) -> [u8; KEY_SIZE]
where
    SUITE: Suite<SCALAR, POINT>,
    POINT: Point<SCALAR>,
    SCALAR: Scalar,
{
    let mut h = suite.xof(Some("vss-dealer".as_bytes()));
    dealer.marshal_to(&mut h).unwrap();
    h.write("vss-verifiers".as_bytes()).unwrap();
    for v in verifiers {
        v.marshal_to(&mut h).unwrap();
    }
    let mut sum = [0 as u8; KEY_SIZE]; //make([]byte, keySize);
    h.read(&mut sum).unwrap();
    sum
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

pub fn aead_encrypt<S, POINT>(
    pre_key: POINT,
    info: &[u8],
    nonce: &[u8; AES_NONCE_LENGTH],
    data: &[u8],
) -> Result<Vec<u8>>
where
    S: Scalar,
    POINT: Point<S>,
{
    let pre_buff = pre_key.marshal_binary()?;
    let key = hkdf::<Sha256, Hmac<Sha256>>(&pre_buff, info)?;
    let encrypted = aes_encrypt(&key, nonce, data, Some(info))?;

    Ok(encrypted)
}

pub fn aead_decrypt<S, POINT>(
    pre_key: POINT,
    info: &[u8],
    nonce: &[u8; AES_NONCE_LENGTH],
    cipher: &[u8],
) -> Result<Vec<u8>>
where
    S: Scalar,
    POINT: Point<S>,
{
    let pre_buff = pre_key.marshal_binary()?;
    let key = hkdf::<Sha256, Hmac<Sha256>>(&pre_buff, info)?;
    let decrypted = aes_decrypt(&key, nonce, cipher, Some(info))?;

    Ok(decrypted)
}

pub struct AEAD {
    key: [u8; 32],
}

impl AEAD {
    pub fn new<SCALAR, POINT>(pre: POINT, hkfd_context: &Vec<u8>) -> Result<Self>
    where
        SCALAR: Scalar,
        POINT: Point<SCALAR>,
    {
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

    pub fn nonce_size(&self) -> usize {
        AES_NONCE_LENGTH
    }
}
