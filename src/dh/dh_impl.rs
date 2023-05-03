use core::marker::PhantomData;

use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit,
};
use digest::{
    block_buffer::Eager,
    consts::U256,
    core_api::{BufferKindUser, CoreProxy, FixedOutputCore, UpdateCore},
    generic_array::GenericArray,
    typenum::{IsLess, Le, NonZero},
    HashMarker, OutputSizeUser,
};
use hkdf::Hkdf;
use thiserror::Error;

use crate::{encoding::MarshallingError, group::HashFactory, share::vss::suite::Suite, Point};

pub(crate) const NONCE_SIZE: usize = 12;

pub trait HmacCompatible: OutputSizeUser + CoreProxy<Core = Self::C> {
    type C: HmacCompatibleCore;
}

impl<T: CoreProxy + OutputSizeUser> HmacCompatible for T
where
    <T as CoreProxy>::Core: HmacCompatibleCore,
{
    type C = T::Core;
}

pub trait HmacCompatibleCore:
    FixedOutputCore<BlockSize = Self::B>
    + HashMarker
    + UpdateCore
    + BufferKindUser<BufferKind = Eager>
    + Default
    + Clone
{
    type B: HmacBlockSize;
}

impl<
        T: HashMarker
            + UpdateCore
            + BufferKindUser<BufferKind = Eager>
            + Default
            + Clone
            + FixedOutputCore,
    > HmacCompatibleCore for T
where
    Self::BlockSize: IsLess<U256>,
    Le<Self::BlockSize, U256>: NonZero,
{
    type B = Self::BlockSize;
}

pub trait HmacBlockSize: IsLess<U256, Output = Self::O> {
    type O: NonZero;
}

impl<T: IsLess<U256>> HmacBlockSize for T
where
    Self::Output: NonZero,
{
    type O = Self::Output;
}

pub trait Dh {
    type H: HmacCompatible;

    /// [`dh_exchange()`] computes the shared key from a private key and a public key
    fn dh_exchange<SUITE: Suite>(
        suite: SUITE,
        own_private: <SUITE::POINT as Point>::SCALAR,
        remote_public: SUITE::POINT,
    ) -> SUITE::POINT {
        suite.point().mul(&own_private, Some(&remote_public))
    }

    fn hkdf(ikm: &[u8], info: &[u8], output_size: Option<usize>) -> Result<Vec<u8>, DhError> {
        let size = output_size.unwrap_or(32);
        let h = Hkdf::<Self::H>::new(None, ikm);
        let mut out = vec![0; size];
        h.expand(info, &mut out)
            .map_err(|e| DhError::HkdfFailure(e.to_string()))?;

        Ok(out)
    }

    fn aes_encrypt(
        key: &[u8],
        nonce: &[u8; NONCE_SIZE],
        data: &[u8],
        additional_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, DhError> {
        let key_len = key.len();
        if key_len != 32 {
            return Err(DhError::WrongKeyLength(format!(
                "expected 32, got {key_len}"
            )));
        }
        let key = GenericArray::from_slice(key);
        let aes_gcm = Aes256Gcm::new(key);
        let nonce = GenericArray::from_slice(nonce);

        let payload: Payload = match additional_data {
            None => Payload::from(data),
            Some(add_data) => Payload {
                aad: add_data,
                msg: data,
            },
        };

        let ciphertext = aes_gcm
            .encrypt(nonce, payload)
            .map_err(|e| DhError::DecryptionFailed(e.to_string()))?;

        Ok(ciphertext)
    }

    fn aes_decrypt(
        key: &[u8],
        nonce: &[u8; NONCE_SIZE],
        ciphertext: &[u8],
        additional_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, DhError> {
        let key_len = key.len();
        if key_len != 32 {
            return Err(DhError::WrongKeyLength(format!(
                "expected 32, got {key_len}"
            )));
        }
        let key = GenericArray::from_slice(key);
        let aes_gcm = Aes256Gcm::new(key);
        let nonce = GenericArray::from_slice(nonce);

        let payload: Payload = match additional_data {
            None => Payload::from(ciphertext),
            Some(add_data) => Payload {
                aad: add_data,
                msg: ciphertext,
            },
        };

        let decrypted = aes_gcm
            .decrypt(nonce, payload)
            .map_err(|e| DhError::DecryptionFailed(e.to_string()))?;

        Ok(decrypted)
    }

    fn encrypt<POINT: Point>(
        pre_key: &POINT,
        info: &[u8],
        nonce: &[u8; NONCE_SIZE],
        data: &[u8],
    ) -> Result<Vec<u8>, DhError> {
        let pre_buff = pre_key.marshal_binary()?;
        let key = Self::hkdf(&pre_buff, info, None)?;
        let encrypted = Self::aes_encrypt(&key, nonce, data, Some(info))?;

        Ok(encrypted)
    }

    fn decrypt<POINT: Point>(
        pre_key: &POINT,
        info: &[u8],
        nonce: &[u8; NONCE_SIZE],
        cipher: &[u8],
    ) -> Result<Vec<u8>, DhError> {
        let pre_buff = pre_key.marshal_binary()?;
        let key = Self::hkdf(&pre_buff, info, None)?;
        let decrypted = Self::aes_decrypt(&key, nonce, cipher, Some(info))?;

        Ok(decrypted)
    }
}

impl<T: HashFactory> Dh for T {
    type H = T::T;
}

pub struct AEAD<T: Dh> {
    key: Vec<u8>,
    phantom: PhantomData<T>,
}

impl<DH: Dh> AEAD<DH> {
    pub fn new<POINT: Point>(pre: POINT, hkfd_context: &[u8]) -> Result<Self, DhError> {
        let pre_buff = pre.marshal_binary()?;
        let key = DH::hkdf(&pre_buff, hkfd_context, None)?;
        let key_len = key.len();
        if key_len != 32 {
            return Err(DhError::WrongKeyLength(format!(
                "expected 32, got {key_len}"
            )));
        }
        Ok(AEAD {
            key,
            phantom: PhantomData,
        })
    }

    /// [`seal()`] encrypts and authenticates `plaintext`, authenticates the
    /// `additional_data` and appends the result to `dst`, returning the updated
    /// slice. The nonce must be [`NONCE_SIZE`] bytes long and unique for all
    /// time, for a given key.
    ///
    /// To reuse `plaintext`'s storage for the encrypted output, use `plaintext[..0]`
    /// as `dst`. Otherwise, the remaining capacity of dst must not overlap plaintext.
    pub fn seal(
        &self,
        dst: Option<&mut [u8]>,
        nonce: &[u8; NONCE_SIZE],
        plaintext: &[u8],
        additional_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, DhError> {
        let encrypted = DH::aes_encrypt(&self.key, nonce, plaintext, additional_data)?;
        if let Some(d) = dst {
            d.copy_from_slice(&encrypted);
        }
        Ok(encrypted)
    }

    /// [`open()`] decrypts and authenticates `ciphertext`, authenticates the
    /// `additional_data` and, if successful, appends the resulting `plaintext`
    /// to `dst`, returning the updated slice. The `nonce` must be [`NONCE_SIZE`]
    /// bytes long and both it and the additional data must match the
    /// value passed to [`seal()`].
    ///
    /// To reuse ciphertext's storage for the decrypted output, use `ciphertext[..0]`
    /// as `dst`. Otherwise, the remaining capacity of `dst` must not overlap `plaintext`.
    ///
    /// Even if the function fails, the contents of `dst`, up to its capacity,
    /// may be overwritten.
    pub fn open(
        &self,
        dst: Option<&mut [u8]>,
        nonce: &[u8; NONCE_SIZE],
        ciphertext: &[u8],
        additional_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, DhError> {
        let decrypted = DH::aes_decrypt(&self.key, nonce, ciphertext, additional_data)?;
        if let Some(d) = dst {
            d.copy_from_slice(&decrypted);
        }
        Ok(decrypted)
    }

    pub const fn nonce_size() -> usize {
        NONCE_SIZE
    }
}

#[derive(Debug, Error)]
pub enum DhError {
    #[error("marshalling error")]
    MarshalingError(#[from] MarshallingError),
    #[error("wrong key length")]
    WrongKeyLength(String),
    #[error("aes decryption failed")]
    DecryptionFailed(String),
    #[error("aes encryption failed")]
    EncryptionFailed(String),
    #[error("unexpected error in hkdf_sha256")]
    HkdfFailure(String),
}
