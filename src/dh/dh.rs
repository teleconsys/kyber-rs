use aes_gcm::{
    aead::{Aead, Payload},
    aes::Block,
    Aes256Gcm, KeyInit,
};
use anyhow::{bail, Error, Ok, Result};
use crypto::cipher::BlockSizeUser;
use digest::{
    block_buffer::Eager,
    consts::{B0, B1, U256, U3},
    core_api::{BufferKindUser, CoreProxy, FixedOutputCore, UpdateCore},
    generic_array::{ArrayLength, GenericArray},
    typenum::{Cmp, IsLess, Le, NonZero, UInt, UTerm},
    HashMarker, OutputSizeUser,
};
use hkdf::Hkdf;
use sha2::{Sha256, Sha256VarCore};

use crate::{Point, Suite};

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
    HmacFixedOutputCore + HashMarker + UpdateCore + BufferKindUser<BufferKind = Eager> + Default + Clone
{
}

impl<T> HmacCompatibleCore for T
where
    T: HmacFixedOutputCore,
    T: HashMarker,
    T: UpdateCore,
    T: BufferKindUser<BufferKind = Eager>,
    T: Default,
    T: Clone,
{
}

pub trait HmacFixedOutputCore: FixedOutputCore<BlockSize = Self::B> {
    type B: HmacBlockSize;
}

impl<T: FixedOutputCore> HmacFixedOutputCore for T
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

trait HmacBlockSizeUser: BlockSizeUser<BlockSize = Self::B> {
    type B;
}

impl<T: BlockSizeUser> HmacBlockSizeUser for T {
    type B = T::BlockSize;
}

pub trait Dh {
    type H: HmacCompatible;

    /// dhExchange computes the shared key from a private key and a public key
    fn dh_exchange<SUITE: Suite>(
        suite: SUITE,
        own_private: <SUITE::POINT as Point>::SCALAR,
        remote_public: SUITE::POINT,
    ) -> SUITE::POINT {
        let sk = suite.point();
        sk.mul(&own_private, Some(&remote_public))
    }

    fn hkdf(ikm: &[u8], info: &[u8], output_size: Option<usize>) -> Result<Vec<u8>> {
        let size = match output_size {
            Some(s) => s,
            None => 32,
        };
        let h = Hkdf::<Self::H>::new(None, ikm);
        let mut out = Vec::with_capacity(size);
        for _ in 0..size {
            out.push(0u8);
        }
        h.expand(info, &mut out)
            .map_err(|_| Error::msg("unexpected error in hkdf_sha256"))?;

        Ok(out)
    }

    fn aes_encrypt(
        key: &[u8],
        nonce: &[u8; NONCE_SIZE],
        data: &[u8],
        additional_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        if key.len() != 32 {
            bail!("Key length should be 32")
        }
        let key = GenericArray::from_slice(key);
        let aes_gcm = Aes256Gcm::new(key);
        let nonce = GenericArray::from_slice(nonce);

        let payload: Payload = match additional_data {
            None => data.into(),
            Some(add_data) => Payload {
                aad: add_data,
                msg: data,
            },
        };

        let ciphertext = aes_gcm
            .encrypt(nonce, payload)
            .map_err(|_| Error::msg("aes encryption failed"))?;

        Ok(ciphertext)
    }

    fn aes_decrypt(
        key: &[u8],
        nonce: &[u8; NONCE_SIZE],
        ciphertext: &[u8],
        additional_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        if key.len() != 32 {
            bail!("Key length should be 32")
        }
        let key = GenericArray::from_slice(key);
        let aes_gcm = Aes256Gcm::new(key);
        let nonce = GenericArray::from_slice(nonce);

        let payload: Payload = match additional_data {
            None => ciphertext.into(),
            Some(add_data) => Payload {
                aad: add_data,
                msg: ciphertext,
            },
        };

        let decrypted = aes_gcm
            .decrypt(nonce, payload)
            .map_err(|e| Error::msg(format!("aes decryption failed: {:#?}", e)))?;

        Ok(decrypted)
    }

    fn encrypt<POINT: Point>(
        pre_key: &POINT,
        info: &[u8],
        nonce: &[u8; NONCE_SIZE],
        data: &[u8],
    ) -> Result<Vec<u8>> {
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
    ) -> Result<Vec<u8>> {
        let pre_buff = pre_key.marshal_binary()?;
        let key = Self::hkdf(&pre_buff, info, None)?;
        let decrypted = Self::aes_decrypt(&key, nonce, cipher, Some(info))?;

        Ok(decrypted)
    }
}

pub struct DhStandard {}
impl Dh for DhStandard {
    type H = Sha256;
}

pub struct AEAD {
    key: Vec<u8>,
}

impl AEAD {
    pub fn new<POINT: Point>(pre: POINT, hkfd_context: &Vec<u8>) -> Result<Self> {
        let pre_buff = pre.marshal_binary()?;
        let key = DhStandard::hkdf(&pre_buff, &hkfd_context, None)?;
        if key.len() != 32 {
            bail!("Key length should be 32")
        }
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
        nonce: &[u8; NONCE_SIZE],
        plaintext: &[u8],
        additional_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let encrypted = DhStandard::aes_encrypt(&self.key, nonce, plaintext, additional_data)?;
        if dst.is_some() {
            dst.unwrap().copy_from_slice(&encrypted);
        }
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
        dst: Option<&mut [u8]>,
        nonce: &[u8; NONCE_SIZE],
        ciphertext: &[u8],
        additional_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let decrypted = DhStandard::aes_decrypt(&self.key, nonce, ciphertext, additional_data)?;
        if dst.is_some() {
            dst.unwrap().copy_from_slice(&decrypted);
        }
        Ok(decrypted)
    }

    pub const fn nonce_size() -> usize {
        NONCE_SIZE
    }
}
