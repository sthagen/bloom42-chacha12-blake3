#![no_std]
#![doc = include_str!("README.md")]

use chacha12::ChaCha;
use constant_time_eq::constant_time_eq_32;

#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

pub const KEY_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 32;
pub const TAG_SIZE: usize = 32;

const ENCRYPTION_KDF_CONTEXT: &str = "ChaCha12-BLAKE3 encryption key";
const AUTHENTICATION_KDF_CONTEXT: &str = "ChaCha12-BLAKE3 authentication key";

#[derive(Clone, Copy, Debug)]
pub struct Error {}

#[cfg_attr(feature = "zeroize", derive(Zeroize, ZeroizeOnDrop))]
pub struct ChaCha12Blake3 {
    key: [u8; 32],
    authentication_key: [u8; 32],
}

impl ChaCha12Blake3 {
    pub fn new(key: [u8; 32]) -> Self {
        let authentication_key: [u8; 32] = blake3::derive_key(AUTHENTICATION_KDF_CONTEXT, &key);
        return ChaCha12Blake3 {
            key,
            authentication_key,
        };
    }

    #[cfg(feature = "alloc")]
    pub fn encrypt(&self, nonce: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
        let mut ciphertext = alloc::vec![0u8; plaintext.len() + TAG_SIZE];
        ciphertext[..plaintext.len()].copy_from_slice(&plaintext);

        let tag = self.encrypt_in_place_detached(nonce, &mut ciphertext[..plaintext.len()], aad);
        ciphertext[plaintext.len()..].copy_from_slice(&tag);

        return ciphertext;
    }

    #[cfg(feature = "alloc")]
    pub fn decrypt(&self, nonce: &[u8; 32], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
        if ciphertext.len() < TAG_SIZE {
            return Err(Error {});
        }

        let mut plaintext = alloc::vec![0u8; ciphertext.len() - TAG_SIZE];
        plaintext.copy_from_slice(&ciphertext[..ciphertext.len() - TAG_SIZE]);

        self.decrypt_in_place_detached(
            nonce,
            &mut plaintext,
            &ciphertext[ciphertext.len() - TAG_SIZE..].try_into().unwrap(),
            aad,
        )?;

        return Ok(plaintext);
    }

    pub fn encrypt_in_place_detached(&self, nonce: &[u8; 32], plaintext: &mut [u8], aad: &[u8]) -> [u8; 32] {
        // encryptionKey = blake3::derive_key(context="...", ikm=key || nonce)
        let encryption_key: [u8; 32] = blake3::Hasher::new_derive_key(ENCRYPTION_KDF_CONTEXT)
            .update(&self.key)
            .update(nonce)
            .finalize()
            .into();

        ChaCha::<12>::new(&encryption_key, &nonce[..8].try_into().unwrap()).xor_keystream(plaintext);

        let mut mac_hasher = blake3::Hasher::new_keyed(&self.authentication_key);
        mac_hasher.update(nonce);
        mac_hasher.update(aad);
        mac_hasher.update(&(aad.len() as u64).to_le_bytes());
        mac_hasher.update(&plaintext);
        mac_hasher.update(&(plaintext.len() as u64).to_le_bytes());
        let tag = mac_hasher.finalize();

        #[cfg(feature = "zeroize")]
        Zeroizing::new(encryption_key).zeroize();

        return tag.into();
    }

    pub fn decrypt_in_place_detached(
        &self,
        nonce: &[u8; 32],
        ciphertext: &mut [u8],
        tag: &[u8; 32],
        aad: &[u8],
    ) -> Result<(), Error> {
        let mut mac_hasher = blake3::Hasher::new_keyed(&self.authentication_key);
        mac_hasher.update(nonce);
        mac_hasher.update(aad);
        mac_hasher.update(&(aad.len() as u64).to_le_bytes());
        mac_hasher.update(&ciphertext);
        mac_hasher.update(&(ciphertext.len() as u64).to_le_bytes());
        let mac = mac_hasher.finalize();

        if !constant_time_eq_32(mac.as_bytes(), tag) {
            return Err(Error {});
        }

        // encryptionKey = blake3::derive_key(context="...", ikm=key || nonce)
        let encryption_key: [u8; 32] = blake3::Hasher::new_derive_key(ENCRYPTION_KDF_CONTEXT)
            .update(&self.key)
            .update(nonce)
            .finalize()
            .into();

        ChaCha::<12>::new(&encryption_key, &nonce[..8].try_into().unwrap()).xor_keystream(ciphertext);

        #[cfg(feature = "zeroize")]
        Zeroizing::new(encryption_key).zeroize();

        return Ok(());
    }
}
