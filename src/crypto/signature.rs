use std::fmt::{Display, Formatter};
use secp256k1::{rand, PublicKey, SecretKey};
use secp256k1::{Secp256k1, Message};
use secp256k1::ecdsa::Signature;
use crate::hash;

pub trait PublicSignatureKey<const N: usize>: Eq + Sized + Display {
    fn verify(&self, data: impl AsRef<[u8]>, signature: &[u8; N]) -> Result<(), String>;
    fn to_bytes(&self) -> impl AsRef<[u8]>;
    fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, String>;
}

pub trait PrivateSignatureKey<const N: usize> {
    type PublicSignatureKey: PublicSignatureKey<N>;

    fn generate() -> Self;
    fn sign(&self, data: &[u8]) -> [u8; N];
    fn get_public_key(&self) -> Self::PublicSignatureKey;
    fn is_pair_for(&self, pubkey: Self::PublicSignatureKey) -> bool {
        self.get_public_key() == pubkey
    }
}

#[derive(PartialEq, Eq, Clone, Copy)]
#[derive(Debug)]
pub struct K256PublicSignatureKey {
    key: PublicKey
}

impl PublicSignatureKey<64> for K256PublicSignatureKey {
    fn verify(&self, data: impl AsRef<[u8]>, signature: &[u8; 64]) -> Result<(), String> {
        Signature::from_compact(signature)
            .map_err(|e| format!("Signature could not be decoded: {e}"))?
            .verify(Message::from_digest(hash!(data.as_ref())), &self.key)
            .map_err(|e| format!("Signature could not be decoded: {e}"))
    }

    #[allow(refining_impl_trait)]
    fn to_bytes(&self) -> [u8; 33] {
        self.key.serialize()
    }

    fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, String> {
        Ok(Self {
            key: PublicKey::from_byte_array_compressed(bytes.as_ref().try_into().map_err(|e| format!("Expected exactly 33 bytes: {e}"))?)
                .map_err(|e| format!("Error creating public key from bytes: {e}"))?
        })
    }
}

impl Display for K256PublicSignatureKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.key.to_string())
    }
}

pub struct K256PrivateSignatureKey {
    key: SecretKey
}

impl PrivateSignatureKey<64> for K256PrivateSignatureKey {
    type PublicSignatureKey = K256PublicSignatureKey;

    fn generate() -> Self {
        K256PrivateSignatureKey {
            key: SecretKey::new(&mut rand::rng())
        }
    }

    fn sign(&self, data: &[u8]) -> [u8; 64] {
        let mut signature = Secp256k1::new().sign_ecdsa(
            Message::from_digest(hash!(data)),
            &self.key
        );
        signature.normalize_s();
        signature.serialize_compact()
    }

    #[allow(refining_impl_trait)]
    fn get_public_key(&self) -> K256PublicSignatureKey {
        K256PublicSignatureKey {
            key: PublicKey::from_secret_key(&Secp256k1::new(), &self.key)
        }
    }
}

#[cfg(test)]
mod tests {
    use rand::{Rng, RngCore};
    use super::*;

    #[test]
    fn test_generate_sign_and_verify() {
        let private_key = K256PrivateSignatureKey::generate();
        let public_key = private_key.get_public_key();
        assert!(private_key.is_pair_for(public_key));

        let data = generate_random_bytes();
        let signature = private_key.sign(&data);
        assert!(public_key.verify(&data, &signature).is_ok());
    }

    #[test]
    fn test_serialize_deserialize_public_key() {
        let private_key = K256PrivateSignatureKey::generate();
        let public_key = private_key.get_public_key();

        let public_key_bytes = public_key.to_bytes();
        assert_eq!(K256PublicSignatureKey::from_bytes(&public_key_bytes).unwrap(), public_key);
    }

    #[test]
    fn test_not_corresponding_keys() {
        let private_key_1 = K256PrivateSignatureKey::generate();
        let private_key_2 = K256PrivateSignatureKey::generate();
        let public_key_2 = private_key_2.get_public_key();

        assert!(!private_key_1.is_pair_for(public_key_2));
    }

    fn generate_random_bytes() -> Vec<u8> {
        let mut random_generator = rand::rng();
        let mut bytes = vec![0u8; random_generator.random_range(0..100) as usize];
        random_generator.fill_bytes(&mut bytes);
        bytes
    }
}