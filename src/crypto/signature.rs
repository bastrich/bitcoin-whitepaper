use secp256k1::{rand, PublicKey, SecretKey};
use secp256k1::{Secp256k1, Message};
use secp256k1::ecdsa::Signature;
use sha2::{Digest, Sha256};

pub trait PublicSignatureKey<const N: usize>: Eq {
    fn verify(&self, data: impl AsRef<[u8]>, signature: &[u8; N]) -> bool;
    fn to_bytes(&self) -> impl AsRef<[u8]>;
    fn from_bytes(bytes: impl AsRef<[u8]>) -> Self;
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
pub struct K256PublicSignatureKey {
    key: PublicKey
}

impl K256PublicSignatureKey {
    fn is_high_s(signature: &Signature) -> bool {
        let mut normalized_signature = signature.clone();
        normalized_signature.normalize_s();
        signature != &normalized_signature
    }
}

impl PublicSignatureKey<64> for K256PublicSignatureKey {
    fn verify(&self, data: impl AsRef<[u8]>, signature: &[u8; 64]) -> bool {
        let signature =  Signature::from_compact(signature).unwrap();
        if Self::is_high_s(&signature) {
            return false;
        }
        signature.verify(Message::from_digest(Sha256::digest(data).into()), &self.key).is_ok()
    }

    #[allow(refining_impl_trait)]
    fn to_bytes(&self) -> [u8; 33] {
        self.key.serialize()
    }

    fn from_bytes(bytes: impl AsRef<[u8]>) -> Self {
        Self {
            key: PublicKey::from_byte_array_compressed(bytes.as_ref().try_into().expect("expected exactly 33 bytes")).unwrap()
        }
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
            Message::from_digest(Sha256::digest(data).into()),
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
        assert!(public_key.verify(&data, &signature));
    }

    fn generate_random_bytes() -> Vec<u8> {
        let mut random_generator = rand::rng();
        let mut bytes = vec![0u8; random_generator.random_range(0..100) as usize];
        random_generator.fill_bytes(&mut bytes);
        bytes
    }
}