use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use k256::ecdsa::signature::{Signer, Verifier};
use k256::elliptic_curve::rand_core::OsRng;
use sha2::{Digest, Sha256};

pub trait PublicSignatureKey<const N: usize> {

    fn verify(&self, data: &[u8], signature: &[u8; N]) -> bool;
}

pub trait PrivateSignatureKey<const N: usize> {
    fn generate() -> Self;
    fn sign(&self, data: &[u8]) -> [u8; N];
    fn get_public_key(&self) -> impl PublicSignatureKey<N>;
}

pub struct K256PublicSignatureKey {
    key: VerifyingKey
}

impl PublicSignatureKey<64> for K256PublicSignatureKey {
    fn verify(&self, data: &[u8], signature: &[u8; 64]) -> bool {
        self.key.verify(data, &Signature::from_slice(signature).unwrap()).is_ok()
    }
}


pub struct K256PrivateSignatureKey {
    key: SigningKey
}

impl PrivateSignatureKey<64> for K256PrivateSignatureKey {
    fn generate() -> Self {
        K256PrivateSignatureKey {
            key: SigningKey::random(&mut OsRng)
        }
    }

    fn sign(&self, data: &[u8]) -> [u8; 64] {
        let signature: Signature = self.key.sign(data);
        signature.to_bytes().into()
    }

    #[allow(refining_impl_trait)]
    fn get_public_key(&self) -> K256PublicSignatureKey {
        K256PublicSignatureKey {
            key: VerifyingKey::from(&self.key)
        }
    }
}

pub trait CryptoHash {
    fn calculate_crypto_hash(&self) -> [u8; 32] {
        Sha256::digest(self.provide_bytes()).into()
    }

    fn provide_bytes(&self) -> Vec<u8>;
}
