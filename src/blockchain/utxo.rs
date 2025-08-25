use std::rc::Weak;
use derivative::Derivative;
use rust_decimal::Decimal;
use sha2::{Digest, Sha256};

#[derive(Derivative)]
#[derivative(PartialEq, Eq, Hash, Clone)]
pub struct UTXOReference {
    pub tx_hash: [u8; 32],
    pub output_index: u32,
    #[derivative(PartialEq="ignore")]
    #[derivative(Hash="ignore")]
    pub data: Weak<UTXOData>
}

impl UTXOReference {
    pub fn calculate_crypto_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update("UTXOReference:v1:");
        hasher.update(&self.tx_hash);
        hasher.update(":");
        hasher.update(&self.output_index.to_le_bytes());
        hasher.finalize().into()
    }
}

#[derive(PartialEq, Eq)]
pub struct UTXOData {
    pub amount: Decimal,
    pub pubkey: [u8; 33],
}

impl UTXOData {
    pub fn calculate_crypto_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update("UTXOData:v1:");
        hasher.update(&self.amount.serialize());
        hasher.update(":");
        hasher.update(&self.pubkey);
        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use std::rc::Rc;
    use rand_core::RngCore;
    use secp256k1::rand;
    use secp256k1::rand::Rng;
    use super::*;

    #[test]
    fn test_create_and_hash_utxo_reference() {
        let utxo_reference_1 = UTXOReference {
            tx_hash: generate_random_bytes::<32>(),
            output_index: rand::rng().random_range(0..100),
            data: Weak::new()
        };
        let hash_1 = utxo_reference_1.calculate_crypto_hash();
        let hash_1_retried = utxo_reference_1.calculate_crypto_hash();

        let utxo_reference_2 = UTXOReference {
            tx_hash: generate_random_bytes::<32>(),
            output_index: rand::rng().random_range(0..100),
            data: Weak::new()
        };
        let hash_2 = utxo_reference_2.calculate_crypto_hash();

        assert_eq!(hash_1, hash_1_retried);
        assert_ne!(hash_1, hash_2);

    }

    #[test]
    fn test_create_and_hash_utxo_data() {
        let utxo_data_1 = UTXOData {
            amount: Decimal::from(rand::rng().random_range(0..100)),
            pubkey: generate_random_bytes::<33>()
        };
        let hash_1 = utxo_data_1.calculate_crypto_hash();
        let hash_1_retried = utxo_data_1.calculate_crypto_hash();

        let utxo_data_2 = UTXOData {
            amount: Decimal::from(rand::rng().random_range(0..100)),
            pubkey: generate_random_bytes::<33>()
        };
        let hash_2 = utxo_data_2.calculate_crypto_hash();

        assert_eq!(hash_1, hash_1_retried);
        assert_ne!(hash_1, hash_2);
    }

    fn generate_random_bytes<const N: usize>() -> [u8; N] {
        let mut random_generator = rand::rng();
        let mut bytes = [0u8; N];
        random_generator.fill_bytes(&mut bytes);
        bytes
    }
}
