use std::rc::Weak;
use derivative::Derivative;
use rust_decimal::Decimal;
use sha2::{Digest, Sha256};

#[derive(Derivative)]
#[derivative(PartialEq, Eq, Hash)]
pub struct UTXOReference {
    pub tx_hash: [u8; 32],
    pub output_index: u32,
    #[derivative(PartialEq="ignore")]
    #[derivative(Hash="ignore")]
    pub data: Weak<UTXOData>
}

impl UTXOReference {
    pub fn calculate_crypto_hash(&self) -> impl AsRef<[u8]> {
        let mut hasher = Sha256::new();
        hasher.update("UTXOReference:v1:");
        hasher.update(&self.tx_hash);
        hasher.update(":");
        hasher.update(&self.output_index.to_le_bytes());
        hasher.finalize()
    }
}

#[derive(PartialEq, Eq)]
pub struct UTXOData {
    pub amount: Decimal,
    pub pubkey: [u8; 33],
}

impl UTXOData {
    pub fn calculate_crypto_hash(&self) -> impl AsRef<[u8]> {
        let mut hasher = Sha256::new();
        hasher.update("UTXOData:v1:");
        hasher.update(&self.amount.serialize());
        hasher.update(":");
        hasher.update(&self.pubkey);
        hasher.finalize()
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_hash() {

    }
}
