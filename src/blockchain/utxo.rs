use std::rc::Weak;
use derivative::Derivative;
use rust_decimal::Decimal;
use crate::crypto::CryptoHash;

#[derive(Derivative)]
#[derivative(PartialEq, Eq, Hash)]
pub struct UTXOReference {
    pub tx_hash: Vec<u8>,
    pub output_index: u32,
    #[derivative(PartialEq="ignore")]
    #[derivative(Hash="ignore")]
    pub data: Weak<UTXOData>
}

impl CryptoHash for UTXOReference {
    fn provide_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];

        bytes.append(b"UTXOReference:v1:".to_vec().as_mut());
        bytes.append(self.tx_hash.clone().as_mut());
        bytes.push(':'.try_into().unwrap());
        bytes.append(self.output_index.to_le_bytes().to_vec().as_mut());

        bytes
    }
}

#[derive(PartialEq, Eq, Hash)]
pub struct UTXOData {
    pub amount: Decimal,
    pub pubkey: Vec<u8>,
}

impl CryptoHash for UTXOData {
    fn provide_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];

        bytes.extend_from_slice(b"UTXOData:v1:");
        bytes.extend_from_slice(&self.amount.serialize());
        bytes.push(':'.try_into().unwrap());
        bytes.append(self.pubkey.clone().as_mut());

        bytes
    }
}
