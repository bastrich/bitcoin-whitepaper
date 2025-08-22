use crate::blockchain::utxo::{UTXOData, UTXOReference};
use crate::crypto::{CryptoHash, K256PrivateSignatureKey, K256PublicSignatureKey, PrivateSignatureKey, PublicSignatureKey};
use k256::ecdsa::signature::{Signer, Verifier};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use std::ops::Deref;
use std::rc::Rc;
use std::time::UNIX_EPOCH;

trait Tx: CryptoHash {
    fn hash(&self) -> Vec<u8>;
}




// type Tx = Tx<64>;

// pub enum Tx {
//     K256Tx(SignedTx<64>)
// }

pub struct SignedTx<const N: usize> {
    timestamp: u128,
    pub inputs: Vec<UTXOReference>,
    pub outputs: Vec<Rc<UTXOData>>,
    signature: [u8; N]
}

impl SignedTx<64> {
    pub fn new(
        inputs: Vec<UTXOReference>,
        outputs: Vec<Rc<UTXOData>>,
        private_signature_key: &K256PrivateSignatureKey,
    ) -> Result<Self, String> {
        if outputs.is_empty() {
            return Err("No outputs specified".to_string());
        }

        let timestamp = UNIX_EPOCH.elapsed().unwrap().as_millis();
        let signature_bytes = private_signature_key
            .sign(Self::convert_to_bytes(timestamp, &inputs, &outputs).deref());

        Ok(Self {
            timestamp,
            inputs,
            outputs,
            signature: signature_bytes,
        })
    }

    pub fn verify(&self, public_signature_key: K256PublicSignatureKey) -> bool {
        let bytes = Self::convert_to_bytes(self.timestamp, &self.inputs, &self.outputs);
        public_signature_key.verify(&bytes, &self.signature)
    }

    fn convert_to_bytes(
        timestamp: u128,
        inputs: &Vec<UTXOReference>,
        outputs: &Vec<Rc<UTXOData>>,
    ) -> Vec<u8> {
        let mut bytes = vec![];

        bytes.append(b"Tx:v1:".to_vec().as_mut());
        bytes.append(timestamp.to_le_bytes().to_vec().as_mut());
        bytes.append(format!(":{}:", inputs.len()).as_bytes().to_vec().as_mut());
        for input in inputs {
            bytes.extend_from_slice(&input.calculate_crypto_hash());
            bytes.push(':'.try_into().unwrap());
        }
        bytes.append(format!(":{}", outputs.len()).as_bytes().to_vec().as_mut());
        for output in outputs {
            bytes.push(':'.try_into().unwrap());
            bytes.extend_from_slice(&output.calculate_crypto_hash());
        }

        bytes
    }
}

impl CryptoHash for SignedTx<64> {
    fn provide_bytes(&self) -> Vec<u8> {
        let mut bytes = Self::convert_to_bytes(self.timestamp, &self.inputs, &self.outputs);

        bytes.extend_from_slice(&self.signature);

        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_verify() {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = VerifyingKey::from(&signing_key);
    }
}
