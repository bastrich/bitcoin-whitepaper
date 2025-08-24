
use crate::blockchain::utxo::{UTXOData, UTXOReference};
use crate::crypto::signature::{K256PrivateSignatureKey, K256PublicSignatureKey, PrivateSignatureKey, PublicSignatureKey};
use std::rc::Rc;
use itertools::Itertools;
use sha2::{Digest, Sha256};

pub struct Tx {
    pub hash: [u8; 32],
    pub inputs: Vec<UTXOReference>,
    pub outputs: Vec<Rc<UTXOData>>,
    signature: [u8; 64]
}

impl Tx {
    pub fn new(
        inputs: Vec<UTXOReference>,
        outputs: Vec<Rc<UTXOData>>,
        private_signature_key: &K256PrivateSignatureKey,
    ) -> Result<Self, String> {
        if outputs.is_empty() {
            return Err("No outputs specified".to_string());
        }

        let input_pubkeys: Vec<[u8; 33]> = inputs.iter()
            .map(|input| input.data.upgrade().unwrap().pubkey)
            .unique()
            .collect();

        match input_pubkeys.len() {
            0 => {
                let output_pubkeys: Vec<[u8; 33]> = outputs.iter()
                    .map(|output| output.pubkey)
                    .unique()
                    .collect();
                if output_pubkeys.len() > 1 {
                    return Err("Ounlly singlke".to_string());

                }
                if !private_signature_key.is_pair_for(K256PublicSignatureKey::from_bytes(output_pubkeys[0])?) {
                    return Err("Invalid public key".to_string());
                }
            }
            1 => {
                if !private_signature_key.is_pair_for(K256PublicSignatureKey::from_bytes(input_pubkeys[0])?) {
                    return Err("Invalid public key".to_string());
                }
            }
            _ => {
                return Err("Only single sender possible".to_string());
            }
        }

        let data_bytes = Self::convert_to_bytes(&inputs, &outputs);
        let signature = private_signature_key.sign(data_bytes.as_ref());

        let mut hasher = Sha256::new();
        hasher.update(data_bytes);
        hasher.update(":");
        hasher.update(signature);
        let hash = hasher.finalize().into();

        Ok(Self {
            hash,
            inputs,
            outputs,
            signature,
        })
    }

    pub fn verify(&self, public_signature_key: K256PublicSignatureKey) -> Result<(), String> {
        let bytes = Self::convert_to_bytes(&self.inputs, &self.outputs);
        public_signature_key.verify(&bytes, &self.signature)
    }

    fn convert_to_bytes(
        inputs: &Vec<UTXOReference>,
        outputs: &Vec<Rc<UTXOData>>,
    ) -> impl AsRef<[u8]> {
        let mut bytes = vec![];

        bytes.extend_from_slice(format!("Tx:v1:{}:", inputs.len()).as_bytes());
        for input in inputs {
            bytes.extend_from_slice(input.calculate_crypto_hash().as_ref());
            bytes.extend_from_slice(b":");
        }
        bytes.extend_from_slice(format!(":{}", outputs.len()).as_bytes());
        for output in outputs {
            bytes.extend_from_slice(b":");
            bytes.extend_from_slice(output.calculate_crypto_hash().as_ref());
        }

        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_verify() {

    }
}
