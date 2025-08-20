use std::rc::Rc;
use std::time::UNIX_EPOCH;
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use k256::ecdsa::signature::{Signer, Verifier};
use rand::rngs::OsRng;
use crate::blockchain::{CryptoHash, UTXOData, UTXOReference};

pub struct Tx {
    timestamp: u128,
    pub inputs: Vec<UTXOReference>,
    pub outputs: Vec<Rc<UTXOData>>,
    signature: Vec<u8>,
}

impl Tx {
    pub fn new(inputs: Vec<UTXOReference>, outputs: Vec<Rc<UTXOData>>, private_signature_key: Vec<u8>) -> Self {
        let timestamp = UNIX_EPOCH.elapsed().unwrap().as_millis();

        let bytes = Self::build_bytes(timestamp, &inputs, &outputs);

        let signing_key = SigningKey::from_bytes(private_signature_key.as_slice().into()).unwrap();
        let signature: Signature = signing_key.sign(bytes.as_slice());
        let signature_bytes = signature.to_bytes().to_vec();

        Tx { timestamp, inputs, outputs, signature: signature_bytes }
    }

    pub fn verify(&self, public_signature_key: Vec<u8>) -> bool {
        let bytes = Self::build_bytes(
            self.timestamp,
            &self.inputs,
            &self.outputs,
        );
        let verifying_key = VerifyingKey::from_sec1_bytes(public_signature_key.as_slice()).unwrap();
        verifying_key.verify(bytes.as_slice(), &Signature::from_bytes(self.signature.as_slice().into()).unwrap()).is_ok()
    }

    fn build_bytes(timestamp: u128, inputs: &Vec<UTXOReference>, outputs: &Vec<Rc<UTXOData>>) -> Vec<u8> {
        let mut bytes = vec![];

        bytes.append(b"Tx:v1:".to_vec().as_mut());
        bytes.append(timestamp.to_le_bytes().to_vec().as_mut());
        bytes.append(
            format!(":{}:", inputs.len())
                .as_bytes()
                .to_vec()
                .as_mut(),
        );
        for input in inputs {
            bytes.append(input.calculate_crypto_hash().as_mut());
            bytes.push(':'.try_into().unwrap());
        }
        bytes.append(
            format!(":{}", outputs.len())
                .as_bytes()
                .to_vec()
                .as_mut(),
        );
        for output in outputs {
            bytes.push(':'.try_into().unwrap());
            bytes.append(output.calculate_crypto_hash().as_mut());
        }

        bytes
    }
}

impl CryptoHash for Tx {
    fn provide_bytes(&self) -> Vec<u8> {
        let mut bytes = Self::build_bytes(
            self.timestamp,
            &self.inputs,
            &self.outputs,
        );

        bytes.append(self.signature.clone().as_mut());

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