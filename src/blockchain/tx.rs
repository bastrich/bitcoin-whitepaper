
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
    pub fn new_regular(
        inputs: Vec<UTXOReference>,
        outputs: Vec<Rc<UTXOData>>,
        private_signature_key: &K256PrivateSignatureKey
    ) -> Result<Self, String> {
        Self::new(inputs, outputs, private_signature_key, false)
    }

    pub fn new_genesis(
        outputs: Vec<Rc<UTXOData>>,
        private_signature_key: &K256PrivateSignatureKey
    ) -> Result<Self, String> {
        Self::new(vec![], outputs, private_signature_key, true)
    }
    
    
    fn new(
        inputs: Vec<UTXOReference>,
        outputs: Vec<Rc<UTXOData>>,
        private_signature_key: &K256PrivateSignatureKey,
        is_genesis_tx: bool
    ) -> Result<Self, String> {
        if outputs.is_empty() {
            return Err("No outputs specified".to_string());
        }

        let has_duplicated_inputs = inputs.iter().unique().count() < inputs.len();
        if has_duplicated_inputs {
            return Err("Duplicated inputs specified".to_string());
        }

        let input_pubkeys: Vec<[u8; 33]> = inputs.iter()
            .map(|input| input.data.upgrade().expect("Expected valid UTXO data reference").pubkey)
            .unique()
            .collect();

        match input_pubkeys.len() {
            0 => {
                if !is_genesis_tx {
                    let output_pubkeys: Vec<[u8; 33]> = outputs.iter()
                        .map(|output| output.pubkey)
                        .unique()
                        .collect();
                    if output_pubkeys.len() > 1 {
                        return Err("If there are no inputs, only a single destination (mining fee) allowed".to_string());

                    }
                    if !private_signature_key.is_pair_for(K256PublicSignatureKey::from_bytes(output_pubkeys[0])?) {
                        return Err("If there are no inputs, public key of the output should correspond to the signer private key".to_string());
                    }
                }
            }
            1 => {
                if !private_signature_key.is_pair_for(K256PublicSignatureKey::from_bytes(input_pubkeys[0])?) {
                    return Err("Public key of the inputs should correspond to the signer private key".to_string());
                }
            }
            _ => {
                return Err("Only a single source address allowed".to_string());
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
    use std::any::Any;
    use std::rc::Weak;
    use rand_core::RngCore;
    use rust_decimal::Decimal;
    use secp256k1::rand;
    use secp256k1::rand::Rng;
    use super::*;

    #[test]
    fn test_no_outputs() {
        let private_key = K256PrivateSignatureKey::generate();

        assert_error(
            Tx::new_regular(vec![], vec![], &private_key),
            "No outputs specified"
        );
    }

    #[test]
    fn test_duplicated_inputs() {
        let private_key = K256PrivateSignatureKey::generate();
        let utxo_data = Rc::new(UTXOData {
            amount: Decimal::from(rand::rng().random_range(0..100)),
            pubkey: private_key.get_public_key().to_bytes()
        });
        let utxo_reference = UTXOReference {
            tx_hash: generate_random_bytes::<32>(),
            output_index: rand::rng().random_range(0..100),
            data: Weak::new()
        };
        let utxo_reference_duplicate = utxo_reference.clone();

        assert_error(
            Tx::new_regular(vec![utxo_reference, utxo_reference_duplicate], vec![Rc::clone(&utxo_data)], &private_key),
            "Duplicated inputs specified"
        );
    }

    #[test]
    fn test_no_inputs_single_destination() {
        let private_key_1 = K256PrivateSignatureKey::generate();
        let private_key_2 = K256PrivateSignatureKey::generate();
        let utxo_data_1 = Rc::new(UTXOData {
            amount: Decimal::from(rand::rng().random_range(0..100)),
            pubkey: private_key_1.get_public_key().to_bytes()
        });
        let utxo_data_2 = Rc::new(UTXOData {
            amount: Decimal::from(rand::rng().random_range(0..100)),
            pubkey: private_key_2.get_public_key().to_bytes()
        });

        assert_error(
            Tx::new_regular(vec![], vec![Rc::clone(&utxo_data_1), Rc::clone(&utxo_data_2)], &private_key_1),
            "If there are no inputs, only a single destination (mining fee) allowed"
        );
    }

    #[test]
    fn test_no_inputs_destination_key_pair() {
        let private_key_1 = K256PrivateSignatureKey::generate();
        let private_key_2 = K256PrivateSignatureKey::generate();
        let utxo_data = Rc::new(UTXOData {
            amount: Decimal::from(rand::rng().random_range(0..100)),
            pubkey: private_key_1.get_public_key().to_bytes()
        });

        assert_error(
            Tx::new_regular(vec![], vec![Rc::clone(&utxo_data)], &private_key_2),
            "If there are no inputs, public key of the output should correspond to the signer private key"
        );
    }

    #[test]
    fn test_source_key_pair() {
        let private_key_1 = K256PrivateSignatureKey::generate();
        let private_key_2 = K256PrivateSignatureKey::generate();
        let utxo_data = Rc::new(UTXOData {
            amount: Decimal::from(rand::rng().random_range(0..100)),
            pubkey: private_key_1.get_public_key().to_bytes()
        });
        let utxo_reference = UTXOReference {
            tx_hash: generate_random_bytes::<32>(),
            output_index: rand::rng().random_range(0..100),
            data: Rc::downgrade(&utxo_data)
        };

        assert_error(
            Tx::new_regular(vec![utxo_reference], vec![Rc::clone(&utxo_data)], &private_key_2),
            "Public key of the inputs should correspond to the signer private key"
        );
    }

    #[test]
    fn test_multiple_sources() {
        let private_key_1 = K256PrivateSignatureKey::generate();
        let private_key_2 = K256PrivateSignatureKey::generate();
        let utxo_data_1 = Rc::new(UTXOData {
            amount: Decimal::from(rand::rng().random_range(0..100)),
            pubkey: private_key_1.get_public_key().to_bytes()
        });
        let utxo_data_2 = Rc::new(UTXOData {
            amount: Decimal::from(rand::rng().random_range(0..100)),
            pubkey: private_key_2.get_public_key().to_bytes()
        });
        let utxo_reference_1 = UTXOReference {
            tx_hash: generate_random_bytes::<32>(),
            output_index: rand::rng().random_range(0..100),
            data: Rc::downgrade(&utxo_data_1)
        };
        let utxo_reference_2 = UTXOReference {
            tx_hash: generate_random_bytes::<32>(),
            output_index: rand::rng().random_range(0..100),
            data: Rc::downgrade(&utxo_data_2)
        };
        assert_error(
            Tx::new_regular(vec![utxo_reference_1, utxo_reference_2], vec![Rc::clone(&utxo_data_1)], &private_key_1),
            "Only a single source address allowed"
        );
    }

    #[test]
    fn test_create_and_verify() {
        let private_key_1 = K256PrivateSignatureKey::generate();
        let utxo_data_1 = Rc::new(UTXOData {
            amount: Decimal::from(rand::rng().random_range(0..100)),
            pubkey: private_key_1.get_public_key().to_bytes()
        });
        let utxo_data_2 = Rc::new(UTXOData {
            amount: Decimal::from(rand::rng().random_range(0..100)),
            pubkey: private_key_1.get_public_key().to_bytes()
        });
        let utxo_reference_1 = UTXOReference {
            tx_hash: generate_random_bytes::<32>(),
            output_index: rand::rng().random_range(0..100),
            data: Rc::downgrade(&utxo_data_1)
        };
        let utxo_reference_2 = UTXOReference {
            tx_hash: generate_random_bytes::<32>(),
            output_index: rand::rng().random_range(0..100),
            data: Rc::downgrade(&utxo_data_2)
        };

        let private_key_2 = K256PrivateSignatureKey::generate();
        let utxo_data_3 = Rc::new(UTXOData {
            amount: Decimal::from(rand::rng().random_range(0..100)),
            pubkey: private_key_2.get_public_key().to_bytes()
        });

        let tx = Tx::new_regular(
            vec![utxo_reference_1, utxo_reference_2],
            vec![Rc::clone(&utxo_data_3)],
            &private_key_1,
        ).expect("Successfully creating transaction expected");

        assert!(tx.verify(private_key_1.get_public_key()).is_ok());
        assert_error(
            tx.verify(private_key_2.get_public_key()),
            "Signature could not be decoded: signature failed verification"
        );
    }

    fn generate_random_bytes<const N: usize>() -> [u8; N] {
        let mut random_generator = rand::rng();
        let mut bytes = [0u8; N];
        random_generator.fill_bytes(&mut bytes);
        bytes
    }

    fn assert_error(result: Result<impl Any, String>, expected_error: &str) {
        match result {
            Ok(_) => assert!(false, "Expected an error: {}", expected_error),
            Err(error) => assert_eq!(error, expected_error),
        }
    }
}
