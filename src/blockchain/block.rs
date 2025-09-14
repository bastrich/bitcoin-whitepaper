use std::iter::once;
use std::rc::Rc;
use std::time::UNIX_EPOCH;
use rust_decimal::Decimal;
use rust_decimal::prelude::Zero;
use crate::blockchain::tx::Tx;
use crate::blockchain::utxo::UTXOData;
use crate::crypto::signature::{K256PrivateSignatureKey, K256PublicSignatureKey, PrivateSignatureKey, PublicSignatureKey};
use crate::hash;

pub struct Block {
    pub serial_number: u64,
    pub timestamp: u128,
    pub author_pubkey: K256PublicSignatureKey,
    pub hash: [u8; 32],
    pub txs: Vec<Rc<Tx>>,
    pub nonce: u32,
    pub prev_hash: [u8; 32],
}

impl Block {
    const TARGET_PREFIX: [u8; 2] = [0, 0];

    pub fn mine(
        serial_number: u64,
        author_private_key: &K256PrivateSignatureKey,
        mut txs: Vec<Tx>,
        prev_hash: [u8; 32],
    ) -> Result<Block, String> {
        let timestamp = UNIX_EPOCH.elapsed().map_err(|e| format!("Can't get current timestamp: {}", e))?.as_millis();
        let author_pubkey = author_private_key.get_public_key();
        let coinbase_tx = Self::build_coinbase_tx(author_private_key, &txs)?;

        txs.insert(0, coinbase_tx);

        let (nonce, hash) = (0..=u32::MAX)
            .find_map(|nonce| {
                let hash: [u8; 32] = hash!(
                    "Block:v1:",
                    serial_number.to_le_bytes(),
                    ":",
                    timestamp.to_le_bytes(),
                    ":",
                    txs.iter().map(|tx| tx.hash).collect::<Vec<_>>(),
                    nonce.to_le_bytes(),
                    prev_hash.as_slice()
                );

                if hash.starts_with(&Self::TARGET_PREFIX) {
                    Some((nonce, hash))
                } else {
                    None
                }
            })
            .ok_or_else(|| "Couldn't find required 'nonce' while mining block")?;

        let txs = txs.into_iter().map(|tx| Rc::new(tx)).collect();

        Ok(Block {
            serial_number,
            timestamp,
            author_pubkey,
            hash,
            txs,
            nonce,
            prev_hash,
        })
    }

    fn build_coinbase_tx(
        author_private_key: &K256PrivateSignatureKey,
        txs: &Vec<Tx>
    ) -> Result<Tx, String> {
        let mining_reward_output = Self::build_mining_reward_output(author_private_key.get_public_key().to_bytes());
        let fee_output = Self::build_fee_output(author_private_key.get_public_key().to_bytes(), &txs)?;
        let coinbase_outputs = once(mining_reward_output)
            .chain(fee_output)
            .collect();
        Tx::new_regular(
            vec![],
            coinbase_outputs,
            &author_private_key
        )
    }

    fn build_mining_reward_output(pubkey: [u8; 33]) -> Rc<UTXOData> {
        Rc::new(UTXOData {
            amount: Decimal::from(50),
            pubkey: pubkey,
        })
    }

    fn build_fee_output(pubkey: [u8; 33], txs: &[Tx]) -> Result<Option<Rc<UTXOData>>, String> {
        let fee: Decimal  = txs.iter()
            .try_fold(Decimal::ZERO, |sum, tx| {
                let inputs_sum: Decimal = tx.inputs.iter()
                    .try_fold(
                        Decimal::ZERO,
                        |inputs_sum, input| Ok::<Decimal, String>(inputs_sum + input.data.upgrade().ok_or_else(|| "Input reference is expected to refer a valid UTXO data".to_string())?.amount)
                    )?;
                let outputs_sum: Decimal  = tx.outputs.iter().map(|o| o.amount).sum();
                Ok::<Decimal, String>(sum + inputs_sum - outputs_sum)
            })?;

        if fee > Decimal::zero() {
            Ok(Some(Rc::new(UTXOData {
                amount: Decimal::from(fee),
                pubkey,
            })))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use rand_core::RngCore;
    use secp256k1::rand;
    use secp256k1::rand::Rng;
    use crate::blockchain::utxo::UTXOReference;
    use super::*;

    #[test]
    fn test_mine() {
        let serial_number = 123;
        let private_key = K256PrivateSignatureKey::generate();
        let sender_utxo_data = (0..rand::rng().random_range(1..10))
            .map(|_| {
                let sender_private_key = K256PrivateSignatureKey::generate();
                let utxos = generate_utxo_data(sender_private_key.get_public_key().to_bytes());
                (sender_private_key, utxos)
            })
            .collect::<Vec<_>>();
        let txs = sender_utxo_data.iter()
            .map(|(private_key, utxos)| {
                generate_random_tx(private_key, utxos)
            })
            .collect::<Vec<_>>();
        let txs_len = txs.len();
        let prev_hash = generate_random_bytes::<32>();

        let block = Block::mine(
            serial_number,
            &private_key,
            txs,
            prev_hash
        );
        assert!(block.is_ok(), "Expected successful block, got: {:?}", block.err());

        let block = block.unwrap();
        assert_eq!(block.serial_number, serial_number);
        assert!(block.timestamp < UNIX_EPOCH.elapsed().unwrap().as_millis());
        assert_eq!(block.author_pubkey, private_key.get_public_key());
        assert!(block.hash.starts_with(&[0u8]));
        assert_eq!(block.txs.len(), txs_len + 1);
        assert!(block.nonce > 0);
        assert_eq!(block.prev_hash, prev_hash);
    }

    fn generate_random_bytes<const N: usize>() -> [u8; N] {
        let mut random_generator = rand::rng();
        let mut bytes = [0u8; N];
        random_generator.fill_bytes(&mut bytes);
        bytes
    }

    fn generate_utxo_data(pubkey: [u8; 33]) -> Vec<Rc<UTXOData>> {
        vec![
            Rc::new(UTXOData {
                amount: Decimal::from(rand::rng().random_range(0..100)),
                pubkey
            }),
            Rc::new(UTXOData {
                amount: Decimal::from(rand::rng().random_range(0..100)),
                pubkey
            })
        ]
    }

    fn generate_random_tx(
        sender_private_key: &K256PrivateSignatureKey, sender_utxos: &Vec<Rc<UTXOData>>
    ) -> Tx {

        let sender_utxo_reference_1 = UTXOReference {
            tx_hash: generate_random_bytes::<32>(),
            output_index: rand::rng().random_range(0..100),
            data: Rc::downgrade(&sender_utxos[0])
        };
        let sender_utxo_reference_2 = UTXOReference {
            tx_hash: generate_random_bytes::<32>(),
            output_index: rand::rng().random_range(0..100),
            data: Rc::downgrade(&sender_utxos[1])
        };

        let receiver_public_key = K256PrivateSignatureKey::generate().get_public_key();
        let receiver_utxo_data = Rc::new(UTXOData {
            amount: Decimal::from(rand::rng().random_range(0..100)),
            pubkey: receiver_public_key.to_bytes()
        });

        Tx::new_regular(
            vec![sender_utxo_reference_1, sender_utxo_reference_2],
            vec![Rc::clone(&receiver_utxo_data)],
            &sender_private_key,
        ).expect("Successfully creating transaction expected")
    }
}