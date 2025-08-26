use std::iter::once;
use std::rc::Rc;
use std::time::UNIX_EPOCH;
use rust_decimal::Decimal;
use rust_decimal::prelude::Zero;
use sha2::{Digest, Sha256};
use crate::blockchain::tx::Tx;
use crate::blockchain::utxo::UTXOData;
use crate::crypto::signature::{K256PrivateSignatureKey, K256PublicSignatureKey, PrivateSignatureKey, PublicSignatureKey};

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
    const TARGET_PREFIX: [u8; 1] = [0];

    pub fn mine(
        serial_number: u64,
        author_private_key: &K256PrivateSignatureKey,
        mut txs: Vec<Tx>,
        prev_hash: [u8; 32],
    ) -> Result<Block, String> {
        let timestamp = UNIX_EPOCH.elapsed().unwrap().as_millis();
        let author_pubkey = author_private_key.get_public_key();
        let coinbase_tx = Self::build_coinbase_tx(author_private_key, &txs)?;

        txs.insert(0, coinbase_tx);

        let (nonce, hash) = (0..=u32::MAX)
            .find_map(|nonce| {
                let mut hasher = Sha256::new();

                hasher.update(b"Block:v1:");
                hasher.update(serial_number.to_le_bytes());
                hasher.update(b":");
                hasher.update(timestamp.to_le_bytes());
                hasher.update(b":");
                for tx in &txs {
                    hasher.update(tx.hash);
                }
                hasher.update(nonce.to_le_bytes());
                hasher.update(prev_hash.as_slice());

                let hash: [u8; 32] = hasher.finalize().into();
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
        let fee_output = Self::build_fee_output(author_private_key.get_public_key().to_bytes(), &txs);
        let coinbase_outputs = once(mining_reward_output)
            .chain(fee_output)
            .collect();
        Tx::new(
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

    fn build_fee_output(pubkey: [u8; 33], txs: &Vec<Tx>) -> Option<Rc<UTXOData>> {
        let fee: Decimal  = txs.iter()
            .map(|tx| {
                let inputs_sum: Decimal = tx.inputs.iter().map(|i| i.data.upgrade().unwrap().amount).sum();
                let outputs_sum: Decimal  = tx.outputs.iter().map(|o| o.amount).sum();
                inputs_sum - outputs_sum
            })
            .sum();

        if fee > Decimal::zero() {
            Some(Rc::new(UTXOData {
                amount: Decimal::from(fee),
                pubkey: pubkey,
            }))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use rand_core::RngCore;
    use secp256k1::rand;
    use super::*;

    #[test]
    fn test_mine() {
        let serial_number = 123;
        let private_key = K256PrivateSignatureKey::generate();
        let txs = vec![];
        let prev_hash = generate_random_bytes::<32>();

        let block = Block::mine(
            serial_number,
            &private_key,
            txs,
            prev_hash
        );
    }

    fn generate_random_bytes<const N: usize>() -> [u8; N] {
        let mut random_generator = rand::rng();
        let mut bytes = [0u8; N];
        random_generator.fill_bytes(&mut bytes);
        bytes
    }
}