use std::rc::Rc;
use std::time::UNIX_EPOCH;
use rust_decimal::Decimal;
use rust_decimal::prelude::Zero;
use sha2::{Digest, Sha256};
use crate::blockchain::tx::Tx;
use crate::blockchain::utxo::UTXOData;
use crate::crypto::signature::{K256PrivateSignatureKey, K256PublicSignatureKey, PublicSignatureKey};

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
        author_pubkey: K256PublicSignatureKey,
        author_private_key: K256PrivateSignatureKey,
        mut txs: Vec<Tx>,
        prev_hash: [u8; 32],
    ) -> Result<Block, String> {
        let timestamp = UNIX_EPOCH.elapsed().unwrap().as_millis();

        let mut coinbase_outputs = vec![Rc::new(UTXOData {
            amount: Decimal::from(50),
            pubkey: author_pubkey.to_bytes(),
        })];
        let fee: Decimal  = txs.iter()
            .map(|tx| {
                let inputs_sum: Decimal = tx.inputs.iter().map(|i| i.data.upgrade().unwrap().amount).sum();
                let outputs_sum: Decimal  = tx.outputs.iter().map(|o| o.amount).sum();
                inputs_sum - outputs_sum
            })
            .sum();
        if fee > Decimal::zero() {
            coinbase_outputs.push(Rc::new(UTXOData {
                amount: Decimal::from(fee),
                pubkey: author_pubkey.to_bytes(),
            }))
        }
        let coinbase_tx = Tx::new(
            vec![],
            coinbase_outputs,
            &author_private_key
        ).unwrap();
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
            .expect("Failed to mine block");

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
}

#[cfg(test)]
mod tests {
    
    #[test]
    fn test_mine() {
        
    }
}