mod tx;


use rust_decimal::Decimal;
use rust_decimal::prelude::Zero;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::mem;
use std::rc::{Rc, Weak};
use std::time::UNIX_EPOCH; // requires 'getrandom' feature

use derivative::Derivative;
use crate::blockchain::tx::Tx;

trait CryptoHash {
    fn calculate_crypto_hash(&self) -> Vec<u8> {
        Sha256::digest(self.provide_bytes().as_slice()).to_vec()
    }

    fn provide_bytes(&self) -> Vec<u8>;
}

struct Blockchain {
    blocks: Vec<Block>,
    tx_hash_to_tx: HashMap<Vec<u8>, Rc<Tx>>,
    mempool: Vec<Tx>,
}

impl Blockchain {
    fn new(genesis_transactions: Vec<Tx>, author_pubkey: Vec<u8>, author_private_key: Vec<u8>) -> Blockchain {
        let genesis_block = Block::mine(0, author_pubkey, author_private_key, genesis_transactions, [0u8; 32].to_vec());
        let tx_hash_to_tx = genesis_block
            .txs
            .iter()
            .map(|tx| (tx.calculate_crypto_hash(), Rc::clone(tx)))
            .collect::<HashMap<Vec<u8>, Rc<Tx>>>();
        Blockchain {
            blocks: vec![genesis_block],
            tx_hash_to_tx,
            mempool: vec![],
        }
    }

    fn get_balance(&self, pubkey: Vec<u8>) -> Decimal {
        let mut balance = Decimal::zero();

        for block in &self.blocks {
            for tx in &block.txs {
                for utxo_reference in &tx.inputs {
                    let utxo_data = &self
                        .tx_hash_to_tx
                        .get(&utxo_reference.tx_hash)
                        .unwrap()
                        .outputs[utxo_reference.output_index as usize];
                    if utxo_data.pubkey == pubkey {
                        balance -= utxo_data.amount;
                    }
                }

                for utxo_data in &tx.outputs {
                    if utxo_data.pubkey == pubkey {
                        balance += utxo_data.amount;
                    }
                }
            }
        }

        balance
    }

    fn get_available_outputs(&self, source_pubkey: Vec<u8>) -> Vec<UTXOReference> {
        let mut outputs = self.blocks
            .iter()
            .fold(HashSet::new(), |mut outputs, block| {
                block.txs.iter().for_each(|tx| {
                    for input in &tx.inputs {
                        outputs.remove(input);
                    }

                    let tx_hash = tx.calculate_crypto_hash();
                    tx.outputs.iter()
                        .filter(|output| output.pubkey == source_pubkey)
                        .enumerate()
                        .for_each(|(i, output)| {
                        outputs.insert(UTXOReference {
                            tx_hash: tx_hash.clone(),
                            output_index: i as u32,
                            data: Rc::downgrade(&output),
                        });
                    });
                });

                outputs
            })
            .into_iter()
            .collect::<Vec<UTXOReference>>();

        outputs.sort_by_key(|output| output.data.upgrade().unwrap().amount);

        outputs
    }

    fn build_tx(
        &self,
        available_outputs: Vec<UTXOReference>,
        amount: Decimal,
        fee: Decimal,
        destination_pubkey: Vec<u8>,
        source_private_key: Vec<u8>,
    ) -> Result<Tx, &str> {
        let mut collected_input = Decimal::zero();
        let mut tx_inputs = vec![];
        for output in available_outputs {
            collected_input += output.data.upgrade().unwrap().amount;
            tx_inputs.push(output);

            if collected_input >= amount + fee {
                break;
            }
        }

        if collected_input < amount + fee {
            return Err("Not enough balance");
        }

        let mut tx_outputs = vec![
            Rc::new(UTXOData {
                amount: amount,
                pubkey: destination_pubkey
            })
        ];
        let exchange = collected_input - amount - fee;
        if exchange > Decimal::zero() {
            tx_outputs.push(Rc::new(UTXOData {
                amount: exchange,
                pubkey: tx_inputs.first().unwrap().data.upgrade().unwrap().pubkey.clone(),
            }));
        }

        Ok(Tx::new(tx_inputs, tx_outputs, source_private_key))
    }

    fn create_tx_in_mempool(
        &mut self,
        source_public_key: Vec<u8>,
        source_private_key: Vec<u8>,
        amount: Decimal,
        destination_pubkey: Vec<u8>,
    ) -> Result<(), &str> {
        self.mempool.push(self.build_tx(
            self.get_available_outputs(source_public_key),
            amount,
            Decimal::try_from("1.00").unwrap(),
            destination_pubkey,
            source_private_key
        ).unwrap());
        Ok(())
    }

    fn mine_next_block(&mut self, author_pubkey: Vec<u8>, author_private_key: Vec<u8>) {
        if self.mempool.is_empty() {
            return;
        }

        let new_block = Block::mine(
            self.blocks.len() as u64,
            author_pubkey,
            author_private_key,
            mem::take(&mut self.mempool),
            self.blocks.last().unwrap().hash.clone(),
        );

        for (hash, tx) in new_block
            .txs
            .iter()
            .map(|tx| (tx.calculate_crypto_hash(), Rc::clone(tx)))
        {
            self.tx_hash_to_tx.insert(hash, tx);
        }

        self.blocks.push(new_block);
    }
}

struct Block {
    serial_number: u64,
    timestamp: u128,
    author_pubkey: Vec<u8>,
    hash: Vec<u8>,
    txs: Vec<Rc<Tx>>,
    nonce: u32,
    prev_hash: Vec<u8>,
}

impl Block {
    fn mine(
        serial_number: u64,
        author_pubkey: Vec<u8>,
        author_private_key: Vec<u8>,
        mut txs: Vec<Tx>,
        prev_hash: Vec<u8>,
    ) -> Block {
        let timestamp = UNIX_EPOCH.elapsed().unwrap().as_millis();
        let target_prefix = b"\x00\x00";

        let reward_tx = Tx::new(
            vec![],
            vec![Rc::new(UTXOData {
                amount: Decimal::from(50),
                pubkey: author_pubkey.clone(),
            })],
            author_private_key
        );
        txs.insert(0, reward_tx);

        let (nonce, hash) = (0..=u32::MAX)
            .find_map(|nonce| {
                let mut hasher = Sha256::new();

                hasher.update(b"Block:v1:");
                hasher.update(serial_number.to_le_bytes());
                hasher.update(b":");
                hasher.update(timestamp.to_le_bytes());
                hasher.update(b":");
                for tx in &txs {
                    hasher.update(tx.calculate_crypto_hash());
                }
                hasher.update(nonce.to_le_bytes());
                hasher.update(prev_hash.as_slice());

                let hash = hasher.finalize();
                if hash.starts_with(target_prefix) {
                    Some((nonce, hash.to_vec()))
                } else {
                    None
                }
            })
            .expect("Failed to mine block");

        let txs = txs.into_iter().map(|tx| Rc::new(tx)).collect();

        Block {
            serial_number,
            timestamp,
            author_pubkey,
            hash,
            txs,
            nonce,
            prev_hash,
        }
    }
}



#[derive(Derivative)]
#[derivative(PartialEq, Eq, Hash)]
struct UTXOReference {
    tx_hash: Vec<u8>,
    output_index: u32,
    #[derivative(PartialEq="ignore")]
    #[derivative(Hash="ignore")]
    data: Weak<UTXOData>
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
struct UTXOData {
    amount: Decimal,
    pubkey: Vec<u8>,
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
