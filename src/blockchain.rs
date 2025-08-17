use std::collections::HashMap;
use std::hash::Hash;
use std::rc::Rc;
use rust_decimal::Decimal;
use std::time::UNIX_EPOCH;
use rust_decimal::prelude::Zero;
use sha2::{Digest, Sha256};

trait CryptoHash {
    fn calculate_crypto_hash(&self) -> Vec<u8> {
        Sha256::digest(self.provide_bytes().as_slice()).to_vec()
    }

    fn provide_bytes(&self) -> Vec<u8>;
}

struct Blockchain {
    genesis_block: LinkedBlock,
    tx_hash_to_tx: HashMap<Vec<u8>, Rc<Tx>>,
    mempool: Vec<Tx>,
}

struct LinkedBlock {
    prev: Option<Box<LinkedBlock>>,
    value: Block,
    next: Option<Box<LinkedBlock>>,
}

impl Blockchain {
    fn new(genesis_transactions: Vec<Tx>) -> Blockchain {
        let genesis_block = Block::mine(0, genesis_transactions, [0u8; 32].to_vec());
        let tx_hash_to_tx = genesis_block.txs.iter().map(|tx| (tx.calculate_crypto_hash(), Rc::clone(tx))).collect::<HashMap<Vec<u8>, Rc<Tx>>>();
        Blockchain {
            genesis_block: LinkedBlock {
                prev: None,
                value: genesis_block,
                next: None,
            },
            tx_hash_to_tx,
            mempool: vec![]
        }
    }

    fn get_balance(&self, pubkey: Vec<u8>) -> Decimal {
        let mut balance = Decimal::zero();

        let mut current_block =  Some(&self.genesis_block);
        while let Some(linked_block) = &current_block {
            let block = &linked_block.value;
            for tx in &block.txs {
                for utxo_reference in &tx.inputs {
                    let utxo_data = &self.tx_hash_to_tx.get(&utxo_reference.tx_hash).unwrap().outputs[utxo_reference.output_index as usize];
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

            current_block = linked_block.next.as_deref();
        }

        balance
    }

    fn add_tx_to_mempool(&self, source_pubkey: Vec<u8>, amount: Decimal, destination_pubkey: Vec<u8>)  {

    }

    fn mine_next_block(&self) {
        if self.mempool.is_empty() {
            return;
        }


    }
}

struct Block {
    serial_number: u64,
    timestamp: u128,
    hash: Vec<u8>,
    txs: Vec<Rc<Tx>>,
    nonce: u32,
    prev_hash: Vec<u8>,
}

impl Block {
    fn mine(serial_number: u64, txs: Vec<Tx>, prev_hash: Vec<u8>) -> Block {
        let timestamp = UNIX_EPOCH.elapsed().unwrap().as_millis();
        let target_prefix = b"\x00\x00";

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

        let txs  = txs.into_iter().map(|tx| Rc::new(tx)).collect();

        Block {
            serial_number, timestamp, hash, txs, nonce, prev_hash
        }
    }
}

struct Tx {
    timestamp: u128,
    inputs: Vec<UTXOReference>,
    outputs: Vec<UTXOData>,
    signature: Vec<u8>,
}

impl CryptoHash for Tx {
    fn provide_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];

        bytes.append(b"Tx:v1:".to_vec().as_mut());
        bytes.append(self.timestamp.to_le_bytes().to_vec().as_mut());
        bytes.append(format!(":{}:", &self.inputs.len()).as_bytes().to_vec().as_mut());
        for input in &self.inputs {
            bytes.append(input.calculate_crypto_hash().as_mut());
            bytes.push(':'.try_into().unwrap());
        }
        bytes.append(format!(":{}:", &self.outputs.len()).as_bytes().to_vec().as_mut());
        for output in &self.outputs {
            bytes.append(output.calculate_crypto_hash().as_mut());
            bytes.push(':'.try_into().unwrap());
        }
        bytes.push(':'.try_into().unwrap());
        bytes.append(self.signature.clone().as_mut());

        bytes
    }
}

struct UTXOReference {
    tx_hash: Vec<u8>,
    output_index: u32,
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

