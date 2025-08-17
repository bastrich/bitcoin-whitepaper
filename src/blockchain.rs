use std::hash::Hash;
use rust_decimal::Decimal;
use std::time::UNIX_EPOCH;


use sha2::{Digest, Sha256};

trait CryptoHash {
    fn calculate_crypto_hash(&self) -> Vec<u8> {
        Sha256::digest(self.provide_bytes().as_slice()).to_vec()
    }

    fn provide_bytes(&self) -> Vec<u8>;
}

struct Blockchain {
    genesis_block: LinkedBlock,
}

impl Blockchain {
    fn new() -> Blockchain {

    }
}

struct LinkedBlock {
    prev: Option<Box<LinkedBlock>>,
    value: Block,
    next: Option<Box<LinkedBlock>>,
}

struct Block {
    hash: Vec<u8>,
    txs: Vec<Tx>,
    nonce: u32,
    prev_hash: Vec<u8>,
}

impl Block {
    fn mine(txs: Vec<Tx>, prev_hash: Vec<u8>) -> Block {
        let timestamp = UNIX_EPOCH.elapsed().unwrap().as_millis();
        let target_prefix = b"\x00\x00";

        let (nonce, hash) = (0..=u32::MAX)
            .find_map(|nonce| {
                let mut hasher = Sha256::new();

                hasher.update(b"Block:v1:");
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


        Block {
            hash, txs, nonce, prev_hash
        }
    }
}

struct Tx {
    timestamp: u128,
    input: UTXOReference,
    output: UTXOData,
    signature: Vec<u8>,
}

impl CryptoHash for Tx {
    fn provide_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];

        bytes.append(b"Tx:v1:".to_vec().as_mut());
        bytes.append(self.timestamp.to_le_bytes().to_vec().as_mut());
        bytes.push(':'.try_into().unwrap());
        bytes.append(self.input.calculate_crypto_hash().as_mut());
        bytes.push(':'.try_into().unwrap());
        bytes.append(self.output.calculate_crypto_hash().as_mut());
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

        bytes.append(b"UTXOData:v1:".to_vec().as_mut());
        bytes.append(self.amount.serialize().to_vec().as_mut());
        bytes.push(':'.try_into().unwrap());
        bytes.append(self.pubkey.clone().as_mut());

        bytes
    }
}

