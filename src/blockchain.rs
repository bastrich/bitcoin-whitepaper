mod tx;
mod block;
mod utxo;

use rust_decimal::Decimal;
use rust_decimal::prelude::Zero;
use std::collections::{HashMap, HashSet, VecDeque};
use std::mem;
use std::rc::{Rc, Weak};
use itertools::Itertools;
use min_heap::MinHeap;
use crate::blockchain::block::Block;
use crate::blockchain::tx::Tx;
use crate::blockchain::utxo::{UTXOData, UTXOReference};
use crate::crypto::signature::{K256PrivateSignatureKey, K256PublicSignatureKey, PrivateSignatureKey, PublicSignatureKey};

struct Blockchain {
    blocks: Vec<Block>,
    available_outputs: HashMap<[u8; 33], MinHeap<UTXOReference>>,
    mempool: Vec<Tx>,
}

impl Blockchain {
    fn new(genesis_transactions: Vec<Tx>, author_private_key: K256PrivateSignatureKey) -> Result<Blockchain, String> {
        let genesis_block = Block::mine(0, &author_private_key, genesis_transactions, [0u8; 32])?;
        let available_outputs = genesis_block
            .txs
            .iter()
            .flat_map(|tx|
                tx.outputs.iter()
                    .enumerate()
                    .map(|(i, output)| UTXOReference {
                        tx_hash: tx.hash,
                        output_index: i as u32,
                        data: Rc::downgrade(&output)
                    })
            )
            .map(|output: UTXOReference| (output.data.upgrade().unwrap().pubkey, output))
            .fold(HashMap::new(), |mut acc, (k, v)| {
                acc.entry(k).or_insert_with(MinHeap::new).push(v);
                acc
            });

        Ok(Blockchain {
            blocks: vec![genesis_block],
            available_outputs,
            mempool: vec![],
        })
    }

    fn get_balance(&self, pubkey: [u8; 33]) -> Decimal {
        let available_outputs =  self.available_outputs.get(&pubkey).unwrap();
        available_outputs.iter().map(|output| output.data.upgrade().unwrap().amount).sum()
    }

    fn build_tx(
        &mut self,
        amount: Decimal,
        fee: Decimal,
        destination_pubkey: [u8; 33],
        source_private_key: K256PrivateSignatureKey,
    ) -> Result<Tx, &str> {
        let mut collected_input = Decimal::zero();
        let mut tx_inputs = vec![];

        let available_outputs =  self.available_outputs.get_mut(&source_private_key.get_public_key().to_bytes()).unwrap();

        while collected_input < amount + fee {
            let output = available_outputs.pop().ok_or_else(|| "Not enough balance")?;
            collected_input += output.data.upgrade().unwrap().amount;
            tx_inputs.push(output);
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

        Ok(Tx::new(tx_inputs, tx_outputs, &source_private_key).unwrap())
    }

    fn create_tx_in_mempool(
        &mut self,
        source_public_key: [u8; 33],
        source_private_key: K256PrivateSignatureKey,
        amount: Decimal,
        destination_pubkey: [u8; 33],
    ) -> Result<(), &str> {
        let tx = self.build_tx(
            amount,
            Decimal::try_from("1.00").unwrap(),
            destination_pubkey,
            source_private_key
        ).unwrap();
        self.mempool.push(tx);
        Ok(())
    }

    fn mine_next_block(&mut self, author_private_key: &K256PrivateSignatureKey) -> Result<(), String> {
        if self.mempool.is_empty() {
            return Ok(());
        }

        let new_block = Block::mine(
            self.blocks.len() as u64,
            &author_private_key,
            mem::take(&mut self.mempool),
            self.blocks.last().unwrap().hash.clone(),
        )?;

        new_block.txs.iter()
            .flat_map(|tx|
                tx.outputs.iter()
                    .enumerate()
                    .map(|(i, output)| UTXOReference {
                        tx_hash: tx.hash,
                        output_index: i as u32,
                        data: Rc::downgrade(&output)
                    })
            )
            .for_each(|utxo_reference| {
                self.available_outputs
                    .entry(utxo_reference.data.upgrade().unwrap().pubkey)
                    .or_insert_with(MinHeap::new)
                    .push(utxo_reference)
            });

        self.blocks.push(new_block);

        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blockchain() {

    }
}