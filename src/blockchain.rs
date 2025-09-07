mod block;
mod tx;
mod utxo;

use crate::blockchain::block::Block;
use crate::blockchain::tx::Tx;
use crate::blockchain::utxo::{UTXOData, UTXOReference};
use crate::crypto::signature::{K256PrivateSignatureKey, K256PublicSignatureKey, PrivateSignatureKey, PublicSignatureKey};
use itertools::Itertools;
use min_heap::MinHeap;
use rust_decimal::Decimal;
use rust_decimal::prelude::Zero;
use std::collections::{HashMap, HashSet, VecDeque};
use std::mem;
use std::rc::{Rc, Weak};

struct Blockchain {
    blocks: Vec<Block>,
    available_outputs: HashMap<[u8; 33], MinHeap<UTXOReference>>,
    mempool: Vec<Tx>,
}

impl Blockchain {
    fn new(genesis_balances: Vec<([u8; 33], Decimal)>, author_private_key: K256PrivateSignatureKey) -> Result<Blockchain, String> {
        let genesis_transaction = Tx::new(
            vec![],
            genesis_balances
                .into_iter()
                .map(|(pubkey, balance)| Rc::new(UTXOData { amount: balance, pubkey }))
                .collect(),
            &author_private_key,
        )
        .map_err(|error| format!("Can´t create genesis transaction: {}", error))?;

        let genesis_block = Block::mine(0, &author_private_key, vec![genesis_transaction], [0u8; 32])?;

        let available_outputs = genesis_block
            .txs
            .iter()
            .flat_map(|tx| {
                tx.outputs.iter().enumerate().map(|(i, output)| UTXOReference {
                    tx_hash: tx.hash,
                    output_index: i as u32,
                    data: Rc::downgrade(&output),
                })
            })
            .try_fold(HashMap::new(), |mut acc, (output)| {
                let pubkey = output
                    .data
                    .upgrade()
                    .ok_or_else(|| "Input reference is expected to refer a valid UTXO data".to_string())?
                    .pubkey;
                acc.entry(pubkey).or_insert_with(MinHeap::new).push(output);
                Ok::<HashMap<[u8; 33], MinHeap<UTXOReference>>, String>(acc)
            })?;

        Ok(Blockchain {
            blocks: vec![genesis_block],
            available_outputs,
            mempool: vec![],
        })
    }

    fn get_balance(&self, pubkey: [u8; 33]) -> Result<Decimal, &str> {
        let available_outputs = self.available_outputs.get(&pubkey).ok_or_else(|| "Address not found")?;
        Ok(
            available_outputs.iter()
                .try_fold(
                    Decimal::zero(),
                    |sum, output| Ok(
                        sum + output.data.upgrade().ok_or_else(|| "Input reference is expected to refer a valid UTXO data")?.amount
                    )
                )?
        )
    }

    fn build_tx(&mut self, amount: Decimal, fee: Decimal, destination_pubkey: [u8; 33], source_private_key: K256PrivateSignatureKey) -> Result<Tx, String> {
        let mut collected_input = Decimal::zero();
        let mut tx_inputs = vec![];

        let available_outputs = self.available_outputs
            .get_mut(&source_private_key.get_public_key().to_bytes())
            .ok_or_else(|| format!("There is no available funds in address {}, or it doesn't exist", &source_private_key.get_public_key()))?;

        while collected_input < amount + fee {
            let output = available_outputs.pop().ok_or_else(|| "Not enough balance")?;
            collected_input += output.data.upgrade().ok_or_else(|| "Input reference is expected to refer a valid UTXO data")?.amount;
            tx_inputs.push(output);
        }

        let mut tx_outputs = vec![Rc::new(UTXOData {
            amount: amount,
            pubkey: destination_pubkey,
        })];
        let exchange = collected_input - amount - fee;
        if exchange > Decimal::zero() {
            tx_outputs.push(Rc::new(UTXOData {
                amount: exchange,
                pubkey: tx_inputs.first().expect("Logic error: ist of inputs can't be empty here").data.upgrade().ok_or_else(|| "Input reference is expected to refer a valid UTXO data")?.pubkey.clone(),
            }));
        }

        Tx::new(tx_inputs, tx_outputs, &source_private_key)
    }

    fn create_tx_in_mempool(
        &mut self,
        source_private_key: K256PrivateSignatureKey,
        amount: Decimal,
        fee: Decimal,
        destination_pubkey: [u8; 33]
    ) -> Result<(), String> {
        let tx = self
            .build_tx(amount, fee, destination_pubkey, source_private_key)?;
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
            self.blocks.last().ok_or_else(|| "Blocks can't be empty, at least genesis block is expected")?.hash.clone(),
        )?;

        new_block
            .txs
            .iter()
            .flat_map(|tx| {
                tx.outputs.iter().enumerate().map(|(i, output)| UTXOReference {
                    tx_hash: tx.hash,
                    output_index: i as u32,
                    data: Rc::downgrade(&output),
                })
            })
            .try_for_each(|utxo_reference| -> Result<(), &str> {
                self.available_outputs
                    .entry(utxo_reference.data.upgrade().ok_or_else(|| "Input reference is expected to refer a valid UTXO data")?.pubkey)
                    .or_insert_with(MinHeap::new)
                    .push(utxo_reference);

                Ok(())
            })?;

        self.blocks.push(new_block);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_new_blockchain() {

    }
}
