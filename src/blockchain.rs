mod tx;
mod block;
mod utxo;

use rust_decimal::Decimal;
use rust_decimal::prelude::Zero;
use std::collections::{HashMap, HashSet};
use std::mem;
use std::rc::Rc;

use crate::blockchain::block::Block;
use crate::blockchain::tx::Tx;
use crate::blockchain::utxo::{UTXOData, UTXOReference};
use crate::crypto::signature::{K256PrivateSignatureKey, K256PublicSignatureKey};

struct Blockchain {
    blocks: Vec<Block>,
    tx_hash_to_tx: HashMap<[u8; 32], Rc<Tx>>,
    mempool: Vec<Tx>,
}

impl Blockchain {
    fn new(genesis_transactions: Vec<Tx>, author_pubkey: K256PublicSignatureKey, author_private_key: K256PrivateSignatureKey) -> Blockchain {
        let genesis_block = Block::mine(0, author_pubkey, author_private_key, genesis_transactions, [0u8; 32]);
        let tx_hash_to_tx = genesis_block
            .txs
            .iter()
            .map(|tx| (tx.hash, Rc::clone(tx)))
            .collect::<HashMap<[u8; 32], Rc<Tx>>>();
        Blockchain {
            blocks: vec![genesis_block],
            tx_hash_to_tx,
            mempool: vec![],
        }
    }

    fn get_balance(&self, pubkey: [u8; 33]) -> Decimal {
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

    fn get_available_outputs(&self, source_pubkey: [u8; 33]) -> Vec<UTXOReference> {
        let mut outputs = self.blocks
            .iter()
            .fold(HashSet::new(), |mut outputs, block| {
                block.txs.iter().for_each(|tx| {
                    for input in &tx.inputs {
                        outputs.remove(input);
                    }

                    tx.outputs.iter()
                        .filter(|output| output.pubkey == source_pubkey)
                        .enumerate()
                        .for_each(|(i, output)| {
                        outputs.insert(UTXOReference {
                            tx_hash: tx.hash,
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
        destination_pubkey: [u8; 33],
        source_private_key: K256PrivateSignatureKey,
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

        Ok(Tx::new(tx_inputs, tx_outputs, &source_private_key).unwrap())
    }

    fn create_tx_in_mempool(
        &mut self,
        source_public_key: [u8; 33],
        source_private_key: K256PrivateSignatureKey,
        amount: Decimal,
        destination_pubkey: [u8; 33],
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

    fn mine_next_block(&mut self, author_pubkey: K256PublicSignatureKey, author_private_key: K256PrivateSignatureKey) {
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
            .map(|tx| (tx.hash, Rc::clone(tx)))
        {
            self.tx_hash_to_tx.insert(hash, tx);
        }

        self.blocks.push(new_block);
    }
}