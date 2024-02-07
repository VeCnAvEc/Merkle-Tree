use hex;

use tiny_keccak::Hasher;
use crate::abi::{keccak256, make_hash};

struct MerkleTree {
    hashes: Vec<[u8; 32]>,
    transactions: [&'static str; 4],
}

pub mod abi {
    use tiny_keccak::{Hasher, Sha3};

    pub fn encode_packed(args: &[&[u8]]) -> Vec<u8> {
        let mut encoded: Vec<u8> = Vec::new();

        for arg in args {
            encoded.extend_from_slice(arg);
        }

        encoded
    }

    pub fn keccak256(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha3::v256();
        let mut output: [u8; 32] = [0u8; 32];

        hasher.update(data);
        hasher.finalize(&mut output);

        output
    }

    pub fn make_hash(input: String) -> [u8; 32] {
        let encode = encode_packed(&[input.as_bytes()]);

        keccak256(&encode)
    }
}

impl MerkleTree {
    pub fn new() -> Self {
        let mut hashes: Vec<[u8; 32]> = Vec::new();
        let mut transactions = [
            "TX1: Danil -> Ivan",
            "TX2: Ivan -> Danil",
            "TX3: Pavel -> Sveta",
            "TX4: Evgeniy -> Genadiy"
        ];

        for transaction in 0..transactions.len() {
            hashes.push(abi::make_hash(transactions[transaction].to_string()));
        }

        let mut count = transactions.len();
        let mut offset = 0;

        while count > 0 {
            for i in (0..count).step_by(2) {
                if count - 1 == 0 {
                    break;
                }
                let encode = abi::encode_packed(&[&hashes[offset + i], &hashes[offset + i + 1]]);

                hashes.push(keccak256(
                    &encode
                ));
            }

            offset += count;
            count /= 2;
        }

        MerkleTree {
            hashes,
            transactions
        }
    }

    pub fn verify(&self, transaction: String, mut index: usize, root_hash: &[u8; 32], proof: Vec<[u8; 32]>) -> bool {
        let mut hash = make_hash(transaction);

        for i in 0..proof.len() {
            let element = proof[i];
            if index % 2 == 0 {
                let encode = abi::encode_packed(&[&hash, &element]);
                hash = keccak256(&encode);
            } else {
                let encode = abi::encode_packed(&[&element, &hash]);
                hash = keccak256(&encode);
            }

            index /= 2;
        }

        return hex::encode(hash) == hex::encode(root_hash);
    }
}

fn main() {
    let merkle_tree = MerkleTree::new();

    // Test 1
    let index = 2;
    let tx = merkle_tree.transactions[index];
    let root_hash = merkle_tree.hashes[merkle_tree.hashes.len() - 1];
    let proof = vec![merkle_tree.hashes[3], merkle_tree.hashes[4]];

    // Output true
    println!("{}", merkle_tree.verify(tx.to_string(), index, &root_hash, proof));

    // Test 2
    let index_2 = 3;
    let tx_2 = merkle_tree.transactions[index_2];
    let proof_2 = vec![merkle_tree.hashes[2], merkle_tree.hashes[4]];

    // Output true
    println!("{}", merkle_tree.verify(tx_2.to_string(), index_2, &root_hash, proof_2));

    // Test 3
    let index_3 = 2;
    let tx_3 = merkle_tree.transactions[index_3];
    let root_hash_3 = merkle_tree.hashes[merkle_tree.hashes.len() - 2];
    let proof_3 = vec![merkle_tree.hashes[3], merkle_tree.hashes[4]];

    // Output false
    println!("{}", merkle_tree.verify(tx_3.to_string(), index_3, &root_hash_3, proof_3));

    // Test 4
    let index_4 = 2;
    let tx_4 = merkle_tree.transactions[index_4];
    let proof_4 = vec![merkle_tree.hashes[2], merkle_tree.hashes[4]];

    // Output false
    println!("{}", merkle_tree.verify(tx_4.to_string(), index_4, &root_hash, proof_4));
}