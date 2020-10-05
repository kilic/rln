use crate::poseidon::{Poseidon as Hasher, PoseidonParams};
use sapling_crypto::bellman::pairing::ff::{Field, PrimeField, PrimeFieldRepr};
use sapling_crypto::bellman::pairing::Engine;
use std::collections::HashMap;

pub struct MerkleTree<E>
where
    E: Engine,
{
    pub hasher: Hasher<E>,
    zero: Vec<E::Fr>,
    depth: usize,
    nodes: HashMap<(usize, usize), E::Fr>,
}

impl<E> MerkleTree<E>
where
    E: Engine,
{
    pub fn empty(mut hasher: Hasher<E>, depth: usize) -> Self {
        let mut zero: Vec<E::Fr> = Vec::with_capacity(depth + 1);
        zero.push(E::Fr::from_str("0").unwrap());
        for i in 0..depth {
            zero.push(hasher.hash([zero[i]; 2].to_vec()));
        }
        zero.reverse();
        MerkleTree {
            hasher: hasher,
            zero: zero.clone(),
            depth: depth,
            nodes: HashMap::new(),
        }
    }

    fn get_node(&self, depth: usize, index: usize) -> E::Fr {
        *self
            .nodes
            .get(&(depth, index))
            .unwrap_or_else(|| &self.zero[depth])
    }

    fn hash_couple(&mut self, depth: usize, index: usize) -> E::Fr {
        let b = index & !1;
        self.hasher
            .hash([self.get_node(depth, b), self.get_node(depth, b + 1)].to_vec())
    }

    fn recalculate_from(&mut self, leaf_index: usize) {
        let mut i = leaf_index;
        let mut depth = self.depth;
        loop {
            let h = self.hash_couple(depth, i);
            i >>= 1;
            depth -= 1;
            self.nodes.insert((depth, i), h);
            if depth == 0 {
                break;
            }
        }
        assert_eq!(depth, 0);
        assert_eq!(i, 0);
    }

    pub fn insert(&mut self, leaf_index: usize, new: E::Fr, old: Option<E::Fr>) {
        let d = self.depth;
        {
            if old.is_some() {
                let old = old.unwrap();
                let t = self.get_node(d, leaf_index);
                if t.is_zero() {
                    assert!(old.is_zero());
                } else {
                    assert!(t.eq(&self.hasher.hash(vec![old])));
                }
            }
        };
        let leaf = self.hasher.hash(vec![new]);
        self.update(leaf_index, leaf);
    }

    pub fn update(&mut self, leaf_index: usize, leaf: E::Fr) {
        self.nodes.insert((self.depth, leaf_index), leaf);
        self.recalculate_from(leaf_index);
    }

    pub fn root(&self) -> E::Fr {
        return self.get_node(0, 0);
    }

    pub fn witness(&mut self, leaf_index: usize) -> Vec<(E::Fr, bool)> {
        let mut witness = Vec::<(E::Fr, bool)>::with_capacity(self.depth);
        let mut i = leaf_index;
        let mut depth = self.depth;
        loop {
            i ^= 1;
            witness.push((self.get_node(depth, i), (i & 1 == 1)));
            i >>= 1;
            depth -= 1;
            if depth == 0 {
                break;
            }
        }
        assert_eq!(i, 0);
        witness
    }

    pub fn check_inclusion(
        &mut self,
        witness: Vec<(E::Fr, bool)>,
        leaf_index: usize,
        data: E::Fr,
    ) -> bool {
        let mut acc = self.hasher.hash(vec![data]);
        {
            assert!(self.get_node(self.depth, leaf_index).eq(&acc));
        }
        for w in witness.into_iter() {
            if w.1 {
                acc = self.hasher.hash(vec![acc, w.0]);
            } else {
                acc = self.hasher.hash(vec![w.0, acc]);
            }
        }
        acc.eq(&self.root())
    }
}

#[test]
fn test_merkle_set() {
    let zero = Some(Fr::zero());
    let data: Vec<Fr> = (0..8)
        .map(|s| Fr::from_str(&format!("{}", s)).unwrap())
        .collect();
    use sapling_crypto::bellman::pairing::bn256::{Bn256, Fr, FrRepr};
    let params = PoseidonParams::<Bn256>::new(8, 55, 3, None, None, None);
    let hasher = Hasher::new(params);
    let mut set = MerkleTree::empty(hasher, 3);
    let leaf_index = 6;
    set.insert(leaf_index, data[0], zero);
    let witness = set.witness(leaf_index);
    assert!(set.check_inclusion(witness, leaf_index, data[0]));
}

#[test]
fn test_merkle_zeros() {
    use sapling_crypto::bellman::pairing::bn256::{Bn256, Fr, FrRepr};
    let params = PoseidonParams::<Bn256>::new(8, 55, 3, None, None, None);
    let hasher = Hasher::new(params);
    let mut set = MerkleTree::empty(hasher, 32);
    set.insert(5, Fr::from_str("1").unwrap(), Some(Fr::zero()));
    println!("{}", set.root());
    set.insert(6, Fr::from_str("2").unwrap(), Some(Fr::zero()));
    println!("{}", set.root());
}
