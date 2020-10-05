use crate::circuit::poseidon::PoseidonCircuit;
use crate::circuit::rln::{RLNCircuit, RLNInputs};
use crate::merkle::MerkleTree;
use crate::poseidon::{Poseidon as PoseidonHasher, PoseidonParams};
use rand::{Rand, SeedableRng, XorShiftRng};
use sapling_crypto::bellman::groth16::*;
use sapling_crypto::bellman::pairing::ff::{Field, PrimeField, PrimeFieldRepr};
use sapling_crypto::bellman::pairing::Engine;
use sapling_crypto::bellman::Circuit;
use sapling_crypto::circuit::test::TestConstraintSystem;
use std::error::Error;
use std::thread::sleep;
use std::time::{Duration, Instant};

pub struct BenchResult {
    pub number_of_constaints: usize,
    pub prover_key_size: usize,
    pub prover_time: f64,
}

impl BenchResult {
    pub fn new() -> BenchResult {
        BenchResult {
            number_of_constaints: 0,
            prover_key_size: 0,
            prover_time: 0f64,
        }
    }

    pub fn print(&self) {
        println!("number of constraints\n{}", self.number_of_constaints);
        println!("prover key size\n{}", self.prover_key_size);
        println!("prover time\n{}", self.prover_time);
    }
}

pub fn run_rln_bench<E: Engine>(
    merkle_depth: usize,
    poseidon_params: PoseidonParams<E>,
) -> BenchResult {
    RLNTest::new(merkle_depth, poseidon_params).run()
}

pub struct RLNTest<E>
where
    E: Engine,
{
    merkle_depth: usize,
    poseidon_params: PoseidonParams<E>,
}

impl<E> RLNTest<E>
where
    E: Engine,
{
    pub fn new(merkle_depth: usize, poseidon_params: PoseidonParams<E>) -> RLNTest<E> {
        RLNTest::<E> {
            poseidon_params,
            merkle_depth,
        }
    }

    fn inputs(&self) -> RLNInputs<E> {
        let mut rng = XorShiftRng::from_seed([0x3dbe6258, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let mut hasher = PoseidonHasher::new(self.poseidon_params.clone());
        // Initialize empty merkle tree
        let merkle_depth = self.merkle_depth;
        let mut membership_tree = MerkleTree::empty(hasher.clone(), merkle_depth);

        // A. setup an identity

        let id_key = E::Fr::rand(&mut rng);
        let id_comm = hasher.hash(vec![id_key.clone()]);

        // B. insert to the membership tree

        let id_index = 6; // any number below 2^depth will work
        membership_tree.update(id_index, id_comm);

        // C.1 get membership witness

        let auth_path = membership_tree.witness(id_index);
        assert!(membership_tree.check_inclusion(auth_path.clone(), id_index, id_key.clone()));

        // C.2 prepare sss

        // get current epoch
        let epoch = E::Fr::rand(&mut rng);

        let signal_hash = E::Fr::rand(&mut rng);
        // evaluation point is the signal_hash
        let share_x = signal_hash.clone();

        // calculate current line equation
        let a_0 = id_key.clone();
        let a_1 = hasher.hash(vec![a_0, epoch]);

        // evaluate line equation
        let mut share_y = a_1.clone();
        share_y.mul_assign(&share_x);
        share_y.add_assign(&a_0);

        // calculate nullfier
        let nullifier = hasher.hash(vec![a_1]);

        // compose the circuit

        let inputs = RLNInputs::<E> {
            share_x: Some(share_x),
            share_y: Some(share_y),
            epoch: Some(epoch),
            nullifier: Some(nullifier),
            root: Some(membership_tree.root()),
            id_key: Some(id_key),
            auth_path: auth_path.into_iter().map(|w| Some(w)).collect(),
        };

        inputs
    }

    fn empty_inputs(&self) -> RLNInputs<E> {
        RLNInputs::<E> {
            share_x: None,
            share_y: None,
            epoch: None,
            nullifier: None,
            root: None,
            id_key: None,
            auth_path: vec![None; self.merkle_depth],
        }
    }

    pub fn run(&self) -> BenchResult {
        let mut rng = XorShiftRng::from_seed([0x3dbe6258, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let hasher = PoseidonCircuit::new(self.poseidon_params.clone());
        let inputs = self.inputs();
        let circuit = RLNCircuit::<E> {
            inputs: inputs.clone(),
            hasher: hasher.clone(),
        };

        let mut result = BenchResult::new();

        let mut cs = TestConstraintSystem::<E>::new();
        {
            let circuit = circuit.clone();
            circuit.synthesize(&mut cs).unwrap();
            let unsatisfied = cs.which_is_unsatisfied();
            if unsatisfied.is_some() {
                panic!("unsatisfied\n{}", unsatisfied.unwrap());
            }
            let unconstrained = cs.find_unconstrained();
            if !unconstrained.is_empty() {
                panic!("unconstrained\n{}", unconstrained);
            }
            assert!(cs.is_satisfied());
            result.number_of_constaints = cs.num_constraints();
        }

        {
            let parameters = {
                let inputs = self.empty_inputs();
                let circuit = RLNCircuit::<E> {
                    inputs,
                    hasher: hasher.clone(),
                };
                let parameters = generate_random_parameters(circuit, &mut rng).unwrap();
                parameters
            };

            let mut v = vec![];
            parameters.write(&mut v).unwrap();

            result.prover_key_size = v.len();

            let now = Instant::now();
            let proof = create_random_proof(circuit, &parameters, &mut rng).unwrap();

            result.prover_time = now.elapsed().as_millis() as f64 / 1000.0;

            let verifing_key = prepare_verifying_key(&parameters.vk);
            assert!(verify_proof(&verifing_key, &proof, &inputs.public_inputs()).unwrap());
        }

        result
    }
}
