use super::utils::set_panic_hook;
use crate::circuit::poseidon::PoseidonCircuit;
use crate::circuit::rln::{RLNCircuit, RLNInputs};
use crate::poseidon::{Poseidon as PoseidonHasher, PoseidonParams};
use sapling_crypto::bellman::groth16::{create_proof, prepare_verifying_key, verify_proof};
use sapling_crypto::bellman::groth16::{create_random_proof, Parameters, Proof};
use sapling_crypto::bellman::pairing::bn256::{Bn256, Fr};
use sapling_crypto::bellman::pairing::Engine;
use sapling_crypto::bellman::{Circuit, ConstraintSystem, SynthesisError};
use std::io::{self, Error, ErrorKind, Read, Write};
use wasm_bindgen::prelude::*;

#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
struct RLNWasm {
  circuit_parameters: Parameters<Bn256>,
  circuit_hasher: PoseidonCircuit<Bn256>,
  merkle_depth: usize,
}

#[wasm_bindgen]
impl RLNWasm {
  #[wasm_bindgen]
  pub fn new(merkle_depth: usize, raw_circuit_parameters: &[u8]) -> RLNWasm {
    set_panic_hook();
    let circuit_parameters = Parameters::<Bn256>::read(raw_circuit_parameters, true).unwrap();
    let poseidon_params = PoseidonParams::<Bn256>::default();
    let circuit_hasher = PoseidonCircuit::new(poseidon_params.clone());
    RLNWasm {
      circuit_parameters,
      circuit_hasher,
      merkle_depth,
    }
  }

  #[wasm_bindgen]
  pub fn generate_proof(&self, input: &[u8]) -> Result<Vec<u8>, JsValue> {
    use rand::chacha::ChaChaRng;
    use rand::SeedableRng;
    let mut rng = ChaChaRng::new_unseeded();
    let inputs = RLNInputs::<Bn256>::read(input).expect("failed to read inputs");
    assert_eq!(self.merkle_depth, inputs.merkle_depth());
    let circuit = RLNCircuit {
      inputs: inputs.clone(),
      hasher: self.circuit_hasher.clone(),
    };
    let proof = create_random_proof(circuit, &self.circuit_parameters, &mut rng).expect("failed to create proof");
    let mut output: Vec<u8> = Vec::new();
    proof.write(&mut output).expect("failed to write proof");
    Ok(output)
  }

  #[wasm_bindgen]
  pub fn verify(&self, raw_proof: &[u8], raw_public_inputs: &[u8]) -> bool {
    let proof = Proof::read(raw_proof).unwrap();
    let public_inputs =
      RLNInputs::<Bn256>::read_public_inputs(raw_public_inputs).expect("failed to read public inputs");
    let verifing_key = prepare_verifying_key(&self.circuit_parameters.vk);
    let success = verify_proof(&verifing_key, &proof, &public_inputs).expect("failed to verify proof");
    success
  }
}

#[cfg(test)]
mod test {

  use crate::circuit::poseidon::PoseidonCircuit;
  use crate::circuit::rln::{RLNCircuit, RLNInputs};
  use crate::merkle::MerkleTree;
  use crate::poseidon::{Poseidon as PoseidonHasher, PoseidonParams};
  use rand::{Rand, SeedableRng, XorShiftRng};
  use sapling_crypto::bellman::groth16::{generate_random_parameters, Parameters, Proof};
  use sapling_crypto::bellman::pairing::bn256::{Bn256, Fr};
  use sapling_crypto::bellman::pairing::ff::{Field, PrimeField, PrimeFieldRepr};

  use wasm_bindgen_test::*;

  fn gen_circuit_parameters(merkle_depth: usize) -> Vec<u8> {
    let mut rng = XorShiftRng::from_seed([0x3dbe6258, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
    let poseidon_params = PoseidonParams::<Bn256>::default();
    let inputs = RLNInputs::<Bn256>::empty(merkle_depth);
    let circuit = RLNCircuit::<Bn256> {
      inputs,
      hasher: PoseidonCircuit::new(poseidon_params.clone()),
    };
    let parameters = generate_random_parameters(circuit, &mut rng).unwrap();
    let mut writer: Vec<u8> = Vec::new();
    parameters.write(&mut writer);
    writer
  }

  #[wasm_bindgen_test]
  fn test_rln_wasm() {
    let merkle_depth = 32usize;
    let circuit_parameters = gen_circuit_parameters(merkle_depth);
    //
    // prepare inputs

    let mut rng = XorShiftRng::from_seed([0x3dbe6258, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
    let poseidon_params = PoseidonParams::<Bn256>::default();
    let mut hasher = PoseidonHasher::new(poseidon_params.clone());
    let mut membership_tree = MerkleTree::empty(hasher.clone(), merkle_depth);

    // A. setup an identity

    let id_key = Fr::rand(&mut rng);
    let id_comm = hasher.hash(vec![id_key.clone()]);

    // B. insert to the membership tree

    let id_index = 6; // any number below 2^depth will work
    membership_tree.update(id_index, id_comm);

    // C.1 get membership witness

    let auth_path = membership_tree.witness(id_index);
    assert!(membership_tree.check_inclusion(auth_path.clone(), id_index, id_key.clone()));

    // C.2 prepare sss

    // get current epoch
    let epoch = Fr::rand(&mut rng);

    let signal_hash = Fr::rand(&mut rng);
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

    let root = membership_tree.root();

    //
    // serialize input

    let mut writer: Vec<u8> = Vec::new();
    share_x.into_repr().write_le(&mut writer).unwrap();
    share_y.into_repr().write_le(&mut writer).unwrap();
    epoch.into_repr().write_le(&mut writer).unwrap();
    nullifier.into_repr().write_le(&mut writer).unwrap();
    root.into_repr().write_le(&mut writer).unwrap();
    id_key.into_repr().write_le(&mut writer).unwrap();
    for (e, _) in auth_path.iter() {
      e.into_repr().write_le(&mut writer).unwrap();
    }
    let raw_circuit_parameters = writer.as_slice();

    //
    // call wasm

    use super::RLNWasm;
    // let rlnWasm = RLNWasm::new(merkle_depth, raw_circuit_parameters);
  }
}
