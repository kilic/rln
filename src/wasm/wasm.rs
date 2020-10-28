use super::utils::set_panic_hook;
use crate::circuit::poseidon::PoseidonCircuit;
use crate::circuit::rln::{RLNCircuit, RLNInputs};
use crate::poseidon::{Poseidon as PoseidonHasher, PoseidonParams};
use bellman::groth16::{create_proof, prepare_verifying_key, verify_proof};
use bellman::groth16::{create_random_proof, Parameters, Proof};
use bellman::pairing::bn256::{Bn256, Fr};
use bellman::pairing::Engine;
use bellman::{Circuit, ConstraintSystem, SynthesisError};
use std::io::{self, Error, ErrorKind, Read, Write};
use wasm_bindgen::prelude::*;

use crate::merkle::MerkleTree;

use bellman::groth16::generate_random_parameters;
use bellman::pairing::ff::{Field, PrimeField, PrimeFieldRepr};
use bellman::pairing::CurveAffine;
use rand::{Rand, SeedableRng, XorShiftRng};

#[wasm_bindgen]
pub struct RLNWasm {
    circuit_parameters: Parameters<Bn256>,
    circuit_hasher: PoseidonCircuit<Bn256>,
    merkle_depth: usize,
}

#[wasm_bindgen]
pub struct G1Hex {
    x: String,
    y: String,
}

#[wasm_bindgen]
pub struct G2Hex {
    x_c0: String,
    x_c1: String,
    y_c0: String,
    y_c1: String,
}

impl G1Hex {
    pub fn x(&self) -> String {
        self.x.clone()
    }

    pub fn y(&self) -> String {
        self.y.clone()
    }
}

impl G2Hex {
    pub fn x_c0(&self) -> String {
        self.x_c0.clone()
    }

    pub fn x_c1(&self) -> String {
        self.x_c1.clone()
    }

    pub fn y_c0(&self) -> String {
        self.y_c0.clone()
    }

    pub fn y_c1(&self) -> String {
        self.y_c1.clone()
    }
}

#[wasm_bindgen]
pub struct VerifierKey {
    alpha_1: G1Hex,
    beta_2: G2Hex,
    gamma_2: G2Hex,
    delta_2: G2Hex,
    ic_array: Array,
}

use sapling_crypto::bellman::pairing::bn256::{G1Affine, G2Affine};

use js_sys::Array;

impl VerifierKey {
    pub fn some() -> Array {
        let js_array: Array = Array::new();

        js_array.push(&wasm_bindgen::JsValue::from(String::from("xxx")));
        js_array.push(&wasm_bindgen::JsValue::from(String::from("yyy")));
        js_array
    }

    pub fn new(circuit_parameters: Parameters<Bn256>) -> VerifierKey {
        let vk = circuit_parameters.vk;
        let ic_array: Array = Array::new();
        for e_ic in vk.ic.iter() {
            ic_array.push(&wasm_bindgen::JsValue::from(Self::g1_to_js(e_ic.clone())));
        }
        VerifierKey {
            alpha_1: Self::g1_to_js(vk.alpha_g1),
            beta_2: Self::g2_to_js(vk.beta_g2),
            gamma_2: Self::g2_to_js(vk.gamma_g2),
            delta_2: Self::g2_to_js(vk.delta_g2),
            ic_array,
        }
    }

    fn g1_to_js(point: G1Affine) -> G1Hex {
        let mut buf_x: Vec<u8> = vec![];
        let mut buf_y: Vec<u8> = vec![];
        let point_xy = point.into_xy_unchecked();
        point_xy.0.into_repr().write_be(&mut buf_x).unwrap();
        let x = hex::encode(buf_x);
        point_xy.1.into_repr().write_be(&mut buf_y).unwrap();
        let y = hex::encode(buf_y);
        G1Hex { x, y }
    }

    fn g2_to_js(point: G2Affine) -> G2Hex {
        let mut buf_x_c0: Vec<u8> = vec![];
        let mut buf_x_c1: Vec<u8> = vec![];
        let mut buf_y_c0: Vec<u8> = vec![];
        let mut buf_y_c1: Vec<u8> = vec![];

        let point_xy = point.into_xy_unchecked();

        point_xy.0.c0.into_repr().write_be(&mut buf_x_c0).unwrap();
        let x_c0 = hex::encode(buf_x_c0);

        point_xy.0.c1.into_repr().write_be(&mut buf_x_c1).unwrap();
        let x_c1 = hex::encode(buf_x_c1);

        point_xy.1.c0.into_repr().write_be(&mut buf_y_c0).unwrap();
        let y_c0 = hex::encode(buf_y_c0);

        point_xy.1.c1.into_repr().write_be(&mut buf_y_c1).unwrap();
        let y_c1 = hex::encode(buf_y_c1);

        G2Hex {
            x_c0,
            x_c1,
            y_c0,
            y_c1,
        }
    }
}

#[wasm_bindgen]
impl RLNWasm {
    #[wasm_bindgen]
    pub fn new(merkle_depth: usize, raw_circuit_parameters: &[u8]) -> RLNWasm {
        set_panic_hook();
        let circuit_parameters = Parameters::<Bn256>::read(raw_circuit_parameters, true).unwrap();
        let poseidon_params = PoseidonParams::<Bn256>::new(8, 55, 3, None, None, None);
        let circuit_hasher = PoseidonCircuit::new(poseidon_params.clone());
        RLNWasm {
            circuit_parameters,
            circuit_hasher,
            merkle_depth,
        }
    }

    pub fn export_verifier_key(&self) -> VerifierKey {
        VerifierKey::new(self.circuit_parameters.clone())
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
        let proof = create_random_proof(circuit, &self.circuit_parameters, &mut rng)
            .expect("failed to create proof");
        let mut output: Vec<u8> = Vec::new();
        proof.write(&mut output).expect("failed to write proof");
        Ok(output)
    }

    #[wasm_bindgen]
    pub fn verify(&self, raw_proof: &[u8], raw_public_inputs: &[u8]) -> bool {
        let proof = Proof::read(raw_proof).unwrap();
        let public_inputs = RLNInputs::<Bn256>::read_public_inputs(raw_public_inputs)
            .expect("failed to read public inputs");
        let verifing_key = prepare_verifying_key(&self.circuit_parameters.vk);
        let success =
            verify_proof(&verifing_key, &proof, &public_inputs).expect("failed to verify proof");
        success
    }
}

#[cfg(test)]
mod test {

    use wasm_bindgen_test::*;

    use crate::circuit::poseidon::PoseidonCircuit;
    use crate::circuit::rln::{RLNCircuit, RLNInputs};
    use crate::merkle::MerkleTree;
    use crate::poseidon::{Poseidon as PoseidonHasher, PoseidonParams};
    use bellman::groth16::{generate_random_parameters, Parameters, Proof};
    use bellman::pairing::bn256::{Bn256, Fr};
    use bellman::pairing::ff::{Field, PrimeField, PrimeFieldRepr};
    use rand::{Rand, SeedableRng, XorShiftRng};

    fn gen_circuit_parameters(merkle_depth: usize) -> Vec<u8> {
        let mut rng = XorShiftRng::from_seed([0x3dbe6258, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let poseidon_params = PoseidonParams::<Bn256>::new(8, 55, 3, None, None, None);
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

    fn gen_valid_inputs(merkle_depth: usize) -> RLNInputs<Bn256> {
        let mut rng = XorShiftRng::from_seed([0x3dbe6258, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let poseidon_params = PoseidonParams::<Bn256>::new(8, 55, 3, None, None, None);
        let mut hasher = PoseidonHasher::new(poseidon_params.clone());
        let mut membership_tree = MerkleTree::empty(hasher.clone(), merkle_depth);

        let id_key = Fr::rand(&mut rng);
        let id_comm = hasher.hash(vec![id_key.clone()]);

        let id_index = 6;
        membership_tree.update(id_index, id_comm);

        let auth_path = membership_tree.witness(id_index);
        assert!(membership_tree.check_inclusion(auth_path.clone(), id_index, id_key.clone()));

        let epoch = Fr::rand(&mut rng);

        let signal_hash = Fr::rand(&mut rng);
        let share_x = signal_hash.clone();

        let a_0 = id_key.clone();
        let a_1 = hasher.hash(vec![a_0, epoch]);

        let mut share_y = a_1.clone();
        share_y.mul_assign(&share_x);
        share_y.add_assign(&a_0);

        let nullifier = hasher.hash(vec![a_1]);

        let root = membership_tree.root();

        let inputs = RLNInputs::<Bn256> {
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

    #[wasm_bindgen_test]
    fn test_rln_wasm() {
        let merkle_depth = 32usize;
        let raw_circuit_parameters = gen_circuit_parameters(merkle_depth);
        let inputs = gen_valid_inputs(merkle_depth);
        let mut raw_inputs: Vec<u8> = Vec::new();
        inputs.write(&mut raw_inputs);
        use super::RLNWasm;
        let rln_wasm = RLNWasm::new(merkle_depth, raw_circuit_parameters.as_slice());
        let proof = rln_wasm.generate_proof(raw_inputs.as_slice());
        let mut public_inputs: Vec<u8> = Vec::new();
        inputs.write_public_inputs(&mut public_inputs);
        let proof = proof.unwrap();
        assert_eq!(
            rln_wasm.verify(proof.as_slice(), public_inputs.as_slice()),
            true
        );
    }
}
