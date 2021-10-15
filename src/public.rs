use crate::circuit::rln::{RLNCircuit, RLNInputs};
use crate::hash_to_field::hash_to_field;
use crate::merkle::MerkleTree;
use crate::poseidon::{Poseidon as PoseidonHasher, PoseidonParams};
use crate::utils::{read_fr, read_signal_hash, read_uncompressed_proof, write_uncompressed_proof};
use crate::{circuit::poseidon::PoseidonCircuit, merkle::IncrementalMerkleTree};
use bellman::groth16::generate_random_parameters;
use bellman::groth16::{create_proof, prepare_verifying_key, verify_proof};
use bellman::groth16::{create_random_proof, Parameters, Proof};
use bellman::pairing::ff::{Field, PrimeField, PrimeFieldRepr, ScalarEngine};
use bellman::pairing::{CurveAffine, EncodedPoint, Engine};
use bellman::{Circuit, ConstraintSystem, SynthesisError};
use byteorder::{LittleEndian, ReadBytesExt};
use rand::{thread_rng, Rand, Rng};
use std::{
    io::{self, Error, ErrorKind, Read, Write},
    ptr::null,
};

// Rate Limit Nullifier

#[derive(Clone)]
pub struct RLNSignal<E>
where
    E: Engine,
{
    pub epoch: E::Fr,
    pub hash: E::Fr,
}

impl<E> RLNSignal<E>
where
    E: Engine,
{
    pub fn read<R: Read>(mut reader: R) -> io::Result<RLNSignal<E>> {
        let mut buf = <E::Fr as PrimeField>::Repr::default();

        buf.read_le(&mut reader)?;
        let epoch =
            E::Fr::from_repr(buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let hash = read_signal_hash::<R, E>(reader)?;

        Ok(RLNSignal { epoch, hash })
    }
}

pub struct RLN<E: Engine> {
    circuit_parameters: Parameters<E>,
    poseidon_params: PoseidonParams<E>,
    tree: IncrementalMerkleTree<E>,
}

impl<E: Engine> RLN<E> {
    fn default_poseidon_params() -> PoseidonParams<E> {
        PoseidonParams::<E>::new(8, 55, 3, None, None, None)
    }

    fn new_circuit(merkle_depth: usize, poseidon_params: PoseidonParams<E>) -> Parameters<E> {
        let mut rng = thread_rng();
        let inputs = RLNInputs::<E>::empty(merkle_depth);
        let circuit = RLNCircuit::<E> {
            inputs,
            hasher: PoseidonCircuit::new(poseidon_params.clone()),
        };
        generate_random_parameters(circuit, &mut rng).unwrap()
    }

    fn new_with_params(
        merkle_depth: usize,
        circuit_parameters: Parameters<E>,
        poseidon_params: PoseidonParams<E>,
    ) -> RLN<E> {
        let hasher = PoseidonHasher::new(poseidon_params.clone());
        let tree = IncrementalMerkleTree::empty(hasher, merkle_depth);
        RLN {
            circuit_parameters,
            poseidon_params,
            tree,
        }
    }

    pub fn new(merkle_depth: usize, poseidon_params: Option<PoseidonParams<E>>) -> RLN<E> {
        let poseidon_params = match poseidon_params {
            Some(params) => params,
            None => Self::default_poseidon_params(),
        };
        let circuit_parameters = Self::new_circuit(merkle_depth, poseidon_params.clone());
        Self::new_with_params(merkle_depth, circuit_parameters, poseidon_params)
    }

    pub fn new_with_raw_params<R: Read>(
        merkle_depth: usize,
        raw_circuit_parameters: R,
        poseidon_params: Option<PoseidonParams<E>>,
    ) -> io::Result<RLN<E>> {
        let circuit_parameters = Parameters::<E>::read(raw_circuit_parameters, true)?;
        let poseidon_params = match poseidon_params {
            Some(params) => params,
            None => Self::default_poseidon_params(),
        };
        Ok(Self::new_with_params(
            merkle_depth,
            circuit_parameters,
            poseidon_params,
        ))
    }

    /// returns current membership root
    /// * `root` is a scalar field element in 32 bytes
    pub fn get_root<W: Write>(&self, mut result_data: W) -> io::Result<()> {
        let root = self.tree.get_root();
        root.into_repr().write_le(&mut result_data)?;
        Ok(())
    }

    /// inserts new member with given public key
    /// * `input_data` is a 32 scalar field element in 32 bytes
    pub fn update_next_member<R: Read>(&mut self, input_data: R) -> io::Result<()> {
        let mut buf = <E::Fr as PrimeField>::Repr::default();
        buf.read_le(input_data)?;
        let leaf =
            E::Fr::from_repr(buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        self.tree.update_next(leaf)?;
        Ok(())
    }

    //// deletes member with given index
    pub fn delete_member(&mut self, index: usize) -> io::Result<()> {
        self.tree.delete(index)?;
        Ok(())
    }

    /// hashes plain text to a field element
    pub fn signal_to_field<R: Read, W: Write>(
        &self,
        input_data: R,
        mut result_data: W,
    ) -> io::Result<()> {
        let result = read_signal_hash::<R, E>(input_data)?;
        result.into_repr().write_le(&mut result_data)?;
        Ok(())
    }

    /// given public inputs and autharization data generates public inputs and proof
    /// * expect `input_data`  serialized as  [ id_key<32> | id_index<8> | epoch<32> | signal_len<8> | signal<var> ]
    /// * `result_data` is proof data serialized as [ proof<256>| root<32>| epoch<32>| share_x<32>| share_y<32>| nullifier<32> ]
    pub fn generate_proof<R: Read, W: Write>(
        &self,
        mut input_data: R,
        mut result_data: W,
    ) -> io::Result<()> {
        let id_key: E::Fr = read_fr::<_, E>(&mut input_data, 1)?[0];
        let id_index = input_data.read_u64::<LittleEndian>()? as usize;

        let signal = RLNSignal::<E>::read(input_data)?;

        use hex;

        let hasher = self.hasher();
        let share_x = signal.hash.clone();

        // line equation
        let a_0 = id_key.clone();
        let a_1: E::Fr = hasher.hash(vec![a_0, signal.epoch]);
        // evaluate line equation
        let mut share_y = a_1.clone();
        share_y.mul_assign(&share_x);
        share_y.add_assign(&a_0);
        let nullifier = hasher.hash(vec![a_1]);

        let root = self.tree.get_root();
        // TODO: check id key here
        let auth_path = self.tree.get_witness(id_index)?;

        let inputs = RLNInputs::<E> {
            share_x: Some(share_x),
            share_y: Some(share_y),
            epoch: Some(signal.epoch),
            nullifier: Some(nullifier),
            root: Some(root),
            id_key: Some(id_key),
            auth_path: auth_path.into_iter().map(|w| Some(w)).collect(),
        };

        let circuit = RLNCircuit {
            inputs: inputs.clone(),
            hasher: PoseidonCircuit::new(self.poseidon_params.clone()),
        };

        let mut rng = thread_rng();
        let proof = create_random_proof(circuit, &self.circuit_parameters, &mut rng).unwrap();
        write_uncompressed_proof(proof.clone(), &mut result_data)?;
        root.into_repr().write_le(&mut result_data)?;
        signal.epoch.into_repr().write_le(&mut result_data)?;
        share_x.into_repr().write_le(&mut result_data)?;
        share_y.into_repr().write_le(&mut result_data)?;
        nullifier.into_repr().write_le(&mut result_data)?;

        Ok(())
    }

    /// given proof and public data verifies the signal
    /// * expect `input_data` is serialized as:
    /// [ proof<256>| root<32>| epoch<32>| share_x<32>| share_y<32>| nullifier<32> | signal_len<8> | signal<var> ]
    pub fn verify<R: Read>(&self, mut input_data: R) -> io::Result<bool> {
        let proof = read_uncompressed_proof(&mut input_data)?;
        let public_inputs = RLNInputs::<E>::read_public_inputs(&mut input_data)?;
        let signal_hash = read_signal_hash::<R, E>(input_data)?;

        if signal_hash != public_inputs[2] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "signal hash mismatch",
            ));
        }

        let verifing_key = prepare_verifying_key(&self.circuit_parameters.vk);
        let success = verify_proof(&verifing_key, &proof, &public_inputs).unwrap();
        Ok(success)
    }

    /// generates public private key pair
    /// * `key_pair_data` is seralized as [ secret<32> | public<32> ]
    pub fn key_gen<W: Write>(&self, mut input_data: W) -> io::Result<()> {
        let mut rng = thread_rng();
        let hasher = self.hasher();
        let secret = E::Fr::rand(&mut rng);
        let public: E::Fr = hasher.hash(vec![secret.clone()]);
        secret.into_repr().write_le(&mut input_data)?;
        public.into_repr().write_le(&mut input_data)?;
        Ok(())
    }

    pub fn export_verifier_key<W: Write>(&self, w: W) -> io::Result<()> {
        self.circuit_parameters.vk.write(w)
    }

    pub fn export_circuit_parameters<W: Write>(&self, w: W) -> io::Result<()> {
        self.circuit_parameters.write(w)
    }

    pub fn hasher(&self) -> PoseidonHasher<E> {
        PoseidonHasher::new(self.poseidon_params.clone())
    }

    pub fn poseidon_params(&self) -> PoseidonParams<E> {
        self.poseidon_params.clone()
    }
}

// #[cfg(test)]
// mod tests {
//     use crate::{circuit::bench, public::RLNSignal};
//     use crate::{poseidon::PoseidonParams, public};
//     use bellman::pairing::bn256::{Bn256, Fr};
//     use rand::{Rand, SeedableRng, XorShiftRng};

//     fn merkle_depth() -> usize {
//         4usize
//     }

//     fn rln_test() -> bench::RLNTest<Bn256> {
//         let merkle_depth = merkle_depth();
//         let poseidon_params = PoseidonParams::<Bn256>::new(8, 55, 3, None, None, None);
//         let rln_test = bench::RLNTest::<Bn256>::new(merkle_depth, Some(poseidon_params));
//         rln_test
//     }

//     #[test]
//     fn test_xxx() {
//         let rln = rln_test();
//         let rln = rln.rln;

//         let input_data: Vec<u8> = vec![1, 2, 3, 4];
//         let n = 4;
//         let mut result_data: Vec<u8> = Vec::new();

//         rln.signal_to_field(&input_data[..], n, &mut result_data)
//             .unwrap();
//     }
// }
