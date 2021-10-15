use bellman::pairing::ff::{Field, PrimeField, PrimeFieldRepr, ScalarEngine};
use bellman::pairing::Engine;
use digest::{FixedOutput, VariableOutput, XofReader};
use num_bigint::BigUint;
use num_traits::{Num, One, Zero};
use sha2::{Digest, Sha256};
use std::convert::TryInto;
use std::str::EncodeUtf16;

const PREFIX_RLN_HASH_TO_FIELD: &[u8; 17] = b"rln_hash_to_field";
const PREFIX_RLN_HASH_TO_FIELD_LO: &[u8; 20] = b"rln_hash_to_field_lo";
const PREFIX_RLN_HASH_TO_FIELD_HI: &[u8; 20] = b"rln_hash_to_field_hi";

pub fn hash_to_field<E: Engine>(data: &[u8]) -> <E as ScalarEngine>::Fr {
    let mut hasher = Sha256::new();
    hasher.update(PREFIX_RLN_HASH_TO_FIELD);
    hasher.update(data);

    let mut hasher_to_lo = hasher.clone();
    let mut hasher_to_hi = hasher.clone();

    hasher_to_lo.update(PREFIX_RLN_HASH_TO_FIELD_LO);
    let result_1: [u8; 32] = hasher_to_lo.finalize_fixed().as_slice().try_into().unwrap();

    hasher_to_hi.update(PREFIX_RLN_HASH_TO_FIELD_HI);
    let result_2: [u8; 32] = hasher_to_hi.finalize_fixed().as_slice().try_into().unwrap();

    let lo = &BigUint::from_bytes_le(&result_1[..]);
    let hi = &BigUint::from_bytes_le(&result_2[..]);

    // FIX: use const R size
    let combined: BigUint = lo + hi * (BigUint::from(1usize) << 256);

    big_to_fr::<E>(combined)
}

fn big_modulus<E: Engine>() -> BigUint {
    let modulus = E::Fr::char();
    let mut buf: Vec<u8> = Vec::new();
    modulus.write_le(&mut buf).unwrap();
    let modulus = BigUint::from_bytes_le(&buf[..]);
    modulus
}

fn big_to_fr<E: Engine>(e: BigUint) -> E::Fr {
    let e = e % big_modulus::<E>();
    let e = e.to_bytes_le();
    let mut buf = <E::Fr as PrimeField>::Repr::default();
    buf.read_le(&e[..]).unwrap();
    E::Fr::from_repr(buf).unwrap()
}
