use blake2::{Blake2s, Digest};

use sapling_crypto::bellman::pairing::ff::{Field, PrimeField, PrimeFieldRepr};
use sapling_crypto::bellman::pairing::Engine;

pub struct PoseidonParams<E: Engine> {
  rf: usize,
  rp: usize,
  t: usize,
  round_constants: Vec<E::Fr>,
  mds_matrix: Vec<E::Fr>,
}

impl<E: Engine> PoseidonParams<E> {
  pub fn new(rf: usize, rp: usize, t: usize, round_constants: Vec<E::Fr>, mds_matrix: Vec<E::Fr>) -> PoseidonParams<E> {
    assert_eq!((rf + rp) * t, round_constants.len());
    PoseidonParams {
      rf,
      rp,
      t,
      round_constants,
      mds_matrix,
    }
  }
  pub fn t(&self) -> usize {
    return self.t;
  }

  pub fn width(&self) -> usize {
    return self.t;
  }

  pub fn partial_round_len(&self) -> usize {
    return self.rp;
  }

  pub fn full_round_len(&self) -> usize {
    return self.rf + self.rp;
  }

  pub fn full_round_half_len(&self) -> usize {
    return self.rf / 2;
  }

  pub fn total_rounds(&self) -> usize {
    return self.rf + self.rp;
  }

  pub fn round_constant(&self, round: usize, block: usize) -> E::Fr {
    let w = self.t();
    return self.round_constants[round * w + block];
  }

  pub fn mds_matrix_row(&self, i: usize) -> Vec<E::Fr> {
    let t = self.t();
    let mut row: Vec<E::Fr> = Vec::with_capacity(t);
    for j in i * t..(i + 1) * t {
      row.push(self.mds_matrix[j]);
    }
    row
  }

  pub fn generate_mds_matrix(persona: &[u8; 8], seed: Vec<u8>, t: usize) -> Vec<E::Fr> {
    let v: Vec<E::Fr> = PoseidonParams::<E>::generate_constants(persona, seed, t * 2);
    let mut matrix: Vec<E::Fr> = Vec::with_capacity(t * t);
    for i in 0..t {
      for j in 0..t {
        let mut tmp = v[i];
        tmp.add_assign(&v[t + j]);
        let entry = tmp.inverse().unwrap();
        matrix.insert((i * t) + j, entry);
      }
    }
    matrix
  }

  pub fn generate_constants(persona: &[u8; 8], seed: Vec<u8>, len: usize) -> Vec<E::Fr> {
    use hex;
    let mut constants: Vec<E::Fr> = Vec::new();
    let mut source = seed.clone();
    loop {
      let mut hasher = Blake2s::new();
      hasher.input(persona);
      hasher.input(source);
      source = hasher.result().to_vec();
      let mut candidate_repr = <E::Fr as PrimeField>::Repr::default();
      candidate_repr.read_le(&source[..]).unwrap();
      if let Ok(candidate) = E::Fr::from_repr(candidate_repr) {
        constants.push(candidate);
        if constants.len() == len {
          break;
        }
      }
    }
    constants
  }
}

pub struct Poseidon<E: Engine> {
  state: Vec<E::Fr>,
  round: usize,
  params: PoseidonParams<E>,
}

impl<E: Engine> Poseidon<E> {
  pub fn new_with_params(
    rf: usize,
    rp: usize,
    t: usize,
    round_constants: Vec<E::Fr>,
    mds_matrix: Vec<E::Fr>,
  ) -> Poseidon<E> {
    let params = PoseidonParams::new(rf, rp, t, round_constants, mds_matrix);
    Poseidon::new(params)
  }
  pub fn new(params: PoseidonParams<E>) -> Poseidon<E> {
    Poseidon {
      round: 0,
      state: Vec::new(),
      params,
    }
  }

  fn new_state(&mut self, inputs: &[E::Fr]) {
    let t = self.t();
    assert!(inputs.len() < t);
    self.state = inputs.to_vec();
    self.state.resize(t, E::Fr::zero());
  }

  fn clear(&mut self) {
    self.round = 0;
  }

  fn t(&self) -> usize {
    self.params.t
  }

  fn result(&self) -> E::Fr {
    self.state[0]
  }

  pub fn hash(&mut self, inputs: &[E::Fr]) -> E::Fr {
    self.new_state(inputs);
    loop {
      self.round(self.round);
      self.round += 1;
      if self.round == self.params.full_round_len() {
        break;
      }
    }
    let r = self.result();
    self.clear();
    r
  }

  fn round(&mut self, round: usize) {
    let a1 = self.params.full_round_half_len();
    let a2 = a1 + self.params.partial_round_len();
    let a3 = self.params.total_rounds();
    if round < a1 {
      self.full_round(round);
    } else if round >= a1 && round < a2 {
      self.partial_round(round);
    } else if round >= a2 && round < a3 {
      self.full_round(round);
    } else {
      panic!("should not be here")
    }
  }

  fn full_round(&mut self, round: usize) {
    self.add_round_constants(round);
    self.apply_quintic_sbox(true);
    self.mul_mds_matrix();
  }

  fn full_round_no_mds(&mut self, round: usize) {
    self.add_round_constants(round);
    self.apply_quintic_sbox(true);
  }

  fn partial_round(&mut self, round: usize) {
    self.add_round_constants(round);
    self.apply_quintic_sbox(false);
    self.mul_mds_matrix();
  }

  fn add_round_constants(&mut self, round: usize) {
    let w = self.params.t;
    for (j, b) in self.state.iter_mut().enumerate() {
      let c = self.params.round_constants[round * w + j];
      b.add_assign(&c);
    }
  }

  fn apply_quintic_sbox(&mut self, full: bool) {
    for s in self.state.iter_mut() {
      let mut b = s.clone();
      b.square();
      b.square();
      s.mul_assign(&b);
      if !full {
        break;
      }
    }
  }
  fn mul_mds_matrix(&mut self) {
    let w = self.params.t;
    let mut new_state = vec![E::Fr::zero(); w];
    for (i, ns) in new_state.iter_mut().enumerate() {
      for (j, s) in self.state.iter().enumerate() {
        let mut tmp = s.clone();
        tmp.mul_assign(&self.params.mds_matrix[i * w + j]);
        ns.add_assign(&tmp);
      }
    }
    self.state = new_state;
  }
}

#[test]
fn test_poseidon() {
  use sapling_crypto::bellman::pairing::bn256;
  use sapling_crypto::bellman::pairing::bn256::{Bn256, Fr};

  let (t, rf, rp) = (3usize, 8usize, 57usize);

  let mut hasher = Blake2s::new();
  hasher.input(b"rln poseidion t3rf4rp57");
  let seed = hasher.result().to_vec();
  let person_full_round_constant = b"rlnhds_c";
  let person_mds_matrix = b"rlnhds_m";

  let round_constants =
    PoseidonParams::<Bn256>::generate_constants(person_full_round_constant, seed.clone(), (rf + rp) * t);

  let mds_matrix = PoseidonParams::<Bn256>::generate_mds_matrix(person_mds_matrix, seed.clone(), t);

  let mut hasher = Poseidon::<Bn256>::new_with_params(rf, rp, t, round_constants, mds_matrix);

  // let input1 = [Fr::from_str("1").unwrap(), Fr::from_str("2").unwrap()];
  let input1 = [Fr::zero()];
  let r1: Fr = hasher.hash(&input1);
  let input2 = [Fr::zero(), Fr::zero()];
  let r2: Fr = hasher.hash(&input2);
  assert_eq!(r1, r2, "just to see if internal state resets");
}
