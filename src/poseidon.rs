use blake2::{Blake2s, Digest};

use sapling_crypto::bellman::pairing::bn256;
use sapling_crypto::bellman::pairing::bn256::{Bn256, Fr};
use sapling_crypto::bellman::pairing::ff::{Field, PrimeField, PrimeFieldRepr};

#[test]
fn test_poseidon() {
  let (t, rf, rp) = (3usize, 8usize, 57usize);
  let mut hasher = Blake2s::new();
  hasher.input(b"rln poseidion t3rf4rp57");
  let seed = hasher.result().to_vec();
  let person_full_round_constant = b"rlnhds01";
  let full_round_constants = PoseidonParams::generate_constants(person_full_round_constant, seed.clone(), rf);
  let person_partial_round_constant = b"rlnhds02";
  let partial_round_constants = PoseidonParams::generate_constants(person_partial_round_constant, seed.clone(), rp);
  let person_mds_matrix = b"rlnhds03";
  let mds_matrix = PoseidonParams::generate_mds_matrix(person_mds_matrix, seed.clone(), t);
  let mut constants: Vec<Fr> = Vec::new();
  for i in 0..rf / 2 {
    constants.push(full_round_constants[i]);
  }
  for i in 0..rp {
    constants.push(partial_round_constants[i]);
  }
  for i in 0..rf / 2 {
    constants.push(full_round_constants[i]);
  }
  let mut hasher = Poseidon::new_with_params(rf, rp, t, constants, mds_matrix);
  let input = [Fr::zero()];
  let r1 = hasher.hash(&input);
  let r2 = hasher.hash(&input);
  assert_eq!(r1, r2, "just to see if internal state resets");
}

struct PoseidonParams {
  rf: usize,
  rp: usize,
  t: usize,
  round_constants: Vec<Fr>,
  mds_matrix: Vec<Fr>,
}

impl PoseidonParams {
  pub fn new(rf: usize, rp: usize, t: usize, round_constants: Vec<Fr>, mds_matrix: Vec<Fr>) -> PoseidonParams {
    assert_eq!(rf + rp, round_constants.len());
    PoseidonParams {
      rf,
      rp,
      t,
      round_constants,
      mds_matrix,
    }
  }
  pub fn generate_mds_matrix(persona: &[u8; 8], seed: Vec<u8>, t: usize) -> Vec<Fr> {
    let mut matrix: Vec<Fr> = Vec::with_capacity(t * t);
    let mut xs: Vec<Fr> = Vec::with_capacity(t);
    let mut ys: Vec<Fr> = Vec::with_capacity(t);
    let mut source = seed.clone();
    loop {
      let mut hasher = Blake2s::new();
      hasher.input(persona);
      hasher.input(source);
      source = hasher.result().to_vec();
      let mut candidate_repr = <bn256::Fr as PrimeField>::Repr::default();
      candidate_repr.read_le(&source[..]).unwrap();
      if let Ok(candidate) = bn256::Fr::from_repr(candidate_repr) {
        xs.push(candidate);
        if xs.len() == t {
          break;
        }
      }
    }
    loop {
      let mut hasher = Blake2s::new();
      hasher.input(persona);
      hasher.input(source);
      source = hasher.result().to_vec();
      let mut candidate_repr = <bn256::Fr as PrimeField>::Repr::default();
      candidate_repr.read_le(&source[..]).unwrap();
      if let Ok(candidate) = bn256::Fr::from_repr(candidate_repr) {
        ys.push(candidate);
        if ys.len() == t {
          break;
        }
      }
    }
    for i in 0..t {
      for j in 0..t {
        let mut tmp = xs[i];
        tmp.add_assign(&ys[j]);
        let entry = tmp.inverse().unwrap();
        matrix.insert((i * t) + j, entry);
      }
    }
    matrix
  }

  fn generate_constants(persona: &[u8; 8], seed: Vec<u8>, len: usize) -> Vec<Fr> {
    let mut constants: Vec<Fr> = Vec::new();
    let mut source = seed.clone();
    loop {
      let mut hasher = Blake2s::new();
      hasher.input(persona);
      hasher.input(source);
      source = hasher.result().to_vec();
      let mut candidate_repr = <bn256::Fr as PrimeField>::Repr::default();
      candidate_repr.read_le(&source[..]).unwrap();
      if let Ok(candidate) = bn256::Fr::from_repr(candidate_repr) {
        constants.push(candidate);
        if constants.len() == len {
          break;
        }
      }
    }
    constants
  }
}

struct Poseidon {
  state: Vec<Fr>,
  round: usize,
  params: PoseidonParams,
}

impl Poseidon {
  pub fn new_with_params(rf: usize, rp: usize, t: usize, round_constants: Vec<Fr>, mds_matrix: Vec<Fr>) -> Poseidon {
    let params = PoseidonParams::new(rf, rp, t, round_constants, mds_matrix);
    Poseidon::new(params)
  }
  pub fn new(params: PoseidonParams) -> Poseidon {
    Poseidon {
      round: 0,
      state: Vec::new(),
      params,
    }
  }

  pub fn hash(&mut self, inputs: &[Fr]) -> Fr {
    self.new_state(inputs);
    while self.round() {}
    self.round = 0;
    self.result()
  }

  fn new_state(&mut self, inputs: &[Fr]) {
    let t = self.t();
    assert!(inputs.len() < t);
    self.state = inputs.to_vec();
    self.state.resize(t, Fr::zero());
  }

  fn t(&self) -> usize {
    self.params.t
  }

  fn result(&self) -> Fr {
    self.state[0]
  }

  fn round(&mut self) -> bool {
    let a1 = self.params.rf / 2;
    let a2 = self.params.rf / 2 + self.params.rp;
    let a3 = self.params.rf + self.params.rp;

    if self.round < a1 {
      self.full_round();
      false
    } else if self.round >= a1 && self.round < a2 {
      self.partial_round();
      false
    } else if self.round >= a2 && self.round < a3 {
      self.full_round();
      false
    } else {
      true
    }
  }

  fn full_round(&mut self) {
    self.add_round_constants();
    self.apply_quintic_sbox();
    self.mul_mds_matrix();
  }

  fn full_round_no_mds(&mut self) {
    self.add_round_constants();
    self.apply_quintic_sbox();
  }

  fn partial_round(&mut self) {
    self.add_round_constants();
    self.apply_quintic_sbox();
    self.mul_mds_matrix();
  }

  fn add_round_constants(&mut self) {
    let w = self.params.t;
    // use zip
    for (j, b) in self.state.iter_mut().enumerate() {
      let c = self.params.round_constants[self.round * w + j];
      b.add_assign(&c);
    }
  }

  fn apply_quintic_sbox(&mut self) {
    for s in self.state.iter_mut() {
      let mut b = s.clone();
      b.square();
      b.square();
      s.mul_assign(&b);
    }
  }

  fn mul_mds_matrix(&mut self) {
    let w = self.params.t;
    let mut new_state = vec![Fr::zero(); w];
    for (i, ns) in new_state.iter_mut().enumerate() {
      // slice and zip
      for (j, s) in self.state.iter().enumerate() {
        let mut tmp = s.clone();
        tmp.mul_assign(&self.params.mds_matrix[i * w + j]);
        ns.add_assign(&tmp);
      }
    }
    self.state = new_state;
  }
}
