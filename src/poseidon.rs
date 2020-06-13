use blake2::{Blake2s, Digest};

use sapling_crypto::bellman::pairing::ff::{Field, PrimeField, PrimeFieldRepr};
use sapling_crypto::bellman::pairing::Engine;

#[derive(Clone)]
pub struct PoseidonParams<E: Engine> {
    rf: usize,
    rp: usize,
    t: usize,
    round_constants: Vec<E::Fr>,
    mds_matrix: Vec<E::Fr>,
}

#[derive(Clone)]
pub struct Poseidon<E: Engine> {
    state: Vec<E::Fr>,
    round: usize,
    params: PoseidonParams<E>,
}

impl<E: Engine> PoseidonParams<E> {
    pub fn new(
        rf: usize,
        rp: usize,
        t: usize,
        round_constants: Vec<E::Fr>,
        mds_matrix: Vec<E::Fr>,
    ) -> PoseidonParams<E> {
        assert_eq!(rf + rp, round_constants.len());
        PoseidonParams {
            rf,
            rp,
            t,
            round_constants,
            mds_matrix,
        }
    }

    pub fn default() -> PoseidonParams<E> {
        let (t, rf, rp) = (3usize, 8usize, 55usize);
        let seed = b"".to_vec();
        let round_constants =
            PoseidonParams::<E>::generate_constants(b"drlnhdsc", seed.clone(), rf + rp);
        let mds_matrix = PoseidonParams::<E>::generate_mds_matrix(b"drlnhdsm", seed.clone(), t);
        PoseidonParams::new(rf, rp, t, round_constants, mds_matrix)
    }

    pub fn width(&self) -> usize {
        return self.t;
    }

    pub fn partial_round_len(&self) -> usize {
        return self.rp;
    }

    pub fn full_round_half_len(&self) -> usize {
        return self.rf / 2;
    }

    pub fn total_rounds(&self) -> usize {
        return self.rf + self.rp;
    }

    pub fn round_constant(&self, round: usize) -> E::Fr {
        return self.round_constants[round];
    }

    pub fn mds_matrix_row(&self, i: usize) -> Vec<E::Fr> {
        let w = self.width();
        self.mds_matrix[i * w..(i + 1) * w].to_vec()
    }

    pub fn mds_matrix(&self) -> Vec<E::Fr> {
        self.mds_matrix.clone()
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

    fn new_state(&mut self, inputs: Vec<E::Fr>) {
        let t = self.t();
        self.state = inputs.clone();
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

    pub fn hash(&mut self, inputs: Vec<E::Fr>) -> E::Fr {
        self.new_state(inputs);
        loop {
            self.round(self.round);
            self.round += 1;
            if self.round == self.params.total_rounds() {
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
            if round == a3 - 1 {
                self.full_round_last();
            } else {
                self.full_round(round);
            }
        } else {
            panic!("should not be here")
        }
    }

    fn full_round(&mut self, round: usize) {
        self.add_round_constants(round);
        self.apply_quintic_sbox(true);
        self.mul_mds_matrix();
    }

    fn full_round_last(&mut self) {
        let last_round = self.params.total_rounds() - 1;
        self.add_round_constants(last_round);
        self.apply_quintic_sbox(true);
    }

    fn partial_round(&mut self, round: usize) {
        self.add_round_constants(round);
        self.apply_quintic_sbox(false);
        self.mul_mds_matrix();
    }

    fn add_round_constants(&mut self, round: usize) {
        for (_, b) in self.state.iter_mut().enumerate() {
            let c = self.params.round_constants[round];
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
fn test_poseidon_hash() {
    use sapling_crypto::bellman::pairing::bn256;
    use sapling_crypto::bellman::pairing::bn256::{Bn256, Fr};
    let mut hasher = Poseidon::<Bn256>::new(PoseidonParams::default());
    let input1: Vec<Fr> = ["0"].iter().map(|e| Fr::from_str(e).unwrap()).collect();
    let r1: Fr = hasher.hash(input1.to_vec());
    let input2: Vec<Fr> = ["0", "0"]
        .iter()
        .map(|e| Fr::from_str(e).unwrap())
        .collect();
    let r2: Fr = hasher.hash(input2.to_vec());
    // println!("{:?}", r1);
    assert_eq!(r1, r2, "just to see if internal state resets");
}
