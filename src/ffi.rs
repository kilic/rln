use crate::public::RLN;
use bellman::pairing::bn256::Bn256;
use std::slice;

/// Buffer struct is taken from
/// https://github.com/celo-org/celo-threshold-bls-rs/blob/master/crates/threshold-bls-ffi/src/ffi.rs

/// Data structure which is used to store buffers of varying length
#[repr(C)]
#[derive(Clone, Debug, PartialEq)]
pub struct Buffer {
    /// Pointer to the message
    pub ptr: *const u8,
    /// The length of the buffer
    pub len: usize,
}

impl From<&[u8]> for Buffer {
    fn from(src: &[u8]) -> Self {
        Self {
            ptr: &src[0] as *const u8,
            len: src.len(),
        }
    }
}

impl<'a> From<&Buffer> for &'a [u8] {
    fn from(src: &Buffer) -> &'a [u8] {
        unsafe { slice::from_raw_parts(src.ptr, src.len) }
    }
}

#[no_mangle]
pub unsafe extern "C" fn new_circuit_from_params(
    merkle_depth: usize,
    parameters_buffer: *const Buffer,
    ctx: *mut *mut RLN<Bn256>,
) -> bool {
    let buffer = <&[u8]>::from(unsafe { &*parameters_buffer });
    let rln = match RLN::<Bn256>::new_with_raw_params(merkle_depth, buffer, None) {
        Ok(rln) => rln,
        Err(_) => return false,
    };
    *ctx = Box::into_raw(Box::new(rln));
    true
}

#[no_mangle]
pub unsafe extern "C" fn generate_proof(
    ctx: *const RLN<Bn256>,
    input_buffer: *const Buffer,
    proof_buffer: *mut Buffer,
) -> bool {
    let input_data = <&[u8]>::from(unsafe { &*input_buffer });
    let rln = unsafe { &*ctx };
    let proof_data = match rln.generate_proof(input_data) {
        Ok(proof_data) => proof_data,
        Err(_) => return false,
    };
    unsafe { *proof_buffer = Buffer::from(&proof_data[..]) };
    std::mem::forget(proof_data);
    true
}

#[no_mangle]
pub unsafe fn verify(
    ctx: *const RLN<Bn256>,
    proof_buffer: *const Buffer,
    public_inputs_buffer: *const Buffer,
    result_ptr: *mut u32,
) -> bool {
    let proof_data = <&[u8]>::from(unsafe { &*proof_buffer });
    let public_inputs_data = <&[u8]>::from(unsafe { &*public_inputs_buffer });
    let rln = unsafe { &*ctx };
    rln.verify(proof_data, public_inputs_data).unwrap();
    if match rln.verify(proof_data, public_inputs_data) {
        Ok(verified) => verified,
        Err(_) => return false,
    } {
        unsafe { *result_ptr = 0 };
    } else {
        unsafe { *result_ptr = 1 };
    };
    true
}

#[cfg(test)]
mod tests {
    use crate::circuit::bench;
    use crate::poseidon::PoseidonParams;
    use bellman::pairing::bn256::{Bn256, Fr};

    use super::*;
    use hex;
    use std::mem::MaybeUninit;

    #[test]
    fn test_ffi() {
        let merkle_depth = 3usize;
        let poseidon_params = PoseidonParams::<Bn256>::new(8, 55, 3, None, None, None);
        let rln_test = bench::RLNTest::<Bn256>::new(merkle_depth, Some(poseidon_params));

        let mut circuit_parameters: Vec<u8> = Vec::new();
        rln_test
            .export_circuit_parameters(&mut circuit_parameters)
            .unwrap();

        // restore this new curcuit with bindings
        let circuit_parameters_buffer = &Buffer::from(circuit_parameters.as_ref());
        let mut rln_pointer = MaybeUninit::<*mut RLN<Bn256>>::uninit();
        unsafe {
            new_circuit_from_params(
                merkle_depth,
                circuit_parameters_buffer,
                rln_pointer.as_mut_ptr(),
            )
        };

        let rln_pointer = unsafe { &*rln_pointer.assume_init() };

        let mut inputs_data: Vec<u8> = Vec::new();
        let inputs = rln_test.valid_inputs();
        inputs.write(&mut inputs_data).unwrap();
        let inputs_buffer = &Buffer::from(inputs_data.as_ref());

        let mut proof_buffer = MaybeUninit::<Buffer>::uninit();

        let success =
            unsafe { generate_proof(rln_pointer, inputs_buffer, proof_buffer.as_mut_ptr()) };
        assert!(success, "proof generation failed");

        let proof_buffer = unsafe { proof_buffer.assume_init() };

        let mut public_inputs_data: Vec<u8> = Vec::new();
        inputs.write_public_inputs(&mut public_inputs_data).unwrap();
        let public_inputs_buffer = &Buffer::from(public_inputs_data.as_ref());

        let mut result = 0u32;
        let result_ptr = &mut result as *mut u32;

        let success =
            unsafe { verify(rln_pointer, &proof_buffer, public_inputs_buffer, result_ptr) };
        assert!(success, "verification operation failed");
        assert_eq!(0, result);
    }
}
