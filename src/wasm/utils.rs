pub fn set_panic_hook() {
    // When the `console_error_panic_hook` feature is enabled, we can call the
    // `set_panic_hook` function at least once during initialization, and then
    // we will get better error messages if our code ever panics.
    //
    // For more details see
    // https://github.com/rustwasm/console_error_panic_hook#readme
    // #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

use bellman::groth16::Proof;
use bellman::pairing::bn256::{Bn256, G1Affine, G2Affine};
use bellman::pairing::ff::{Field, PrimeField, PrimeFieldRepr};
use bellman::pairing::{CurveAffine, EncodedPoint, Engine};

use rand::{Rand, SeedableRng, XorShiftRng};
use std::io::{self, Error, ErrorKind, Read, Write};
use wasm_bindgen::prelude::*;

pub fn write_uncompressed_proof<W: Write>(proof: Proof<Bn256>, mut writer: W) -> io::Result<()> {
    writer.write_all(proof.a.into_uncompressed().as_ref())?;
    writer.write_all(proof.b.into_uncompressed().as_ref())?;
    writer.write_all(proof.c.into_uncompressed().as_ref())?;

    Ok(())
}

pub fn read_uncompressed_proof<R: Read>(mut reader: R) -> io::Result<Proof<Bn256>> {
    let mut g1_repr = <G1Affine as CurveAffine>::Uncompressed::empty();
    let mut g2_repr = <G2Affine as CurveAffine>::Uncompressed::empty();

    reader.read_exact(g1_repr.as_mut())?;
    let a = g1_repr
        .into_affine()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
        .and_then(|e| {
            if e.is_zero() {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "point at infinity",
                ))
            } else {
                Ok(e)
            }
        })?;

    reader.read_exact(g2_repr.as_mut())?;
    let b = g2_repr
        .into_affine()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
        .and_then(|e| {
            if e.is_zero() {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "point at infinity",
                ))
            } else {
                Ok(e)
            }
        })?;

    reader.read_exact(g1_repr.as_mut())?;
    let c = g1_repr
        .into_affine()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
        .and_then(|e| {
            if e.is_zero() {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "point at infinity",
                ))
            } else {
                Ok(e)
            }
        })?;

    Ok(Proof { a, b, c })
}
