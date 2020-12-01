use bellman::groth16::Proof;
// use bellman::pairing::bn256::{Bn256, G1Affine, G2Affine};
use bellman::pairing::ff::{Field, PrimeField, PrimeFieldRepr};
use bellman::pairing::{CurveAffine, EncodedPoint, Engine};

use rand::{Rand, SeedableRng, XorShiftRng};
use std::io::{self, Error, ErrorKind, Read, Write};

pub fn write_uncompressed_proof<W: Write, E: Engine>(
    proof: Proof<E>,
    mut writer: W,
) -> io::Result<()> {
    writer.write_all(proof.a.into_uncompressed().as_ref())?;
    writer.write_all(proof.b.into_uncompressed().as_ref())?;
    writer.write_all(proof.c.into_uncompressed().as_ref())?;
    Ok(())
}

pub fn read_uncompressed_proof<R: Read, E: Engine>(mut reader: R) -> io::Result<Proof<E>> {
    let mut g1_repr = <E::G1Affine as CurveAffine>::Uncompressed::empty();
    let mut g2_repr = <E::G2Affine as CurveAffine>::Uncompressed::empty();

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
