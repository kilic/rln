use bellman::groth16::Proof;
use bellman::pairing::ff::{Field, PrimeField, PrimeFieldRepr, ScalarEngine};
use bellman::pairing::{CurveAffine, EncodedPoint, Engine};
use byteorder::{LittleEndian, ReadBytesExt};
use std::io::{self, Error, ErrorKind, Read, Write};

use crate::hash_to_field::hash_to_field;

pub fn read_signal_hash<R: Read, E: Engine>(mut reader: R) -> io::Result<E::Fr> {
    let n = reader.read_u64::<LittleEndian>()?;
    let mut buf: Vec<u8> = vec![0; n as usize];
    reader.read(&mut buf[..])?;

    Ok(hash_to_field::<E>(&buf[..]))
}

pub fn read_fr<R: Read, E: Engine>(mut reader: R, n: usize) -> io::Result<Vec<E::Fr>> {
    let mut out: Vec<E::Fr> = Vec::new();
    let mut buf = <E::Fr as PrimeField>::Repr::default();
    for _ in 0..n {
        buf.read_le(&mut reader)?;
        let input =
            E::Fr::from_repr(buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        out.push(input);
    }
    Ok(out)
}

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
