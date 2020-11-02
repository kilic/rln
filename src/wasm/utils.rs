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

use js_sys::Array;

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

pub fn g1_to_hex(point: G1Affine) -> G1Hex {
    let mut buf_x: Vec<u8> = vec![];
    let mut buf_y: Vec<u8> = vec![];
    let point_xy = point.into_xy_unchecked();
    point_xy.0.into_repr().write_be(&mut buf_x).unwrap();
    let x = hex::encode(buf_x);
    point_xy.1.into_repr().write_be(&mut buf_y).unwrap();
    let y = hex::encode(buf_y);
    G1Hex { x, y }
}

pub fn g2_to_hex(point: G2Affine) -> G2Hex {
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
