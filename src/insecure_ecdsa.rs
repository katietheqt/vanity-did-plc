use base64::Engine;
use ethnum::U256;
use sha2::{Digest, Sha256};

use crate::math::{add_mod, Curve, mod_inverse, mul_mod};

pub const SECP256K1: Curve = Curve {
    a: U256::ZERO,
    b: U256::new(7u128),
    p: U256::from_words(0xffffffffffffffffffffffffffffffffu128, 0xfffffffffffffffffffffffefffffc2fu128),
    g: (
        U256::from_words(0x79be667ef9dcbbac55a06295ce870b07u128, 0x29bfcdb2dce28d959f2815b16f81798u128),
        U256::from_words(0x483ada7726a3c4655da4fbfc0e1108a8u128, 0xfd17b448a68554199c47d08ffb10d4b8u128),
    ),
    n: U256::from_words(0xfffffffffffffffffffffffffffffffeu128, 0xbaaedce6af48a03bbfd25e8cd0364141u128),
};

#[derive(Debug, Copy, Clone)]
pub struct ConstantTableEntry {
    pub k_pow_neg1_times_r: U256,
    pub r: U256,
}

// To compute an ECDSA signature in our case (private key = 1) we end up calculating:
//   (k^-1 * (digest + r)) % n = ((k^-1 * digest) + (k^-1 * r)) % n
//
// k, r and n are constants - we choose k^-1 to be successive powers of two from 0 to 256, so that
// the multiply is cheap. This function precomputes the values of `k^-1 * r`.
pub fn generate_ecdsa_constants(curve: Curve) -> Vec<ConstantTableEntry> {
    let mut constants = Vec::with_capacity(256);

    for i in 0..256 {
    // let i = 253; {
        let k_pow_neg1 = U256::ONE << i; // the target value of k^-1
        let k = mod_inverse(k_pow_neg1, curve.n); // computed value of k

        // compute the value of `r`
        let point = curve.scalar_multiply(k, curve.g);
        let r = point.0 % curve.n;
        let k_pow_neg1_times_r = mul_mod(k_pow_neg1, r, curve.n);

        constants.push(ConstantTableEntry {
            k_pow_neg1_times_r,
            r,
        });
    }

    constants
}

pub fn generate_signatures(data_buf: &[u8], constants: &[ConstantTableEntry], curve: Curve) -> Vec<String> {
    let mut signatures = Vec::with_capacity(constants.len());

    let hash = Sha256::digest(data_buf);
    let mut digest = U256::from_be_bytes(hash.as_slice().try_into().unwrap());

    for entry in constants {
        digest %= curve.n;

        // add the constant, modulo `n`
        let mut s = add_mod(digest, entry.k_pow_neg1_times_r, curve.n);
        assert_ne!(s, 0, "signature result is 0");

        if s > curve.n / 2 {
            s = curve.n - s;
        }

        // this shifts `digest` left each loop to do the `(1 << i)` multiply.
        if digest < curve.n - digest {
            digest <<= 1;
        } else {
            digest -= curve.n - digest;
        }

        let mut sig_buf = [0u8; 64];
        sig_buf[0..32].copy_from_slice(&entry.r.to_be_bytes());
        sig_buf[32..64].copy_from_slice(&s.to_be_bytes());

        let sig = base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(sig_buf);
        signatures.push(sig);
    }

    signatures
}