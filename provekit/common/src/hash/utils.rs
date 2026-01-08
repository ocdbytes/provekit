use {
    crate::FieldElement,
    ark_ff::{BigInt, PrimeField},
};

pub fn bigint_from_bytes_le<const N: usize>(bytes: &[u8]) -> BigInt<N> {
    // Avoid Vec allocation by using a fixed-size array
    let mut limbs = [0u64; N];
    for (i, chunk) in bytes.chunks_exact(8).enumerate() {
        if i < N {
            limbs[i] = u64::from_le_bytes(chunk.try_into().unwrap());
        }
    }
    BigInt::new(limbs)
}

pub fn field_to_bytes(f: FieldElement) -> [u8; 32] {
    let bigint = f.into_bigint();
    let mut bytes = [0u8; 32];
    for (i, limb) in bigint.0.iter().enumerate() {
        let start = i * 8;
        if start < 32 {
            bytes[start..start + 8].copy_from_slice(&limb.to_le_bytes());
        }
    }
    bytes
}

pub fn bytes_to_field(bytes: [u8; 32]) -> FieldElement {
    FieldElement::new(bigint_from_bytes_le(&bytes))
}

pub fn check_pow_bits(hash: &[u8], bits: f64) -> bool {
    // Count leading zero bits
    let threshold_bits = bits as u32;
    let threshold_bytes = (threshold_bits / 8) as usize;
    let threshold_bits_remainder = (threshold_bits % 8) as u8;
    // Check full bytes
    for i in 0..threshold_bytes {
        if hash[i] != 0 {
            return false;
        }
    }
    // Check remaining bits in the next byte
    if threshold_bits_remainder > 0 && threshold_bytes < 32 {
        let mask = (1u8 << (8 - threshold_bits_remainder)) - 1;
        if hash[threshold_bytes] & mask != 0 {
            return false;
        }
    }
    true
}
