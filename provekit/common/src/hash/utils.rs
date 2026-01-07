use {
    crate::FieldElement,
    ark_ff::{BigInt, PrimeField},
};

pub fn bigint_from_bytes_le<const N: usize>(bytes: &[u8]) -> BigInt<N> {
    let limbs = bytes
        .chunks_exact(8)
        .map(|s| u64::from_le_bytes(s.try_into().unwrap()))
        .collect::<Vec<_>>();
    BigInt::new(limbs.try_into().unwrap())
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
