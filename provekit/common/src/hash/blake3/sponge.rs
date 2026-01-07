use {
    crate::{
        hash::utils::{bigint_from_bytes_le, bytes_to_field, field_to_bytes},
        FieldElement,
    },
    blake3::Hasher,
    spongefish::duplex_sponge::{DuplexSponge, Permutation},
    zeroize::Zeroize,
};

type State = [FieldElement; 2];

#[derive(Clone, Default, Zeroize)]
pub struct Blake3 {
    state: State,
}

impl AsRef<[FieldElement]> for Blake3 {
    fn as_ref(&self) -> &[FieldElement] {
        &self.state
    }
}

impl AsMut<[FieldElement]> for Blake3 {
    fn as_mut(&mut self) -> &mut [FieldElement] {
        &mut self.state
    }
}

impl Permutation for Blake3 {
    type U = FieldElement;
    const N: usize = 2; // State size: 2 field elements
    const R: usize = 1; // Rate: 1 field element per block

    fn new(iv: [u8; 32]) -> Self {
        let felt = FieldElement::new(bigint_from_bytes_le(&iv));
        Self {
            state: [0.into(), felt],
        }
    }

    fn permute(&mut self) {
        // Convert state to bytes: 2 field elements = 64 bytes
        let state_bytes: Vec<u8> = self.state.iter().flat_map(|f| field_to_bytes(*f)).collect();
        // Hash with BLAKE3 to get 32 bytes
        let mut hasher = Hasher::new();
        hasher.update(&state_bytes);
        let hash_bytes = hasher.finalize();
        // Use the first 32 bytes for the first element
        let first_bytes: [u8; 32] = *hash_bytes.as_bytes();
        let first = bytes_to_field(first_bytes);
        // Hash again with the first element to get the second element
        let mut hasher2 = Hasher::new();
        hasher2.update(&first_bytes);
        let hash_bytes2 = hasher2.finalize();
        let second_bytes: [u8; 32] = *hash_bytes2.as_bytes();
        let second = bytes_to_field(second_bytes);
        self.state = [first, second];
    }
}

pub type Blake3Sponge = DuplexSponge<Blake3>;
