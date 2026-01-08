use {
    crate::{
        hash::utils::{bigint_from_bytes_le, bytes_to_field, field_to_bytes},
        FieldElement,
    },
    sha2::{Digest, Sha256},
    spongefish::duplex_sponge::{DuplexSponge, Permutation},
    zeroize::Zeroize,
};

type State = [FieldElement; 2];

#[derive(Clone, Default, Zeroize)]
pub struct Sha2 {
    state: State,
}

impl AsRef<[FieldElement]> for Sha2 {
    fn as_ref(&self) -> &[FieldElement] {
        &self.state
    }
}

impl AsMut<[FieldElement]> for Sha2 {
    fn as_mut(&mut self) -> &mut [FieldElement] {
        &mut self.state
    }
}

impl Permutation for Sha2 {
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
        let mut state_bytes: [u8; 64] = [0; 64];
        state_bytes[0..32].copy_from_slice(&field_to_bytes(self.state[0]));
        state_bytes[32..64].copy_from_slice(&field_to_bytes(self.state[1]));

        // Hash with SHA2 to get 32 bytes
        let mut hasher = Sha256::new();
        hasher.update(&state_bytes);
        let hash_bytes = hasher.finalize();
        // Use the first 32 bytes for the first element, and hash again for the second
        let first_bytes: [u8; 32] = hash_bytes.into();
        let first = bytes_to_field(first_bytes);
        // Hash again with the first element to get the second element
        let mut hasher2 = Sha256::new();
        hasher2.update(&first_bytes);
        let hash_bytes2 = hasher2.finalize();
        let second_bytes: [u8; 32] = hash_bytes2.into();
        let second = bytes_to_field(second_bytes);
        self.state = [first, second];
    }
}

pub type Sha2Sponge = DuplexSponge<Sha2>;
