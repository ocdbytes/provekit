//! Hash function module
//!
//! Hash functions are selected at compile-time using feature flags:
//! - `hash-skyscraper` (default): Skyscraper hash function
//! - `hash-sha2`: SHA-256
//! - `hash-keccak`: Keccak-256
//! - `hash-blake3`: BLAKE3

use {
    crate::FieldElement,
    cfg_if::cfg_if,
    spongefish::{DomainSeparator, ProverState, VerifierState},
};

cfg_if! {
    if #[cfg(feature = "hash-sha2")] {
        pub mod sha2;
        pub type Sponge = crate::hash::sha2::Sha2Sponge;
        pub type MerkleConfig = crate::hash::sha2::Sha2MerkleConfig;
        pub type PoW = crate::hash::sha2::Sha2PoW;

    } else if #[cfg(feature = "hash-blake3")] {
        pub mod blake3;
        pub type Sponge = crate::hash::blake3::Blake3Sponge;
        pub type MerkleConfig = crate::hash::blake3::Blake3MerkleConfig;
        pub type PoW = crate::hash::blake3::Blake3PoW;

    } else if #[cfg(feature = "hash-keccak")] {
        pub mod keccak;
        pub type Sponge = crate::hash::keccak::KeccakSponge;
        pub type MerkleConfig = crate::hash::keccak::KeccakMerkleConfig;
        pub type PoW = crate::hash::keccak::KeccakPoW;

    } else {
        pub mod skyscraper;
        pub type Sponge = crate::hash::skyscraper::SkyscraperSponge;
        pub type MerkleConfig = crate::hash::skyscraper::SkyscraperMerkleConfig;
        pub type PoW = crate::hash::skyscraper::SkyscraperPoW;
    }
}

mod utils;

pub type IOPattern = DomainSeparator<Sponge, FieldElement>;
pub type ProverTranscript = ProverState<Sponge, FieldElement>;
pub type VerifierTranscript<'a> = VerifierState<'a, Sponge, FieldElement>;
