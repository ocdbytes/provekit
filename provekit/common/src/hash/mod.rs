//! Hash function module
//!
//! Hash functions are selected at compile-time using feature flags:
//! - `hash-skyscraper` (default): Skyscraper hash function
//! - `hash-sha2`: SHA-256
//! - `hash-blake3`: BLAKE3

use {
    crate::FieldElement,
    spongefish::{DomainSeparator, ProverState, VerifierState},
};

#[cfg(all(not(feature = "hash-sha2"), feature = "hash-blake3"))]
pub mod blake3;
#[cfg(feature = "hash-sha2")]
pub mod sha2;
#[cfg(all(not(feature = "hash-sha2"), not(feature = "hash-blake3")))]
pub mod skyscraper;
mod utils;

// SHA2 implementation
#[cfg(feature = "hash-sha2")]
pub type Sponge = crate::hash::sha2::Sha2Sponge;
#[cfg(feature = "hash-sha2")]
pub type MerkleConfig = crate::hash::sha2::Sha2MerkleConfig;
#[cfg(feature = "hash-sha2")]
pub type PoW = crate::hash::sha2::Sha2PoW;

// Blake3 implementation
#[cfg(all(not(feature = "hash-sha2"), feature = "hash-blake3"))]
pub type Sponge = crate::hash::blake3::Blake3Sponge;
#[cfg(all(not(feature = "hash-sha2"), feature = "hash-blake3"))]
pub type MerkleConfig = crate::hash::blake3::Blake3MerkleConfig;
#[cfg(all(not(feature = "hash-sha2"), feature = "hash-blake3"))]
pub type PoW = crate::hash::blake3::Blake3PoW;

// Skyscraper implementation (default - when no higher priority hash is enabled)
#[cfg(all(not(feature = "hash-sha2"), not(feature = "hash-blake3")))]
pub type Sponge = crate::hash::skyscraper::SkyscraperSponge;
#[cfg(all(not(feature = "hash-sha2"), not(feature = "hash-blake3")))]
pub type MerkleConfig = crate::hash::skyscraper::SkyscraperMerkleConfig;
#[cfg(all(not(feature = "hash-sha2"), not(feature = "hash-blake3")))]
pub type PoW = crate::hash::skyscraper::SkyscraperPoW;

pub type IOPattern = DomainSeparator<Sponge, FieldElement>;
pub type ProverTranscript = ProverState<Sponge, FieldElement>;
pub type VerifierTranscript<'a> = VerifierState<'a, Sponge, FieldElement>;
