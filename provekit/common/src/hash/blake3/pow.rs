use {
    blake3::{
        guts::BLOCK_LEN,
        platform::{Platform, MAX_SIMD_DEGREE},
        Hasher, IncrementCounter, OUT_LEN,
    },
    spongefish_pow::PowStrategy,
};

/// A SIMD-accelerated BLAKE3-based proof-of-work engine.
///
/// This struct encapsulates the state needed to search for a nonce such that
/// `BLAKE3(challenge || nonce)` is below a difficulty threshold.
///
/// It leverages `Platform::hash_many` for parallel hash evaluation using
/// `MAX_SIMD_DEGREE` lanes.
#[derive(Clone, Copy)]
pub struct Blake3PoW {
    /// The 32-byte challenge seed used as a prefix to every hash input.
    challenge: [u8; 32],
    /// Difficulty target: hashes must be less than this 64-bit threshold.
    threshold: u64,
    /// Platform-specific SIMD hashing backend selected at runtime.
    platform:  Platform,
    /// SIMD batch of hash inputs, each 64 bytes (challenge + nonce).
    inputs:    [[u8; BLOCK_LEN]; MAX_SIMD_DEGREE],
    /// SIMD batch of hash outputs (32 bytes each).
    outputs:   [u8; OUT_LEN * MAX_SIMD_DEGREE],
}

impl PowStrategy for Blake3PoW {
    /// Create a new Blake3PoW instance with a given challenge and difficulty.
    ///
    /// The `bits` parameter controls the difficulty. A higher number means
    /// lower probability of success per nonce. This function prepares the SIMD
    /// input buffer with the challenge prefix and sets the internal threshold.
    ///
    /// # Panics
    /// - If `bits` is not in the range [0.0, 60.0).
    #[allow(clippy::cast_sign_loss)]
    fn new(challenge: [u8; 32], bits: f64) -> Self {
        // BLAKE3 block size must be 64 bytes.
        assert_eq!(BLOCK_LEN, 64);
        // BLAKE3 output size must be 32 bytes.
        assert_eq!(OUT_LEN, 32);
        // Ensure the difficulty is within supported range.
        assert!((0.0..60.0).contains(&bits), "bits must be smaller than 60");

        // Prepare SIMD input buffer: fill each lane with the challenge prefix.
        let mut inputs = [[0u8; BLOCK_LEN]; MAX_SIMD_DEGREE];
        for input in &mut inputs {
            input[..32].copy_from_slice(&challenge);
        }

        Self {
            // Store challenge prefix.
            challenge,
            // Compute threshold: smaller means harder PoW.
            threshold: (64.0 - bits).exp2().ceil() as u64,
            // Detect SIMD platform (e.g., AVX2, NEON, etc).
            platform: Platform::detect(),
            // Pre-filled SIMD inputs (nonce injected later).
            inputs,
            // Zero-initialized output buffer for SIMD hashes.
            outputs: [0; OUT_LEN * MAX_SIMD_DEGREE],
        }
    }

    /// Check if a given `nonce` satisfies the challenge.
    ///
    /// This uses the standard high-level BLAKE3 interface to ensure
    /// full compatibility with reference implementations.
    ///
    /// A nonce is valid if the first 8 bytes of the hash output,
    /// interpreted as a little-endian `u64`, are below the internal threshold.
    fn check(&mut self, nonce: u64) -> bool {
        // Create a new BLAKE3 hasher instance.
        let mut hasher = Hasher::new();

        // Feed the challenge prefix.
        hasher.update(&self.challenge);
        // Feed the nonce as little-endian bytes.
        hasher.update(&nonce.to_le_bytes());
        // Zero-extend the nonce to 32 bytes (challenge + nonce = full block).
        hasher.update(&[0; 24]);

        // Hash the input and extract the first 8 bytes.
        let mut hash = [0u8; 8];
        hasher.finalize_xof().fill(&mut hash);

        // Check whether the result is below the threshold.
        u64::from_le_bytes(hash) < self.threshold
    }

    /// Finds the minimal `nonce` that satisfies the challenge.
    ///
    /// Uses SIMD batching for efficient parallel hash evaluation.
    fn solve(&mut self) -> Option<u64> {
        (0..)
            .step_by(MAX_SIMD_DEGREE)
            .find_map(|nonce| self.check_many(nonce))
    }
}

impl Blake3PoW {
    /// Default BLAKE3 initialization vector. Copied here because it is not
    /// publicly exported.
    #[allow(clippy::unreadable_literal)]
    const BLAKE3_IV: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    const BLAKE3_FLAGS: u8 = 0x0b; // CHUNK_START | CHUNK_END | ROOT

    /// Check a SIMD-width batch of nonces starting at `nonce`.
    ///
    /// Returns the first nonce in the batch that satisfies the challenge
    /// threshold, or `None` if none do.
    fn check_many(&mut self, nonce: u64) -> Option<u64> {
        // Fill each SIMD input block with the challenge + nonce suffix.
        for (i, input) in self.inputs.iter_mut().enumerate() {
            // Write the nonce as little-endian into bytes 32..40.
            let n = (nonce + i as u64).to_le_bytes();
            input[32..40].copy_from_slice(&n);
        }

        // Create references required by `hash_many`.
        let input_refs: [&[u8; BLOCK_LEN]; MAX_SIMD_DEGREE] =
            std::array::from_fn(|i| &self.inputs[i]);

        // Perform parallel hashing over the input blocks.
        self.platform.hash_many::<BLOCK_LEN>(
            &input_refs,
            &Self::BLAKE3_IV,     // Initialization vector
            0,                    // Counter
            IncrementCounter::No, // Do not increment counter
            Self::BLAKE3_FLAGS,   // Default flags
            0,
            0, // No start/end flags
            &mut self.outputs,
        );

        // Scan results and return the first nonce under the threshold.
        for (i, chunk) in self.outputs.chunks_exact(OUT_LEN).enumerate() {
            let hash = u64::from_le_bytes(chunk[..8].try_into().unwrap());
            if hash < self.threshold {
                return Some(nonce + i as u64);
            }
        }

        // None of the batch satisfied the condition.
        None
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        spongefish::{
            ByteDomainSeparator, BytesToUnitDeserialize, BytesToUnitSerialize, DefaultHash,
            DomainSeparator,
        },
        spongefish_pow::{PoWChallenge, PoWDomainSeparator},
    };

    #[test]
    fn test_pow_blake3() {
        const BITS: f64 = 10.0;

        let iopattern = DomainSeparator::<DefaultHash>::new("the proof of work lottery 🎰")
            .add_bytes(1, "something")
            .challenge_pow("rolling dices");

        let mut prover = iopattern.to_prover_state();
        prover.add_bytes(b"\0").expect("Invalid IOPattern");
        prover.challenge_pow::<Blake3PoW>(BITS).unwrap();

        let mut verifier = iopattern.to_verifier_state(prover.narg_string());
        let byte = verifier.next_bytes::<1>().unwrap();
        assert_eq!(&byte, b"\0");
        verifier.challenge_pow::<Blake3PoW>(BITS).unwrap();
    }
}
