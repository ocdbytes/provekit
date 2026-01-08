use {
    sha3::{Digest, Keccak256},
    spongefish_pow::PowStrategy,
};

#[derive(Clone, Copy)]
pub struct KeccakPoW {
    challenge: [u8; 32],
    bits:      f64,
}

impl PowStrategy for KeccakPoW {
    fn new(challenge: [u8; 32], bits: f64) -> Self {
        assert!(
            (0.0..256.0).contains(&bits),
            "bits must be smaller than 256"
        );
        Self { challenge, bits }
    }

    fn check(&mut self, nonce: u64) -> bool {
        // Hash challenge || nonce
        let mut hasher = Keccak256::new();
        hasher.update(&self.challenge);
        hasher.update(&nonce.to_le_bytes());
        let hash = hasher.finalize();
        // Count leading zero bits
        let threshold_bits = self.bits as u32;
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

    fn solve(&mut self) -> Option<u64> {
        let mut nonce = 0u64;
        loop {
            if self.check(nonce) {
                return Some(nonce);
            }
            nonce = nonce.wrapping_add(1);
            if nonce == 0 {
                return None; // Wrapped around, no solution found
            }
        }
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
    fn test_pow_keccak() {
        const BITS: f64 = 10.0;
        let iopattern = DomainSeparator::<DefaultHash>::new("the proof of work lottery 🎰")
            .add_bytes(1, "something")
            .challenge_pow("rolling dices");
        let mut prover = iopattern.to_prover_state();
        prover.add_bytes(b"\0").expect("Invalid IOPattern");
        prover.challenge_pow::<KeccakPoW>(BITS).unwrap();
        let mut verifier = iopattern.to_verifier_state(prover.narg_string());
        let byte = verifier.next_bytes::<1>().unwrap();
        assert_eq!(&byte, b"\0");
        verifier.challenge_pow::<KeccakPoW>(BITS).unwrap();
    }
}
