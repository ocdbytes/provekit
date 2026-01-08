use {
    crate::hash::utils::check_pow_bits,
    rayon,
    sha2::{Digest, Sha256},
    spongefish_pow::PowStrategy,
    std::sync::atomic::{AtomicU64, Ordering},
};

#[derive(Clone, Copy)]
pub struct Sha2PoW {
    challenge: [u8; 32],
    bits:      f64,
}

impl PowStrategy for Sha2PoW {
    fn new(challenge: [u8; 32], bits: f64) -> Self {
        assert!((0.0..60.0).contains(&bits), "bits must be smaller than 60");
        Self { challenge, bits }
    }

    fn check(&mut self, nonce: u64) -> bool {
        // Hash challenge || nonce
        let mut hasher = Sha256::new();
        hasher.update(&self.challenge);
        hasher.update(&nonce.to_le_bytes());
        let hash = hasher.finalize();
        check_pow_bits(&hash, self.bits)
    }

    fn solve(&mut self) -> Option<u64> {
        let solution = AtomicU64::new(u64::MAX);
        rayon::broadcast(|ctx| {
            let challenge = self.challenge;
            let bits = self.bits;
            for nonce in (0..).skip(ctx.index()).step_by(ctx.num_threads()) {
                // Early exit if another thread found a solution
                if nonce >= solution.load(Ordering::Acquire) {
                    return;
                }
                // Check if this nonce is a solution
                let mut hasher = Sha256::new();
                hasher.update(&challenge);
                hasher.update(&nonce.to_le_bytes());
                let hash = hasher.finalize();
                // Count leading zero bits
                let threshold_bits = bits as u32;
                let threshold_bytes = (threshold_bits / 8) as usize;
                let threshold_bits_remainder = (threshold_bits % 8) as u8;
                // Check full bytes
                let mut valid = true;
                for i in 0..threshold_bytes {
                    if hash[i] != 0 {
                        valid = false;
                        break;
                    }
                }
                // Check remaining bits in the next byte
                if valid && threshold_bits_remainder > 0 && threshold_bytes < 32 {
                    let mask = (1u8 << (8 - threshold_bits_remainder)) - 1;
                    if hash[threshold_bytes] & mask != 0 {
                        valid = false;
                    }
                }
                if valid {
                    solution.fetch_min(nonce, Ordering::AcqRel);
                    return;
                }
            }
        });
        let result = solution.load(Ordering::Acquire);
        if result == u64::MAX {
            None
        } else {
            Some(result)
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
    fn test_pow_sha2() {
        const BITS: f64 = 10.0;
        let iopattern = DomainSeparator::<DefaultHash>::new("the proof of work lottery 🎰")
            .add_bytes(1, "something")
            .challenge_pow("rolling dices");
        let mut prover = iopattern.to_prover_state();
        prover.add_bytes(b"\0").expect("Invalid IOPattern");
        prover.challenge_pow::<Sha2PoW>(BITS).unwrap();
        let mut verifier = iopattern.to_verifier_state(prover.narg_string());
        let byte = verifier.next_bytes::<1>().unwrap();
        assert_eq!(&byte, b"\0");
        verifier.challenge_pow::<Sha2PoW>(BITS).unwrap();
    }
}
