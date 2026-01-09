//! Hash function module
//!
//! Hash functions are selected at compile-time using feature flags:
//! - `hash-skyscraper` (default): Skyscraper hash function
//! - `hash-sha2`: SHA-256
//! - `hash-keccak`: Keccak-256
//! - `hash-blake3`: BLAKE3

use {
    crate::{
        hash::{
            blake3::{Blake3CRH, Blake3MerkleConfig, Blake3PoW, Blake3TwoToOne},
            keccak::{KeccakCRH, KeccakMerkleConfig, KeccakPoW, KeccakTwoToOne},
            sha2::{Sha2CRH, Sha2MerkleConfig, Sha2PoW, Sha2TwoToOne},
            skyscraper::{
                SkyscraperCRH, SkyscraperMerkleConfig, SkyscraperPoW, SkyscraperTwoToOne,
            },
        },
        FieldElement,
    },
    ark_crypto_primitives::{
        crh::{CRHScheme, TwoToOneCRHScheme},
        merkle_tree::Config,
        Error,
    },
    rand08::Rng,
    serde::{Deserialize, Serialize},
    spongefish::{
        codecs::arkworks_algebra::{
            FieldDomainSeparator, FieldToUnitDeserialize, FieldToUnitSerialize,
        },
        duplex_sponge::DuplexSpongeInterface,
        ByteDomainSeparator, DomainSeparator, ProofResult, ProverState, VerifierState,
    },
    spongefish_pow::PowStrategy,
    std::{str::FromStr, sync::atomic::{AtomicU8, Ordering}},
    whir::{crypto::merkle_tree::IdentityDigestConverter, whir::domainsep::DigestDomainSeparator},
    zeroize::Zeroize,
};

pub mod blake3;
pub mod keccak;
pub mod sha2;
pub mod skyscraper;

mod utils;

// Use AtomicU8 for lock-free reads in hot paths
static CURRENT_HASH_FUNCTION: AtomicU8 = AtomicU8::new(HashFunction::Skyscraper as u8);

pub fn set_hash_function(hash_fn: HashFunction) {
    CURRENT_HASH_FUNCTION.store(hash_fn as u8, Ordering::Release);
}

#[inline(always)]
pub fn get_hash_function() -> HashFunction {
    unsafe { std::mem::transmute(CURRENT_HASH_FUNCTION.load(Ordering::Relaxed)) }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum HashFunction {
    Sha2 = 0,
    Blake3 = 1,
    Keccak = 2,
    Skyscraper = 3,
}

impl HashFunction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Sha2 => "sha2",
            Self::Blake3 => "blake3",
            Self::Keccak => "keccak",
            Self::Skyscraper => "skyscraper",
        }
    }

    pub fn create_sponge(&self, iv: [u8; 32]) -> Sponge {
        match self {
            Self::Sha2 => Sponge::Sha2(sha2::Sha2Sponge::new(iv)),
            Self::Blake3 => Sponge::Blake3(blake3::Blake3Sponge::new(iv)),
            Self::Keccak => Sponge::Keccak(keccak::KeccakSponge::new(iv)),
            Self::Skyscraper => Sponge::Skyscraper(skyscraper::SkyscraperSponge::new(iv)),
        }
    }
}

impl FromStr for HashFunction {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "sha2" | "sha-256" | "sha256" => Ok(Self::Sha2),
            "blake3" => Ok(Self::Blake3),
            "keccak" | "keccak-256" | "keccak256" => Ok(Self::Keccak),
            "skyscraper" => Ok(Self::Skyscraper),
            _ => Err(format!(
                "Unknown hash function: {}. Valid hash functions: sha2, blake3, keccak, skyscraper",
                s
            )),
        }
    }
}

#[derive(Clone, Zeroize)]
pub enum Sponge {
    Sha2(sha2::Sha2Sponge),
    Blake3(blake3::Blake3Sponge),
    Keccak(keccak::KeccakSponge),
    Skyscraper(skyscraper::SkyscraperSponge),
}

impl Default for Sponge {
    fn default() -> Self {
        let hash_fn = get_hash_function();
        hash_fn.create_sponge([0u8; 32])
    }
}

impl DuplexSpongeInterface<FieldElement> for Sponge {
    fn new(iv: [u8; 32]) -> Self {
        let hash_fn = get_hash_function();
        hash_fn.create_sponge(iv)
    }
    fn absorb_unchecked(&mut self, input: &[FieldElement]) -> &mut Self {
        match self {
            Self::Sha2(sponge) => {
                sponge.absorb_unchecked(input);
            }
            Self::Blake3(sponge) => {
                sponge.absorb_unchecked(input);
            }
            Self::Keccak(sponge) => {
                sponge.absorb_unchecked(input);
            }
            Self::Skyscraper(sponge) => {
                sponge.absorb_unchecked(input);
            }
        }
        self
    }
    fn squeeze_unchecked(&mut self, output: &mut [FieldElement]) -> &mut Self {
        match self {
            Self::Sha2(sponge) => {
                sponge.squeeze_unchecked(output);
            }
            Self::Blake3(sponge) => {
                sponge.squeeze_unchecked(output);
            }
            Self::Keccak(sponge) => {
                sponge.squeeze_unchecked(output);
            }
            Self::Skyscraper(sponge) => {
                sponge.squeeze_unchecked(output);
            }
        }
        self
    }
    fn ratchet_unchecked(&mut self) -> &mut Self {
        match self {
            Self::Sha2(sponge) => {
                sponge.ratchet_unchecked();
            }
            Self::Blake3(sponge) => {
                sponge.ratchet_unchecked();
            }
            Self::Keccak(sponge) => {
                sponge.ratchet_unchecked();
            }
            Self::Skyscraper(sponge) => {
                sponge.ratchet_unchecked();
            }
        }
        self
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MerkleConfig {
    Skyscraper(crate::hash::skyscraper::SkyscraperMerkleConfig),
    Blake3(crate::hash::blake3::Blake3MerkleConfig),
    Keccak(crate::hash::keccak::KeccakMerkleConfig),
    Sha2(crate::hash::sha2::Sha2MerkleConfig),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CRH {
    Skyscraper(SkyscraperCRH),
    Blake3(Blake3CRH),
    Keccak(KeccakCRH),
    Sha2(Sha2CRH),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TwoToOneCRH {
    Skyscraper(SkyscraperTwoToOne),
    Blake3(Blake3TwoToOne),
    Keccak(KeccakTwoToOne),
    Sha2(Sha2TwoToOne),
}

impl CRHScheme for CRH {
    type Input = [FieldElement];
    type Output = FieldElement;
    type Parameters = ();

    fn setup<R: Rng>(_r: &mut R) -> Result<Self::Parameters, Error> {
        Ok(())
    }

    #[inline]
    fn evaluate<T: std::borrow::Borrow<Self::Input>>(
        _: &Self::Parameters,
        input: T,
    ) -> Result<Self::Output, Error> {
        match get_hash_function() {
            HashFunction::Skyscraper => <SkyscraperCRH as CRHScheme>::evaluate(&(), input),
            HashFunction::Blake3 => <Blake3CRH as CRHScheme>::evaluate(&(), input),
            HashFunction::Keccak => <KeccakCRH as CRHScheme>::evaluate(&(), input),
            HashFunction::Sha2 => <Sha2CRH as CRHScheme>::evaluate(&(), input),
        }
    }
}

impl TwoToOneCRHScheme for TwoToOneCRH {
    type Input = FieldElement;
    type Output = FieldElement;
    type Parameters = ();

    fn setup<R: Rng>(_r: &mut R) -> Result<Self::Parameters, Error> {
        Ok(())
    }

    #[inline]
    fn evaluate<T: std::borrow::Borrow<Self::Input>>(
        _: &Self::Parameters,
        l: T,
        r: T,
    ) -> Result<Self::Output, Error> {
        match get_hash_function() {
            HashFunction::Skyscraper => {
                <SkyscraperTwoToOne as TwoToOneCRHScheme>::evaluate(&(), l, r)
            }
            HashFunction::Blake3 => <Blake3TwoToOne as TwoToOneCRHScheme>::evaluate(&(), l, r),
            HashFunction::Keccak => <KeccakTwoToOne as TwoToOneCRHScheme>::evaluate(&(), l, r),
            HashFunction::Sha2 => <Sha2TwoToOne as TwoToOneCRHScheme>::evaluate(&(), l, r),
        }
    }

    #[inline]
    fn compress<T: std::borrow::Borrow<Self::Output>>(
        p: &Self::Parameters,
        l: T,
        r: T,
    ) -> Result<Self::Output, Error> {
        match get_hash_function() {
            HashFunction::Skyscraper => {
                <SkyscraperTwoToOne as TwoToOneCRHScheme>::compress(p, l, r)
            }
            HashFunction::Blake3 => <Blake3TwoToOne as TwoToOneCRHScheme>::compress(p, l, r),
            HashFunction::Keccak => <KeccakTwoToOne as TwoToOneCRHScheme>::compress(p, l, r),
            HashFunction::Sha2 => <Sha2TwoToOne as TwoToOneCRHScheme>::compress(p, l, r),
        }
    }
}

impl Config for MerkleConfig {
    type Leaf = [FieldElement];
    type LeafDigest = FieldElement;
    type LeafInnerDigestConverter = IdentityDigestConverter<FieldElement>;
    type InnerDigest = FieldElement;
    type LeafHash = CRH;
    type TwoToOneHash = TwoToOneCRH;
}

impl MerkleConfig {
    pub fn new(hash_function: HashFunction) -> Self {
        match hash_function {
            HashFunction::Skyscraper => Self::Skyscraper(SkyscraperMerkleConfig),
            HashFunction::Blake3 => Self::Blake3(Blake3MerkleConfig),
            HashFunction::Keccak => Self::Keccak(KeccakMerkleConfig),
            HashFunction::Sha2 => Self::Sha2(Sha2MerkleConfig),
        }
    }
}

#[derive(Clone)]
pub enum PoW {
    Skyscraper(crate::hash::skyscraper::SkyscraperPoW),
    Blake3(Box<crate::hash::blake3::Blake3PoW>),
    Keccak(crate::hash::keccak::KeccakPoW),
    Sha2(crate::hash::sha2::Sha2PoW),
}

impl PowStrategy for PoW {
    fn new(challenge: [u8; 32], bits: f64) -> Self {
        match get_hash_function() {
            HashFunction::Skyscraper => Self::Skyscraper(SkyscraperPoW::new(challenge, bits)),
            HashFunction::Blake3 => Self::Blake3(Box::new(Blake3PoW::new(challenge, bits))),
            HashFunction::Keccak => Self::Keccak(KeccakPoW::new(challenge, bits)),
            HashFunction::Sha2 => Self::Sha2(Sha2PoW::new(challenge, bits)),
        }
    }
    fn check(&mut self, nonce: u64) -> bool {
        match self {
            Self::Skyscraper(pow) => pow.check(nonce),
            Self::Blake3(pow) => pow.check(nonce),
            Self::Keccak(pow) => pow.check(nonce),
            Self::Sha2(pow) => pow.check(nonce),
        }
    }
    fn solve(&mut self) -> Option<u64> {
        match self {
            Self::Skyscraper(pow) => pow.solve(),
            Self::Blake3(pow) => pow.solve(),
            Self::Keccak(pow) => pow.solve(),
            Self::Sha2(pow) => pow.solve(),
        }
    }
}

#[derive(Clone)]
pub enum IOPattern {
    Sha2(DomainSeparator<sha2::Sha2Sponge, FieldElement>),
    Blake3(DomainSeparator<blake3::Blake3Sponge, FieldElement>),
    Keccak(DomainSeparator<keccak::KeccakSponge, FieldElement>),
    Skyscraper(DomainSeparator<skyscraper::SkyscraperSponge, FieldElement>),
}

impl IOPattern {
    pub fn new(label: &str) -> Self {
        Self::new_with_hash(label, get_hash_function())
    }

    pub fn new_with_hash(label: &str, hash_function: HashFunction) -> Self {
        match hash_function {
            HashFunction::Sha2 => Self::Sha2(DomainSeparator::new(label)),
            HashFunction::Blake3 => Self::Blake3(DomainSeparator::new(label)),
            HashFunction::Keccak => Self::Keccak(DomainSeparator::new(label)),
            HashFunction::Skyscraper => Self::Skyscraper(DomainSeparator::new(label)),
        }
    }
    pub fn as_bytes(&self) -> Vec<u8> {
        match self {
            Self::Sha2(io) => io.as_bytes().to_vec(),
            Self::Blake3(io) => io.as_bytes().to_vec(),
            Self::Keccak(io) => io.as_bytes().to_vec(),
            Self::Skyscraper(io) => io.as_bytes().to_vec(),
        }
    }
    fn to_domain_separator_string(&self) -> String {
        match self {
            Self::Sha2(io) => String::from_utf8(io.as_bytes().to_vec()).unwrap(),
            Self::Blake3(io) => String::from_utf8(io.as_bytes().to_vec()).unwrap(),
            Self::Keccak(io) => String::from_utf8(io.as_bytes().to_vec()).unwrap(),
            Self::Skyscraper(io) => String::from_utf8(io.as_bytes().to_vec()).unwrap(),
        }
    }
    pub fn to_prover_state(&self) -> ProverState<Sponge, FieldElement> {
        let domain_separator =
            DomainSeparator::<Sponge, FieldElement>::from_string(self.to_domain_separator_string());
        ProverState::<Sponge, FieldElement>::from(&domain_separator)
    }
    pub fn to_verifier_state<'a>(
        &self,
        transcript: &'a [u8],
    ) -> VerifierState<'a, Sponge, FieldElement> {
        let domain_separator =
            DomainSeparator::<Sponge, FieldElement>::from_string(self.to_domain_separator_string());
        VerifierState::<'a, Sponge, FieldElement>::new(&domain_separator, transcript)
    }
}

impl FieldDomainSeparator<FieldElement> for IOPattern {
    fn add_scalars(self, count: usize, label: &str) -> Self {
        match self {
            Self::Sha2(io) => IOPattern::Sha2(
                <DomainSeparator<sha2::Sha2Sponge, FieldElement> as FieldDomainSeparator<
                    FieldElement,
                >>::add_scalars(io, count, label),
            ),
            Self::Blake3(io) => IOPattern::Blake3(<DomainSeparator<
                blake3::Blake3Sponge,
                FieldElement,
            > as FieldDomainSeparator<FieldElement>>::add_scalars(
                io, count, label
            )),
            Self::Keccak(io) => IOPattern::Keccak(<DomainSeparator<
                keccak::KeccakSponge,
                FieldElement,
            > as FieldDomainSeparator<FieldElement>>::add_scalars(
                io, count, label
            )),
            Self::Skyscraper(io) => IOPattern::Skyscraper(<DomainSeparator<
                skyscraper::SkyscraperSponge,
                FieldElement,
            > as FieldDomainSeparator<FieldElement>>::add_scalars(
                io, count, label
            )),
        }
    }
    fn challenge_scalars(self, count: usize, label: &str) -> Self {
        match self {
            Self::Sha2(io) => IOPattern::Sha2(
                <DomainSeparator<sha2::Sha2Sponge, FieldElement> as FieldDomainSeparator<
                    FieldElement,
                >>::challenge_scalars(io, count, label),
            ),
            Self::Blake3(io) => IOPattern::Blake3(<DomainSeparator<
                blake3::Blake3Sponge,
                FieldElement,
            > as FieldDomainSeparator<FieldElement>>::challenge_scalars(
                io, count, label
            )),
            Self::Keccak(io) => IOPattern::Keccak(<DomainSeparator<
                keccak::KeccakSponge,
                FieldElement,
            > as FieldDomainSeparator<FieldElement>>::challenge_scalars(
                io, count, label
            )),
            Self::Skyscraper(io) => IOPattern::Skyscraper(<DomainSeparator<
                skyscraper::SkyscraperSponge,
                FieldElement,
            > as FieldDomainSeparator<FieldElement>>::challenge_scalars(
                io, count, label
            )),
        }
    }
}

impl ByteDomainSeparator for IOPattern {
    fn add_bytes(self, count: usize, label: &str) -> Self {
        match self {
            Self::Sha2(io) => IOPattern::Sha2(io.add_bytes(count, label)),
            Self::Blake3(io) => IOPattern::Blake3(io.add_bytes(count, label)),
            Self::Keccak(io) => IOPattern::Keccak(io.add_bytes(count, label)),
            Self::Skyscraper(io) => IOPattern::Skyscraper(io.add_bytes(count, label)),
        }
    }
    fn hint(self, label: &str) -> Self {
        match self {
            Self::Sha2(io) => IOPattern::Sha2(io.hint(label)),
            Self::Blake3(io) => IOPattern::Blake3(io.hint(label)),
            Self::Keccak(io) => IOPattern::Keccak(io.hint(label)),
            Self::Skyscraper(io) => IOPattern::Skyscraper(io.hint(label)),
        }
    }
    fn challenge_bytes(self, count: usize, label: &str) -> Self {
        match self {
            Self::Sha2(io) => IOPattern::Sha2(io.challenge_bytes(count, label)),
            Self::Blake3(io) => IOPattern::Blake3(io.challenge_bytes(count, label)),
            Self::Keccak(io) => IOPattern::Keccak(io.challenge_bytes(count, label)),
            Self::Skyscraper(io) => IOPattern::Skyscraper(io.challenge_bytes(count, label)),
        }
    }
}

impl DigestDomainSeparator<MerkleConfig> for IOPattern {
    fn add_digest(self, label: &str) -> Self {
        match self {
            Self::Sha2(io) => IOPattern::Sha2(io.add_digest(label)),
            Self::Blake3(io) => IOPattern::Blake3(io.add_digest(label)),
            Self::Keccak(io) => IOPattern::Keccak(io.add_digest(label)),
            Self::Skyscraper(io) => IOPattern::Skyscraper(io.add_digest(label)),
        }
    }
}

pub type ProverTranscript = ProverState<Sponge, FieldElement>;
pub type VerifierTranscript<'a> = VerifierState<'a, Sponge, FieldElement>;

impl whir::whir::utils::DigestToUnitSerialize<MerkleConfig> for ProverState<Sponge, FieldElement> {
    fn add_digest(&mut self, digest: FieldElement) -> ProofResult<()> {
        self.add_scalars(&[digest])
    }
}

impl<'a> whir::whir::utils::DigestToUnitDeserialize<MerkleConfig>
    for VerifierState<'a, Sponge, FieldElement>
{
    fn read_digest(&mut self) -> ProofResult<FieldElement> {
        let [r] = self.next_scalars()?;
        Ok(r)
    }
}
