mod benchmark;
mod build;
mod circuit_stats;
mod generate_gnark_inputs;
mod prepare;
mod prove;
mod verify;

use {anyhow::Result, argh::FromArgs};

pub trait Command {
    fn run(&self) -> Result<()>;
}

/// Prove & verify a compiled Noir program using R1CS.
#[derive(FromArgs, PartialEq, Debug)]
pub struct Args {
    #[argh(subcommand)]
    subcommand: Commands,

    /// hash function to use (skyscraper, sha2, blake3)
    #[argh(option, short = 'h')]
    pub hash: Option<HashFunction>,

    /// enable Tracy profiling
    #[cfg(feature = "tracy")]
    #[argh(switch)]
    pub tracy: bool,

    /// enable Tracy allocation tracking with provided stack depth, or 0 to
    /// trace allocations without stack traces.
    #[cfg(feature = "tracy")]
    #[argh(option)]
    pub tracy_allocations: Option<usize>,

    /// keep the process alive after completion to allow tracy to collect data
    #[cfg(feature = "tracy")]
    #[argh(switch)]
    pub tracy_keepalive: bool,
}

/// Hash function selection
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub enum HashFunction {
    Skyscraper,
    Sha2,
    Blake3,
}

impl std::str::FromStr for HashFunction {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "skyscraper" => Ok(HashFunction::Skyscraper),
            "sha2" | "sha-2" => Ok(HashFunction::Sha2),
            "blake3" => Ok(HashFunction::Blake3),
            _ => Err(format!(
                "Unknown hash function: {}. Supported: skyscraper, sha2, blake3",
                s
            )),
        }
    }
}

impl Default for HashFunction {
    fn default() -> Self {
        HashFunction::Skyscraper
    }
}

impl HashFunction {
    pub fn feature_flag(&self) -> &'static str {
        match self {
            HashFunction::Skyscraper => "hash-skyscraper",
            HashFunction::Sha2 => "hash-sha2",
            HashFunction::Blake3 => "hash-blake3",
        }
    }
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand)]
enum Commands {
    Prepare(prepare::Args),
    Prove(prove::Args),
    CircuitStats(circuit_stats::Args),
    Verify(verify::Args),
    GenerateGnarkInputs(generate_gnark_inputs::Args),
    Benchmark(benchmark::Args),
}

impl Command for Args {
    fn run(&self) -> Result<()> {
        // Get the hash function
        let hash = self.hash.unwrap_or_default();
        // Build with the selected hash function
        let was_rebuilt = build::ensure_built_with_hash(hash)?;
        if was_rebuilt {
            build::re_execute_with_new_binary()?;
        }
        self.subcommand.run()
    }
}

impl Command for Commands {
    fn run(&self) -> Result<()> {
        match self {
            Self::Prepare(args) => args.run(),
            Self::Prove(args) => args.run(),
            Self::CircuitStats(args) => args.run(),
            Self::Verify(args) => args.run(),
            Self::GenerateGnarkInputs(args) => args.run(),
            Self::Benchmark(args) => args.run(),
        }
    }
}
