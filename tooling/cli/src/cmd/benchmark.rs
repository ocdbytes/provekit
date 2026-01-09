use {
    super::Command,
    anyhow::{Context, Result},
    argh::FromArgs,
    criterion::{black_box, Criterion},
    provekit_common::{file::read, hash::set_hash_function, Prover, Verifier},
    provekit_prover::Prove,
    provekit_verifier::Verify,
    std::path::PathBuf,
    tracing::instrument,
};

/// Benchmark proving and verification using Criterion
#[derive(FromArgs, PartialEq, Eq, Debug)]
#[argh(subcommand, name = "benchmark")]
pub struct Args {
    #[argh(positional)]
    prover_path: PathBuf,

    #[argh(positional)]
    verifier_path: PathBuf,

    #[argh(positional)]
    input_path: PathBuf,
}

impl Command for Args {
    #[instrument(skip_all)]
    fn run(&self) -> Result<()> {
        let prover: Prover = read(&self.prover_path).context("while reading Provekit Prover")?;
        let verifier: Verifier =
            read(&self.verifier_path).context("while reading Provekit Verifier")?;
        set_hash_function(prover.hash_function);
        let proof = prover
            .clone()
            .prove(&self.input_path)
            .context("While proving Noir program statement")?;

        // Verify the proof once before benchmarking to ensure it works
        let mut test_verifier = verifier.clone();
        test_verifier
            .verify(&proof)
            .context("Initial verification failed - proof may be invalid")?;

        let mut criterion = Criterion::default();

        {
            let prover_clone = prover.clone();
            let input_path = self.input_path.clone();
            criterion.bench_function(&format!("prove-{:?}", prover.hash_function), |b| {
                b.iter(|| {
                    let prover = black_box(prover_clone.clone());
                    let input_path = black_box(&input_path);
                    prover.prove(input_path).expect("proving failed")
                })
            });
        }

        {
            let verifier_clone = verifier.clone();
            let proof_clone = proof.clone();
            criterion.bench_function(&format!("verify-{:?}", prover.hash_function), |b| {
                b.iter(|| {
                    let mut verifier = black_box(verifier_clone.clone());
                    let proof = black_box(&proof_clone);
                    verifier.verify(proof).expect("verification failed")
                })
            });
        }

        criterion.final_summary();

        Ok(())
    }
}
