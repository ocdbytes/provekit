# Benchmarking

## Hash Functions
- Skyscraper
- SHA2
- Blake3

## Benchmarking
- Proving time
- Verification time

## To run benchmarks

```sh
# Compile circuit
cd noir-examples/noir-passport-examples/complete_age_check
nargo compile

# Prepare
cargo run --bin provekit-cli -- --hash <hash_function> prepare noir-examples/noir-passport-examples/complete_age_check/target/complete_age_check.json --pkp ./prover.pkp --pkv ./verifier.pkv

# Run benchmarks
cargo run --release --bin provekit-cli -- --hash <hash_function> benchmark ./prover.pkp ./verifier.pkv noir-examples/noir-passport-examples/complete_age_check/Prover.toml
```

This will generate a report in the `target/criterion` directory.

```sh
open $pwd/target/criterion/report/index.html
```

To get memory usage run : 

```sh
cargo instruments --template Allocations --bin provekit-cli -- --hash <hash_function> prove ./prover.pkp noir-examples/noir-passport-examples/complete_age_check/Prover.toml -o ./proof.np
```

Example output:

![Memory usage](./mem_bench.png)