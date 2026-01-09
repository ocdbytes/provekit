# Benchmarking

4 hash functions were benchmarked. Skyscraper is the default hash function. There are no protocol breaking changes between the hash functions. Each hash function is hidden behind a feature flag in order to compile the protocol with the desired hash function.

## Hash Functions

- Skyscraper (default)
- SHA2
- Blake3
- Keccak

## Benchmarking

- Proving time
- Verification time
- Memory usage

## To run benchmarks

```sh
# Compile circuit
cd noir-examples/noir-passport-examples/complete_age_check
nargo compile

# Prepare
cargo run --bin provekit-cli --release prepare noir-examples/noir-passport-examples/complete_age_check/target/complete_age_check.json --pkp ./prover.pkp --pkv ./verifier.pkv --hash <hash_function>

# Run benchmarks
cargo run --bin provekit-cli --release benchmark ./prover.pkp ./verifier.pkv noir-examples/noir-passport-examples/complete_age_check/Prover.toml
```

This will generate a report in the `target/criterion` directory.

```sh
open $pwd/target/criterion/report/index.html
```

To get memory usage run :

```sh
cargo instruments --template Allocations --bin provekit-cli --release prove ./prover.pkp noir-examples/noir-passport-examples/complete_age_check/Prover.toml -o ./proof.np
```

Example output:

![Memory usage](./mem_bench.png)

## Results

| Hash Function | Proving Time (Mean) | Verification Time (Mean) | Prover Chart                          | Verifier Chart                         |
| ------------- | ------------------- | ------------------------ | ------------------------------------- | -------------------------------------- |
| Skyscraper    | 5.9175s             | 33.337ms                 | ![Skyscraper](./skyscraper/prove.png) | ![Skyscraper](./skyscraper/verify.png) |
| SHA2          | 5.3425s             | 30.566ms                 | ![SHA2](./sha2/prove.png)             | ![SHA2](./sha2/verify.png)             |
| Blake3        | 4.2266s             | 26.723ms                 | ![Blake3](./blake3/prove.png)         | ![Blake3](./blake3/verify.png)         |
| Keccak        | 4.9722s             | 28.573ms                 | ![Keccak](./keccak/prove.png)         | ![Keccak](./keccak/verify.png)         |
