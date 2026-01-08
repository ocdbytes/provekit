Task: Benchmark ProveKit Hash Functions (Protocol-Level)

Repo: https://github.com/worldfnd/provekit

Goal
Benchmark ProveKit performance across different hash functions at the protocol level (not the circuit level). Hash changes will mainly affect the Merkle tree and Fiat–Shamir transcript, but the full protocol should be checked for other hash dependencies.

Scope
Use the complete age-check circuit from noir-examples/noir-passport-examples. The circuit must remain unchanged.
Benchmark with:
 • SHA2
 • SHA3
 • BLAKE3
 • SkyscraperV2
 • Other relevant hash functions

Add support in the ProveKit CLI to select the hash function.

Benchmarking
 • Use identical inputs/witnesses across runs.
 • Run each benchmark multiple times.
 • Report:
 • Proving time (avg + variance)
 • Verification time (if applicable)
 • Peak memory / RSS (if feasible)
 • Any other relevant metrics 

Deliverables
 • Code changes enabling hash selection via CLI
 • Short README summarizing setup, protocol changes, results, and key observations
