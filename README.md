# Hash-based Signature Aggregation

[Hash-Based Multi-Signatures for Post-Quantum Ethereum](https://eprint.iacr.org/2025/055.pdf) aggregation implementation based on [Plonky3](https://github.com/Plonky3/Plonky3).

```
.
├── hash-sig-agg         # Aggregation implementation
├── hash-sig-verifier    # Verifier implementation for specific instantiations
└── hash-sig-testdata    # Testdata generator
```

Note that the `hash-sig-verifier` is using an [alternative tweak encoding](https://github.com/han0110/hash-sig/commit/800059fb8e07ef9e22904ccdb8889109017da8b5) to make it more arithmetization friendly.

## Run

```
$ cargo run --release --example hash-sig-agg -- -h
Usage: hash-sig-agg [OPTIONS]

Options:
  -i, --piop <PIOP>
          PIOP to use to prove the AIR [default: univariate] [possible values: univariate, multilinear]
  -m, --pcs-merkle-hash <PCS_MERKLE_HASH>
          Merkle hash to use in PCS [default: poseidon2] [possible values: poseidon2, keccak]
  -r, --log-blowup <LOG_BLOWUP>
          Logarithmic blowup factor to use (inverse of RS code rate) [default: 1]
  -l, --log-signatures <LOG_SIGNATURES>
          Logarithmic amount of signatures to aggregate.
          Requires 'log-blowup + log-signatures <= 17' when 'piop = univariate'.
          Requires 'log-blowup + log-signatures <= 7' when 'piop = multilinear'.
  -p, --pow-bits <POW_BITS>
          Maximum proof-of-work bits to use [default: 0]
  -s, --security-assumption <SECURITY_ASSUMPTION>
          Security assumption of PCS to use [default: johnson-bound] [possible values: johnson-bound, capacity-bound]
  -h, --help
          Print help
  -V, --version
          Print version
```

## Benchmark

```
sh bench.sh
python3 render_table.py
```

The result of each run with different parameters will be saved into directory `report`.

