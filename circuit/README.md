# Hash-based Signature Aggregation

[Hash-Based Multi-Signatures for Post-Quantum Ethereum](https://eprint.iacr.org/2025/055.pdf) aggregation implementation based on [Plonky3](https://github.com/Plonky3/Plonky3).

## Run

```
$ cargo run --release --example hash-sig-agg -- -h
Usage: hash-sig-agg [OPTIONS]

Options:
  -i, --piop <PIOP>
          [default: univariate] [possible values: univariate, multilinear]
  -m, --pcs-merkle-hash <PCS_MERKLE_HASH>
          [default: poseidon2] [possible values: keccak, poseidon2]
  -r, --log-blowup <LOG_BLOWUP>
          [default: 1]
  -l, --log-signatures <LOG_SIGNATURES>
          Logarithmic amount of signatures to aggregate.
          Requires 'log-blowup + log-signatures <= 17' when 'piop = univariate'.
          Requires 'log-blowup + log-signatures <= 7' when 'piop = multilinear'.
  -p, --pow-bits <POW_BITS>
          [default: 0]
  -s, --soundness-type <SOUNDNESS_TYPE>
          [default: provable] [possible values: provable, conjecture]
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

The result will be saved into directory `report` with naming `uv_r${LOG_BLOWUP}_t${THREADS}`.
