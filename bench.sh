#!/bin/sh

measure_peak_memory() {
    OS=$(uname -s)

    if [ $OS = 'Darwin' ]; then V='B '; fi
    AWK_SCRIPT="{ split(\"${V}kB MB GB TB\", v); s=1; while(\$1>1024 && s<9) { \$1/=1024; s++ } printf \"%.2f %s\", \$1, v[s] }"

    printf '%s' 'peak mem: '
    if [ $OS = 'Darwin' ]; then
        $(which time) -l "$@" 2>&1 | grep 'maximum resident set size' | grep -E -o '[0-9]+' | awk "$AWK_SCRIPT"
    else
        $(which time) -f '%M' "$@" 2>&1 | grep -E -o '^[0-9]+' | awk "$AWK_SCRIPT"
    fi
}

mkdir -p report

export JEMALLOC_SYS_WITH_MALLOC_CONF="retain:true,background_thread:true,metadata_thp:always,dirty_decay_ms:-1,muzzy_decay_ms:-1,abort_conf:true"
export RUST_LOG=info

cargo build --profile bench --example hash-sig-agg

for R in 1 2 3; do for T in 4 8 16 24; do
    export RAYON_NUM_THREADS=$T
    OUTPUT="report/uv_r${R}_t${T}"
    RUN="cargo run --quiet --profile bench --example hash-sig-agg -- \
        --piop univariate \
        --pcs-merkle-hash poseidon2 \
        --log-blowup $R \
        --log-signatures 13 \
        --pow-bits 0 \
        --security-assumption johnson-bound"
    $RUN > $OUTPUT
    measure_peak_memory $RUN >> $OUTPUT
done done
