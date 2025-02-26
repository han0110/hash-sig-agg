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

for R in 1 2 3; do for T in 4 8 16 24; do
    export RAYON_NUM_THREADS=$T
    OUTPUT="report/r${R}_t${T}"
    RUN="cargo run --quiet --profile bench --example hash-sig-agg -- --log-signatures 13 --log-blowup $R"
    $RUN > $OUTPUT
    measure_peak_memory $RUN >> $OUTPUT
done done
