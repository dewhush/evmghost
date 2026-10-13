#!/usr/bin/env bash
# evmghost — cross-language latency benchmark
#
# Runs the same recon pass in Rust, Go, and Python against the same contract
# and RPC, N times each, and prints a statistical summary instead of a handful
# of raw samples. Every language is timed by the same definition of a run.
#
# All three ports emit an identical stage table; this harness greps the single
# "total" line out of each, so the comparison is apples-to-apples and does not
# depend on shell timing quirks.
#
#   usage: ./bench/run.sh <RPC_URL> <ADDRESS> <quick|deep> <RUNS> [label]
set -uo pipefail

RPC=${1:-http://127.0.0.1:8545}
ADDR=${2:-0x5FbDB2315678afecb367f032d93F642f64180aa3}
MODE=${3:-quick}
RUNS=${4:-30}
LABEL=${5:-$(basename "$ADDR" | cut -c1-8)}

ROOT=$(cd "$(dirname "$0")/.." && pwd)
GOBIN=${GOBIN:-/tmp/evmghost-go}
RUSTBIN="$ROOT/target/release/evmghost"

if [[ ! -x "$RUSTBIN" ]]; then echo "build rust first: cargo build --release" >&2; exit 1; fi
if [[ ! -x "$GOBIN" ]]; then
  echo "building go port to $GOBIN" >&2
  (cd "$ROOT/bench" && go build -o "$GOBIN" .) || exit 1
fi

declare -A CMD=(
  [rust]="$RUSTBIN $RPC $ADDR $MODE --timings"
  [go]="$GOBIN $RPC $ADDR $MODE"
  [python]="python3 $ROOT/bench/evmghost.py $RPC $ADDR $MODE"
)

# one invocation -> total ms, or empty on failure
probe() {
  timeout 300 bash -c "$1" 2>&1 \
    | awk -F': *' '/^total/ { gsub(" ms", "", $2); print $2; exit }'
}

# The signature dataset (3MB / 289k entries) is re-parsed on every process
# invocation, so the first run of each language is cold. It is discarded and
# never counted; every reported statistic below is warm.
declare -A SAMPLES
for lang in rust go python; do
  echo "# warm-up: $lang" >&2
  probe "${CMD[$lang]}" >/dev/null 2>&1 || true
  for ((i = 1; i <= RUNS; i++)); do
    v=$(probe "${CMD[$lang]}")
    [[ -n "$v" ]] && SAMPLES[$lang]+="$v "
    echo "# $lang run $i: ${v:-FAILED}" >&2
  done
done

# n mean stdev p50 p90 p99 cv — awk, because bc is not guaranteed present
# the input arrives as a single space-separated string; split it here rather
# than relying on awk field-splitting, which would treat it as one record
stats() {
  [[ -z "$1" ]] && { echo "0 - - - - - -"; return; }
  printf '%s\n' $1 | sort -n | awk '
    function ceil(x) { return (x == int(x)) ? x : int(x) + 1 }
    { a[NR] = $1 + 0; s += $1 + 0; n++ }
    END {
      if (n == 0) { print "0 - - - - - -"; exit }
      mean = s / n
      for (i = 1; i <= n; i++) { d = a[i] - mean; ss += d * d }
      sd = (n > 1) ? sqrt(ss / (n - 1)) : 0
      k = int(ceil(0.50 * n)); p50 = a[k]
      k = int(ceil(0.90 * n)); p90 = a[k]
      k = int(ceil(0.99 * n)); p99 = a[k]
      printf "%d %.1f %.1f %.1f %.1f %.1f %.1f\n", n, mean, sd, p50, p90, p99, (mean ? 100 * sd / mean : 0)
    }'
}

echo
echo "## Latency — \`${MODE}\` on \`${LABEL}\` — ${RUNS} warm runs"
echo
echo "| Implementation | Runs | Mean (ms) | StdDev | P50 | P90 | P99 | CV |"
echo "|---|---|---|---|---|---|---|---|"
for lang in rust go python; do
  read -r n mean sd p50 p90 p99 cv <<<"$(stats "${SAMPLES[$lang]:-}")"
  [[ "$n" == "0" ]] && { echo "| $lang | 0 | — | — | — | — | — | — |"; continue; }
  printf '| %-8s | %s | %.1f | %.1f | %.1f | %.1f | %.1f | %.0f%% |\n' \
    "$lang" "$n" "$mean" "$sd" "$p50" "$p90" "$p99" "$cv"
done
echo
echo "Wall-clock per invocation, the same clock a user sees. The cold first run"
echo "of each language is discarded. \`CV\` is coefficient of variation — under"
echo "~10% means the measurement is stable enough to trust the spread."
