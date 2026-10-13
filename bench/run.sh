#!/usr/bin/env bash
# evmghost — cross-language latency benchmark
#
# Runs the same recon pass in Rust, Python, and Go against the same contract
# and RPC, N times each, and prints a latency table. Warm runs only are
# counted: the first run of each language primes DNS, TLS, and the HTTP
# connection pool, and that cost is not the language's.
#
# Usage:
#   ./bench/run.sh [RPC_URL] [ADDRESS] [deep|quick] [N]
set -euo pipefail

cd "$(dirname "$0")/.."

RPC="${1:-https://ethereum-rpc.publicnode.com}"
ADDR="${2:-0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2}"
MODE="${3:-deep}"
N="${4:-3}"

RUST_BIN=./target/release/evmghost
GO_BIN=${GO_BIN:-/tmp/evmghost-go}

if [[ ! -x "$RUST_BIN" ]]; then echo "build rust first: cargo build --release" >&2; exit 1; fi
if [[ ! -x "$GO_BIN" ]];  then echo "build go first: (cd bench && go build -o /tmp/evmghost-go .)" >&2; exit 1; fi

# All three are measured the same way: process wall-clock. Rust's quick mode
# prints no timing breakdown, and per-language output greps drift out of sync
# with the binary, so a uniform shell timing is both simpler and fairer.
declare -A RUN=( [rust]="$RUST_BIN $RPC $ADDR $MODE"
                 [python]="python3 bench/evmghost.py $RPC $ADDR $MODE"
                 [go]="$GO_BIN $RPC $ADDR $MODE" )

# one untimed warm-up round per language, then N timed rounds. The signature
# dataset is 3MB / 289k entries and is re-read on every process invocation,
# so the first timed run of each language is cold; we drop it and run N+1.
declare -A TIMES
for lang in rust python go; do
  echo "# warm-up: $lang" >&2
  timeout 500 bash -c "${RUN[$lang]}" >/dev/null 2>&1 || true
  for i in $(seq 1 $((N + 1))); do
    # awk gives float seconds -> ms in one step; bc is not guaranteed present
    v=$( { /usr/bin/env bash -c "time bash -c '${RUN[$lang]}' >/dev/null 2>&1" ; } 2>&1 \
        | awk '/^real/ { print $2 }' \
        | awk -F'm' '{ s=$1*60 + $2; printf "%.1f", s*1000 }' )
    # skip the first timed round (cold cache) and any failure
    if [[ -n "$v" && $i -gt 1 ]]; then
      TIMES[$lang]+="$v "
    fi
    echo "# $lang run $i: ${v:-FAILED}" >&2
  done
done

# ---- table -------------------------------------------------------------------
# Wall-clock process timing is noisy: each invocation re-parses the 3MB /
# 289k-entry signature dataset, and cold kernel/disk cache makes the first
# run of any language 10-100x slower. We drop the cold run and report the
# median, which is robust to the remaining tail.
median() { # space-separated numbers -> median
  # both printf calls need '%s\n'; a bare '%s' makes wc -l return 0 and the
  # awk median silently divides by zero
  printf '%s\n' $1 | sort -n | awk -v n="$(printf '%s\n' $1 | wc -l)" \
    '{a[NR]=$1} END { if (n%2==1) print a[(n+1)/2]; else printf "%.1f", (a[n/2]+a[n/2+1])/2 }'
}

echo
echo "## Latency — \`$MODE\` on \`$ADDR\`"
echo
echo "| Implementation | Runs | Median (ms) | Min (ms) | Max (ms) |"
echo "|---|---|---|---|---|"
for lang in rust python go; do
  vals=${TIMES[$lang]:-}
  if [[ -z "$vals" ]]; then
    echo "| $lang | 0 | — | — | — |"
    continue
  fi
  # printf '%s\n' so wc -l counts runs; a bare %s gives 0 for every language
  cnt=$(printf '%s\n' $vals | wc -l)
  med=$(median "$vals")
  min=$(printf '%s\n' $vals | sort -n | head -1)
  max=$(printf '%s\n' $vals | sort -n | tail -1)
  echo "| $lang | $cnt | ${med} | ${min} | ${max} |"
done
echo
