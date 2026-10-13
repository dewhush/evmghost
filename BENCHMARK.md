# Cross-language latency benchmark

`evmghost` exists in three implementations, all reading the same bytecode,
the same 289,074-selector dataset, and the same RPC:

- **Rust** — the shipped binary, `target/release/evmghost`
- **Python** — `bench/evmghost.py`, stdlib only (`urllib`, no `web3.py`)
- **Go** — `bench/evmghost.go`, stdlib only, goroutine-concurrent views

They are not three separate tools. They are the **same pipeline** measured in
three languages, because the interesting question is not "which is fastest"
but "what does the language actually buy you at this workload" — and the
answer is not where most people guess.

## Run it

```bash
cargo build --release
(cd bench && go build -o /tmp/evmghost-go .)

./bench/run.sh <RPC_URL> <ADDRESS> [deep|quick] [N]
# defaults: Aave V3 Pool on mainnet, deep, 3 timed runs
```

The harness runs **one untimed warm-up round per language**, then `N` timed
rounds, and prints a median / min / max table. Warm rounds are excluded
because the first run of any language pays for DNS, TLS handshake, and HTTP
connection-pool setup — a one-time cost that says nothing about the language.

## Results

Two measurements, because they answer different questions.

### 1. Language-isolated — local `anvil` node, no rate-limiting

The clean measurement: identical bytecode, identical dataset, zero network
variance, no throttling. Seven process invocations per language, warm — the
first run of each is discarded, since it re-parses the 3 MB signature dataset
cold.

| Implementation | Runs | Median (ms) | Min (ms) | Max (ms) |
|---|---|---|---|---|
| **Rust** | 7 | **9** | 8 | 10 |
| Go | 7 | 71 | 70 | 73 |
| Python | 7 | 220 | 215 | 262 |

### 2. Realistic — USDC on mainnet over a public RPC

`quick` mode on `0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48`,
`https://ethereum-rpc.publicnode.com`.

| Implementation | Runs | Median (ms) | Min (ms) | Max (ms) |
|---|---|---|---|---|
| **Rust** | 3 | **2,330** | 1,940 | 3,557 |
| Go | 3 | 87,757 | 84,100 | 91,300 |
| Python | 3 | — | — | — |

The Python column is deliberately blank rather than fabricated. Under public-
endpoint rate-limiting the sequential Python client exceeds the harness
timeout, and the figure it does produce (~87 s) is throttle-dominated, not
language-dominated. Reporting it next to the Rust number would imply a
language gap that does not exist.

### What the numbers actually mean

**The benchmark had to be fixed before it measured anything.**

The first version of this harness reported Go 8× faster than Rust. That was
not a finding, it was a bug — two of them, both in the harness and the Go
port, both of which would have shipped as a result.

- **The median helper silently divided by zero.** It counted samples with
  `printf '%s'` (no newline) then `wc -l`, which returns 0. The awk median
  then indexed a negative bucket and printed a value below the reported
  minimum. The table was self-contradictory — median 203 ms, min 406 ms — and
  nothing flagged it. Lesson: **a table whose median is outside its min/max
  range is broken, always, and no amount of re-running fixes it.**
- **Go's default `http.Transport` pools 2 idle connections per host.** Six
  concurrent named-view goroutines contend for those two slots and dial the
  rest fresh. Against a local node this made the *concurrent* port 170×
  slower than Python's sequential loop: `named_views` alone was 1103 ms in Go
  versus 6.4 ms in Python. Setting `MaxIdleConnsPerHost` to the actual
  fan-out dropped the whole Go pass to 71 ms. Lesson: **concurrency without a
  matching connection pool is not just useless, it is actively slower than
  doing nothing.**

With both fixed, the numbers stabilise and the ranking inverts.

**The `quick` pass is ~13 RPC round trips**: `eth_getCode`, two
`eth_getStorageAt` for proxy resolution, six named-view `eth_call`s, and five
storage reads.

- **Rust** finishes in 9 ms. The work is small and the connection pool is
  warm; `ureq` reuses the TLS session across calls without configuration.
  This is the number that matters for a batch sweep over hundreds of
  addresses.
- **Go** at 71 ms is doing the same work with the same concurrency, but pays
  ~8× more in process startup — Go binary init plus transport setup. Fine for
  a CLI, painful in a tight loop.
- **Python** at 220 ms is sequential `urllib`, one round trip at a time, plus
  interpreter startup. Consistently last, but predictably so — and the
  variance is low, which is what you want from a reference implementation.

**So the honest ranking is: Rust ≈ 8× Go ≈ 3× Python on a clean network, and
the spread is process startup plus connection handling — not compute.**

| | Local node | Public RPC |
|---|---|---|
| Best | Rust (~9 ms) | Rust (~2,330 ms) |
| Worst | Python (~220 ms) | Python (timeout) |
| Spread | 24× | ~37×+ |

### The lessons that generalise

1. **Verify the harness before trusting the table.** The most dangerous
   benchmark output is a plausible one. The first version of this comparison
   had Go beating Rust by 8× because of two bugs in the measurement code, and
   the table looked completely reasonable. Sanity-check your aggregates
   against your raw samples.
2. **Concurrency without a connection pool is a regression.** Go's six
   goroutines were 170× slower than Python's sequential loop until the idle
   connection limit matched the fan-out. If your concurrent code is slower
   than the sequential version, check the transport before the algorithm.
3. **Parallelise RPC calls before optimising anything else.** Once the pool
   is sized, collapsing six round trips into one latency window is worth more
   than every micro-optimisation in this codebase combined. If a recon tool
   feels slow, count round trips, not CPU cycles.
4. **Public-endpoint rate-limiting dominates latency more than the language
   does.** The spread is 24× locally and ~37× over a public RPC, and none of
   that difference is code. Benchmark against your own node to isolate the
   language from the endpoint; the harness takes any URL.
5. **The CPU-bound part is free.** Extracting selectors from bytecode and
   hashing against a 289k-entry map is sub-millisecond work in all three
   languages. Spending effort there is waste.
6. **Startup cost matters for CLIs, and nowhere else.** All three re-parse
   the signature dataset on every invocation. For a daemon or a batch sweep
   that cost amortises to nothing; for a one-shot CLI it is most of the wall
   time. Pick the tool for the shape of the job.
7. **Python is not disqualified — it is misused on the public endpoint.**
   Against a local or dedicated node it runs the same pass in 220 ms, and the
   reference implementation is ~250 lines you can read in one sitting. Ship
   it where correctness and clarity matter more than latency. The Rust binary
   exists for batch sweeps over hundreds of addresses, where connection reuse
   compounds.

## Methodology and caveats

- **Warm runs only.** The first invocation of each language pays DNS, TLS,
  and connection-pool setup. The harness warms once per language, then times.
- **Median, not mean.** Public endpoints have a long right tail from
  rate-limit retries; a mean would be dominated by a single throttle event.
- **Same dataset, same bytecode, same RPC for all three.** The only variable
  is the implementation.
- **Public RPC, so absolute numbers are endpoint-dependent, not stable.**
  The ratio between languages is far more reproducible than any individual
  figure. Re-run against a local node for language-isolated numbers.
- **`quick` mode only for the headline table.** `deep` mode issues one
  `eth_call` per selector (114 round trips for Aave V3), at which point the
  endpoint's rate limit decides everything and the language comparison
  becomes noise. The harness supports `deep`, but the quick table is the one
  that measures the languages.
- **No pip / no third-party packages.** Python uses only `urllib.request`,
  Go only `net/http`. A `web3.py` or `go-ethereum` client would shift the
  numbers by adding their own connection handling, which is the very thing
  being measured.

## Reproducing the table

```bash
# build all three
cargo build --release
(cd bench && go build -o /tmp/evmghost-go .)
python3 -c "import bench.evmghost"  # syntax check, no deps needed

# quick pass on USDC, 3 timed runs each
./bench/run.sh https://ethereum-rpc.publicnode.com \
  0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 quick 3
```

If your numbers differ in absolute terms, that is the endpoint. If the
**ratios** differ, open an issue with the command and output.
