# evmghost <a href="https://www.rust-lang.org/"><img alt="Rust" src="https://img.shields.io/badge/Rust-2021-dea584?logo=rust&logoColor=white"></a>

> Ghost through EVM bytecode. Detect access-control bugs on smart contracts with **no source code, no ABI, and no Solidity compiler** — bytecode-only.

[![binary size](https://img.shields.io/badge/binary-5.9MB_static-black)](#)
[![tests](https://img.shields.io/badge/tests-41%2F41%20pass-success)](#)
[![no keys needed](https://img.shields.io/badge/auth-read--only%20JSON--RPC-informational)](#)

`evmghost` is a bytecode-first reconnaissance tool for auditors, bug-bounty hunters, and security researchers. It fingerprints deployed smart contracts directly from `eth_getCode`, follows **delegatecall proxy stacks** (EIP-1967 / EIP-1822 / beacons / clones / diamonds), fingerprints every 4-byte selector, replays candidate exploits in a **built-in EVM**, and decodes on-chain events — all from one static binary against any JSON-RPC node.

It exists because the interesting targets are closed-source. When the contract has no verified source on Etherscan and no published ABI, you still need to know: **what can an attacker call, and what happens when they do?**

---

## Performance — Rust / Go / Python

The same `quick` pass runs in three stdlib ports against one `anvil` node,
30 warm invocations each. Full methodology and the bug that had to be fixed
first: [`BENCHMARK.md`](BENCHMARK.md).

| Implementation | Runs | Mean (ms) | StdDev | P50 | P90 | P99 | CV |
|---|---|---|---|---|---|---|---|
| Go | 30 | 4.4 | 0.4 | **4.4** | 5.0 | 5.4 | 8% |
| Rust | 30 | 5.5 | 0.5 | 5.4 | 6.1 | 6.7 | 10% |
| Python | 30 | 12.6 | 1.1 | 12.3 | 13.1 | 16.2 | 8% |

Coefficient of variation is 8–10% across the board, so the spread is a real
signal. The honest read: **the `quick` pass is RPC-bound, not CPU-bound** —
all three do ~13 round trips, and at P50 they sit within 3 ms of each other.
Go and Rust separate by interpreter-free startup; Python pays ~3× purely for
spin-up. Language choice does not move this workload.

---

## Table of contents

- [Performance — Rust / Go / Python](#performance--rust--go--python)
- [Why bytecode-only](#why-bytecode-only)
- [Install](#install)
- [Quick start](#quick-start)
- [Modes](#modes)
- [How it finds bugs](#how-it-finds-bugs)
- [The built-in EVM](#the-built-in-evm)
- [Proxy resolution](#proxy-resolution)
- [Real-world examples](#real-world-examples)
- [Cross-language benchmark](#cross-language-benchmark)
- [Limitations](#limitations)
- [Project layout](#project-layout)
- [Contributing](#contributing)
- [Roadmap](#roadmap)
- [Author](#author)

---

## Why bytecode-only

Source code is not the ground truth. **Bytecode is.** A verified Etherscan source can differ from what is actually deployed; a proxy's logic contract is usually *not* verified at all; and the most valuable targets in a bug-bounty program are closed-source forks of OpenZeppelin, Solady, and Curve with subtle local modifications.

`evmghost` treats the on-chain bytecode as the single source of truth:

- **No compiler needed.** No `solc`, no Foundry toolchain, no remappings. One static binary.
- **No source needed.** Works on unverified contracts, proprietary forks, and stripped metadata.
- **No ABI needed.** Selectors are extracted from the dispatcher, and signatures are matched against an embedded dataset of **289,074 four-byte signatures** — no network lookup, no API key.
- **No trust needed.** Read-only JSON-RPC (`eth_call`, `eth_getCode`, `eth_getStorageAt`). Never signs a transaction, never needs a wallet.

## Install

```bash
git clone https://github.com/0xDew/evmghost.git
cd evmghost
cargo build --release
# → target/release/evmghost
```

Requirements: a Rust 2021+ toolchain (`rustup`) and an Ethereum JSON-RPC endpoint. Any public node works — `ethereum-rpc.publicnode.com`, `1rpc.io/eth`, `eth.drpc.org`, Alchemy, Infura, a local `anvil`/`reth`/`geth --http`, or L2 RPCs. No API key required for the bundled public endpoints; pass your own for rate limits or private chains.

## Quick start

```bash
# Default public endpoint, quick pass
evmghost eth 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48

# Deep pass: every selector, all heuristics, storage 0..31
evmghost eth 0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2 deep

# Scriptable: just the proxy stack, one layer per line
evmghost https://your-rpc.example 0x… proxy

# Read any storage slot
evmghost eth 0x… slot --slot 0 --slot 51 --slot 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc

# Decode recent events
evmghost eth 0xdAC17F958D2ee523a2206206994597C13D831ec7 events 200

# Replay a selector in the built-in EVM against seeded chain state
evmghost eth 0x… replay 0x40c10f19

# JSON output for pipelines
evmghost eth 0x… deep --json | jq '.selectors | length'
```

`eth` is a shortcut for a rotating pool of public endpoints. Pass a full URL to use your own node.

## Modes

| Mode | What it does | Cost |
|---|---|---|
| `quick` *(default)* | Bytecode hash, proxy resolution, named views (`owner`/`paused`/`totalSupply`…), storage slots 0–4 | ~10 RPC calls |
| `deep` | Quick + full selector extraction, vuln heuristics, storage slots 0–31, string scan | ~1 RPC per selector |
| `slot` | Read arbitrary 32-byte storage slots | 1 call per slot |
| `proxy` | Resolve the proxy stack only — scriptable, one layer per line | 1–4 calls |
| `events` | Fetch and decode recent logs (Transfer, Approval, Upgrade, RoleGranted, …) | 1 `eth_getLogs` |
| `replay` | Run one selector through the built-in EVM with state seeded from the chain | ~65 `eth_getStorageAt` |
| `scan` | Passive sweep of a block range, no target address | 1 call per block |

## How it finds bugs

Three independent layers, because no single signal is reliable.

**1. Dispatcher fingerprints.** Solidity's function dispatcher is a predictable pattern: `CALLDATALOAD` of the first word, `SHR` to the low 4 bytes, a comparison against a `PUSH4` constant, then a conditional `JUMPI`. `evmghost` walks this pattern and extracts every selector the contract can actually receive — including selectors that never appear in any published ABI.

**2. Signature + state fuzzing.** Each selector is `eth_call`ed from an attacker address with several argument shapes: zero, max-value, attacker address, victim address, and small integers. A selector that **does not revert** when called by a stranger is a privilege-escalation candidate. Two patterns are flagged:
- `[UNAUTHENTICATED?]` — a write-looking selector that accepts the call.
- `[GREEDY]` — output that depends on a single address argument, i.e. a balance or allowance read worth attacking.

**3. Local EVM replay.** This is the part that separates a heuristic from a proof. For any candidate selector, `evmghost` loads the real bytecode into its own EVM implementation, seeds storage from `eth_getStorageAt` (the first 64 slots plus any slots the run touches), sets `CALLER`/`ORIGIN` to the attacker, and executes. The result is not a guess:

```
[REPLAY] 0x2e1a7d4d withdraw(uint256)  (1 args)
  result      : Revert
  gas_used    : 717
  revert data: 0x08c379a0…0096e6f74206f776e6572…  "not owner"
```

Storage writes are recorded, so you see exactly which slots an unauthenticated call would mutate — and what value it would write.

## The built-in EVM

`src/vm.rs` is a real EVM subset, written from scratch with no dependencies beyond `tiny-keccak` for the Keccak-256 opcode:

- Full stack semantics for the arithmetic, comparison, bitwise, memory, and flow opcodes used by production dispatchers (`PUSH0`/`PUSH32`, `DUP`/`SWAP`, `SHL`/`SHR`/`SAR`, `EXP`, `MUL` full-width, `ADDMOD`/`MOD`, `MCOPY`).
- **Real Keccak-256** — verified against the reference vector for the empty string — so `SLOAD`/`SSTORE` mapping keys hash exactly as Solidity computes them.
- `CALLER`/`ORIGIN`/`ADDRESS`/`CALLVALUE` are set to the attacker's, so `require(msg.sender == owner)` behaves exactly as it would on-chain.
- `SELFDESTRUCT`, `REVERT` (with decoded revert string), `LOG` events, return data, and gas accounting.
- Storage is a sparse map that can be **seeded from the chain**, so replays see real balances, real owners, and real allowances.

The VM is deliberately an interpreter, not a symbolic executor. It runs the actual deployed bytecode with concrete attacker inputs — fast, deterministic, and no false positives from solver timeouts.

## Proxy resolution

Most value sits behind a proxy, and the proxy bytecode contains almost nothing. `evmghost` resolves the full stack before probing, then probes the **logic** contract:

- **EIP-1967** — implementation slot `0x360894…d382bbc`, admin slot, beacon slot
- **EIP-1822 (UUPS)** — `proxiableUUID()` / the standard 1822 slot
- **Beacon proxies** — resolves the beacon, then the implementation it points to
- **EIP-1167 minimal clones** — parses the embedded constant address
- **EIP-2537 diamonds** — facets from `facets()` / Louper-style selectors
- **Fallback getters** — tries `implementation()`, `getImplementation()`, `_implementation()` and other common accessor names
- **Cycle-safe** — the resolver tracks visited addresses and terminates on a loop instead of hanging

Stack depth is reported and each layer is labelled:

```
$ evmghost eth 0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2 proxy
eip1967 0x87870bca…b4fa4e2 0x728a138a…f526fe03cf
logic   0x728a138a…f526fe03cf 0x728a138a…f526fe03cf
# terminal: 0x728a138a4823392c2efa55e028d434f526fe03cf
```

For Aave V3 this is the difference between **5 selectors** (what the proxy exposes) and **114 selectors** (what the logic contract actually implements). A scan that stops at the proxy is not a scan.

## Real-world examples

Validated against live mainnet contracts with **zero false positives**:

- **USDT** (`0xdAC17…`) — 35 selectors, `owner` live, `Issue`/`Redeem`/`Params` admin functions correctly flagged as privileged
- **DAI** (`0x6B17…`) — 22 selectors; `mint` correctly **reverts** for a stranger (no false positive on the most tempting target)
- **WBTC** (`0x2260…`) — string scan surfaced `"renouncing ownership is blocked"` directly from bytecode — a real finding from `[STRINGS]`, not a heuristic
- **Aave V3 Pool** — proxy resolved to `0x728a138a…03cf`, **114 selectors** extracted from logic
- **Uniswap V2/V3 routers** — 36/54 selectors, swap paths mapped, no auth claims
- **WETH** — deposit/withdraw confirmed permissionless as designed

## Cross-language benchmark

The same pipeline exists in three languages — Rust (this binary), Go
(`bench/evmghost.go`, stdlib only), and Python (`bench/evmghost.py`, stdlib
only) — all reading the same bytecode and the same 289,074-selector dataset.
Every port emits an identical stage table, so one harness times all three by
the same clock and the same definition of a run.

```bash
./bench/run.sh <RPC_URL> <ADDRESS> quick 30
```

Local `anvil` node, no rate-limiting, 30 warm runs per language:

| Implementation | Runs | Mean (ms) | StdDev | P50 | P90 | P99 | CV |
|---|---|---|---|---|---|---|---|
| Go | 30 | 4.4 | 0.4 | **4.4** | 5.0 | 5.4 | 8% |
| Rust | 30 | 5.5 | 0.5 | 5.4 | 6.1 | 6.7 | 10% |
| Python | 30 | 12.6 | 1.1 | 12.3 | 13.1 | 16.2 | 8% |

CV is 8–10% across all three, so the spread is a real signal rather than
measurement noise. **The pass is RPC-bound**: ~13 round trips, and all three
languages land within 3 ms of each other at the median.

**The benchmark had to be fixed before it measured anything, and the bug it
exposed is the most useful thing in it.** The first run reported Go 8× faster
than Rust. That was two bugs: a shell `median()` helper that silently divided
by zero, and Go's default `http.Transport` pooling only 2 idle connections per
host — so six concurrent goroutines starved and the "concurrent" port ran
170× slower than Python's sequential loop. Sizing the pool to the fan-out
took the Go pass from 1103 ms to 4.4 ms.

The generalisable lesson: **concurrency without a matching connection pool is
not a missed optimisation, it is an active regression.** Full statistics,
both bugs, and the corrected analysis are in
[`BENCHMARK.md`](BENCHMARK.md).

## Limitations

Honest, because guessing costs you time:

- **Computed jump targets are not tracked symbolically.** Contracts that compute `JUMP` destinations from data (some token and vault implementations) stop with `BadJump`. Adding a jump-target dataflow analysis is the single largest accuracy gain available.
- **`DIV`/`MOD` above 2^128 is a low-128-bit approximation.** Enough for ABI decoding and SafeMath-style arithmetic, not for a division-based prize calculation. Marked with `ponytail:` in `vm.rs`.
- **`eth_getLogs` over wide ranges** is rate-limited on public endpoints. Keep `events` to a few thousand blocks or use a dedicated node.
- **No private transaction simulation.** Replay is read-only recon against current chain state; it does not fork at an arbitrary block height.

## Project layout

```
evmghost/
├── src/
│   ├── main.rs       CLI, help text, RPC endpoint rotation
│   ├── rpc.rs        JSON-RPC client with multi-endpoint fallback
│   ├── probe.rs      modes: quick/deep/slot/proxy/events/replay/scan
│   ├── proxy.rs      proxy stack resolution + event decoding
│   ├── vm.rs         the built-in EVM
│   ├── selectors.rs  4-byte signature lookup + dispatcher extraction
│   ├── strings.rs    printable-string scanner
│   └── scan_mode.rs  mode enum
├── signatures.txt    embedded 289K-selector 4-byte dataset (include_str!)
├── examples/         VulnerableLab.sol, ProxyLab.sol, setup-lab.sh
├── tests/            vm opcodes, dispatcher, replay (7), mainnet proxy
├── .github/workflows/ci.yml
└── Cargo.toml
```

~2,900 lines of Rust, ~6 MB static binary, three runtime dependencies.

## Contributing

The codebase is deliberately small and readable; prefer deleting code to adding it.

- Bug reports and reproduction commands are welcome — include the RPC endpoint, the address, and the mode.
- New heuristics must come with a test that fails before and passes after.
- New opcodes must come with a unit test against a known-good EVM result.
- Selector database additions belong in `src/selectors.rs`.

## Roadmap

- Symbolic jump-target tracking (removes the `BadJump` ceiling)
- Multi-block state seeding for time-accurate replays
- ERC-4626 vault share math (needs full-width `DIV`)
- Facet-level authorization tracing for diamonds
- Batch mode: feed a list of addresses, emit one JSON report per target

## Author

**evmghost** — `0xDew` | **dewhush**

Built for authorized security research and bug-bounty hunting. Use only
against contracts you own or are authorized to test.

Inspired by the gap between "the source is unverified" and "the contract is
live with user funds."
