# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Roadmap

- Symbolic jump-target tracking — removes the `BadJump` ceiling on contracts
  that compute `JUMP` destinations from data
- Multi-block state seeding for time-accurate replays
- ERC-4626 vault share math (requires full-width `DIV`)
- Facet-level authorization tracing for EIP-2537 diamonds
- Batch mode: feed an address list, emit one JSON report per target

## [0.1.0] — 2026-10-13

First public release. Bytecode-only smart-contract access-control scanner.

### Added

- **Bytecode fingerprinting** — dispatcher walk extracts every 4-byte selector
  from `eth_getCode` with no ABI and no source. Solidity `PUSH0` (0x5f) is
  handled as a zero push, which is required for any solc ≥ 0.8.20 target.
- **Proxy stack resolution** — EIP-1967, EIP-1822 (UUPS), beacon proxies,
  EIP-1167 minimal clones, EIP-2537 diamond facets, and delegatecall fallback
  getters. Cycle-safe: visited addresses are tracked so a proxy loop
  terminates instead of hanging. Quick and deep modes probe the resolved
  logic contract, not the proxy.
- **Built-in EVM** (`src/vm.rs`) — a from-scratch EVM subset with real
  Keccak-256 (verified against the reference vector for the empty string),
  attacker-controlled `CALLER`/`ORIGIN`/`ADDRESS`/`CALLVALUE`, full-width
  `MUL`, `EXP`, `SHL`/`SHR`/`SAR`, `ADDMOD`/`MOD`, `MCOPY`, `SELFDESTRUCT`,
  `REVERT` with decoded revert strings, and `LOG`.
- **Chain-seeded storage** — replays seed storage from `eth_getStorageAt`
  (slots 0..64 plus anything the run touches), so `require(msg.sender == owner)`
  evaluates against the real owner.
- **`replay` mode** — run a single selector through the built-in EVM from the
  CLI. Records storage writes, logs, return data, gas used, and decoded revert
  strings. This converts a heuristic flag into a proof.
- **`events` mode** — fetches and decodes recent logs: Transfer, Approval,
  Deposit, Withdrawal, Paused, Unpaused, RoleGranted, RoleRevoked, Upgraded,
  AdminChanged, BeaconUpgraded, OwnershipTransferred.
- **Vulnerability heuristics** — `[UNAUTHENTICATED?]` for write-like selectors that
  accept a stranger's `eth_call`, and `[GREEDY]` for outputs that depend on a
  single address argument.
- **`--json` output** — machine-readable reports with `proxy_stack`, `logic`,
  `selectors`, and `code_bytes` for CI and pipeline use.
- **Multi-endpoint RPC fallback** — rotates through a pool of public endpoints
  on rate limits and 5xx, always starting from the first healthy one.
- **`scan` mode** — passive sweep of a block range without a target address.
- **Embedded 4-byte signature dataset** — **289,074 selectors** compiled from
  the open 4byte.directory corpus, embedded into the binary at build time via
  `include_str!("../signatures.txt")` so lookups are a single hashmap hit with
  no network call. Covers ERC-20/721/1155/4626, OpenZeppelin, Solady, Compound,
  Aave, Uniswap, and the long tail of common DeFi signatures.
- Named-view detection for
  `owner()`, `paused()`, `totalSupply()`, `name()`, `symbol()`, `decimals()`.
- **Test suite** — 41 tests across 6 groups: EVM opcodes, dispatcher
  extraction, exploit replay (7 integration tests), and mainnet proxy
  resolution.

### Mainnet validation

Validated against live mainnet contracts with zero false positives:

- **USDT** — 35 selectors, live `owner`, admin functions flagged privileged
- **DAI** — 22 selectors; `mint` correctly reverts for a stranger
- **WBTC** — bytecode string scan surfaced
  `"renouncing ownership is blocked"`, a real finding from `[STRINGS]`
- **Aave V3 Pool** — proxy resolved to logic `0x728a138a…03cf`, 114 selectors
  extracted (5 visible at the proxy)
- **Uniswap V2 / V3 routers** — 36 / 54 selectors, no auth false positives
- **WETH** — deposit and withdraw confirmed permissionless as designed

### Known limitations

- Computed `JUMP` targets are not tracked symbolically; such contracts stop
  with `BadJump`.
- `DIV` / `MOD` above 2^128 use a low-128-bit approximation. Marked with
  `ponytail:` in `vm.rs`.
- `eth_getLogs` over wide ranges is rate-limited on public endpoints.

[Unreleased]: https://github.com/0xDew/evmghost/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/0xDew/evmghost/releases/tag/v0.1.0
