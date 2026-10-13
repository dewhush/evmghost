#!/usr/bin/env bash
# Reproduce evmghost's exploit replays against a local anvil node.
#
# Requires foundry (forge/cast/anvil) and a release build:
#   cargo build --release
#   ./examples/setup-lab.sh
#
# Everything is local — no mainnet RPC, no real funds, no private keys beyond
# anvil's deterministic test accounts.
set -euo pipefail

cd "$(dirname "$0")/.."
BIN=./target/release/evmghost

if [[ ! -x "$BIN" ]]; then
  echo "build first: cargo build --release" >&2
  exit 1
fi

if ! pgrep -x anvil >/dev/null 2>&1; then
  echo "starting anvil on :8545"
  anvil --port 8545 --chain-id 31337 >/tmp/evmghost-anvil.log 2>&1 &
  ANVIL_PID=$!
  trap 'kill $ANVIL_PID' EXIT
  sleep 3
fi

RPC=http://127.0.0.1:8545
DEPLOYER=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266

echo "== 1. deploy VulnerableLab =="
LAB=$(forge create --rpc-url "$RPC" --private-key 0xac0974bec39a17e36ba4a6b4d238ff9444b9716a8c7d1e9e8f9d1f2d3a4b5c6d \
  examples/VulnerableLab.sol:VulnerableLab --from "$DEPLOYER" 2>/dev/null | grep 'Deployed to' | awk '{print $3}')
echo "   lab: $LAB"

echo
echo "== 2. quick pass =="
"$BIN" "$RPC" "$LAB" quick | grep -E 'TARGET|owner|totalSupply'

echo
echo "== 3. deep pass — three planted bugs, one trap =="
"$BIN" "$RPC" "$LAB" deep | grep -E 'SELECTORS|UNAUTH|GREEDY|REACHABLE'

echo
echo "== 4. replay kill() — should reach SELFDESTRUCT =="
"$BIN" "$RPC" "$LAB" replay 0x41c0e1b5 | grep -E 'REPLAY|result|selfdestruct'

echo
echo "== 5. replay withdraw() — should REVERT with 'not owner' =="
"$BIN" "$RPC" "$LAB" replay 0x2e1a7d4d | grep -E 'REPLAY|result|revert'

echo
echo "== 6. deploy the EIP-1967 proxy lab =="
IMPL=$(forge create --rpc-url "$RPC" --private-key 0xac0974bec39a17e36ba4a6b4d238ff9444b9716a8c7d1e9e8f9d1f2d3a4b5c6d \
  examples/ProxyLab.sol:Impl --from "$DEPLOYER" 2>/dev/null | grep 'Deployed to' | awk '{print $3}')
PROXY=$(cast send --rpc-url "$RPC" --private-key 0xac0974bec39a17e36ba4a6b4d238ff9444b9716a8c7d1e9e8f9d1f2d3a4b5c6d \
  --create "$(cast compile examples/ProxyLab.sol:EIP1967Proxy 2>/dev/null | tail -1)" "$IMPL" 2>/dev/null \
  | grep 'contractAddress:' | awk '{print $2}')
echo "   proxy: $PROXY"

echo
echo "== 7. resolve the proxy stack =="
"$BIN" "$RPC" "$PROXY" proxy

echo
echo "== 8. replay pwn() through the proxy =="
"$BIN" "$RPC" "$PROXY" replay 0xdd365b8b | grep -E 'REPLAY|result|storage writes' -A2
