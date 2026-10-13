# Security Policy

## Scope

`evmghost` is a **read-only reconnaissance tool**. It never signs transactions,
never holds private keys, and never sends a transaction to any network. All
chain interaction is via `eth_call`, `eth_getCode`, `eth_getStorageAt`,
`eth_getTransactionByHash`, and `eth_getLogs`.

Any behavior where `evmghost` attempts a state-changing operation is a bug.

## Reporting a vulnerability

Please report security issues privately rather than opening a public issue.

Include:

1. The commit hash you tested
2. The RPC endpoint and target address (or a minimal reproduction bytecode)
3. The exact command and the output
4. The expected versus actual behavior

## Responsible use

`evmghost` is intended for authorized security research and bug-bounty
programs. Only scan contracts you own, contracts in a program whose scope
explicitly covers them, or contracts you have written permission to test.

Rate-limiting, credential stuffing, and denial-of-service techniques are out
of scope for this tool and are not supported. The bundled public endpoints are
shared — prefer your own node for heavy sweeps.
