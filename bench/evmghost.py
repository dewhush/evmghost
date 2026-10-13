#!/usr/bin/env python3
"""evmghost — Python reference implementation of the quick recon pass.

Same pipeline as the Rust binary: bytecode fetch -> proxy resolution ->
dispatcher selector extraction -> named-view probes. Single-file, stdlib
only, so the benchmark measures the language and the RPC layer, not the
dependency graph.

Usage:
    python3 bench/evmghost.py <RPC_URL> <ADDRESS> [deep]
"""
from __future__ import annotations

import json
import sys
import time
import urllib.request
from pathlib import Path

# EIP-1967 implementation slot: keccak256("eip1967.proxy.implementation") - 1
EIP1967_IMPL_SLOT = (
    "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
)
EIP1967_ADMIN_SLOT = (
    "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
)
EIP1822_SLOT = (
    "0xc5f16f0fcc639fa48a354c50895b9d8f8c1a5d0d0a1c9e2f0e3a6b8c7d6e5f4a"
)

# Views worth naming inline: the highest-value reads when planning an attack.
NAMED_VIEWS = {
    "0x8da5cb5b": "owner()",
    "0x5c975abb": "paused()",
    "0x18160ddd": "totalSupply()",
    "0x06fdde03": "name()",
    "0x95d89b41": "symbol()",
    "0x313ce567": "decimals()",
}

# Only the first byte matters for triage: an SSTORE anywhere in the dispatcher
# region means a call path can mutate state.
WRITE_OPcodes = {0x55, 0xf0, 0xf1, 0xf2, 0xf4, 0xf5, 0xfa}


class Rpc:
    """Minimal JSON-RPC client over stdlib urllib, with endpoint fallback.

    Public endpoints rate-limit aggressively, so a probe rotates to the next
    URL on a failure and always starts from the first healthy one.
    """

    POOL = (
        "https://ethereum-rpc.publicnode.com",
        "https://ethereum.publicnode.com",
        "https://1rpc.io/eth",
        "https://eth.drpc.org",
    )

    def __init__(self, urls: tuple[str, ...] = POOL) -> None:
        self.urls = urls
        self.cur = 0
        self._id = 0

    def call(self, method: str, params: list) -> object:
        last_err: Exception | None = None
        for _ in range(len(self.urls)):
            url = self.urls[self.cur]
            self._id += 1
            body = json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": self._id,
                    "method": method,
                    "params": params,
                }
            ).encode()
            req = urllib.request.Request(
                url, data=body, headers={"Content-Type": "application/json"}
            )
            # some public endpoints reject the default urllib UA with a 403
            req.add_header("User-Agent", "evmghost-bench/1.0")
            try:
                with urllib.request.urlopen(req, timeout=60) as r:
                    payload = json.loads(r.read())
                if payload.get("error"):
                    raise RuntimeError(f"{method}: {payload['error']}")
                return payload["result"]
            except Exception as exc:  # noqa: BLE001 - rotate, do not crash
                last_err = exc
                self.cur = (self.cur + 1) % len(self.urls)
        raise RuntimeError(f"all endpoints failed for {method}: {last_err}")

    def code(self, addr: str) -> bytes:
        hexstr = self.call("eth_getCode", [addr, "latest"])
        return bytes.fromhex(hexstr[2:]) if hexstr != "0x" else b""

    def storage_at(self, addr: str, slot: int) -> str:
        return self.call(
            "eth_getStorageAt",
            [addr, hex(slot), "latest"],
        )

    def block_number(self) -> int:
        return int(self.call("eth_blockNumber", []), 16)

    def call_view(self, to: str, data: str) -> str:
        return self.call(
            "eth_call", [{"to": to, "data": data}, "latest"]
        )


def load_signatures() -> dict[str, str]:
    """289k selectors -> signature strings. One-time cost, measured."""
    path = Path(__file__).resolve().parent.parent / "signatures.txt"
    out: dict[str, str] = {}
    with path.open() as f:
        for line in f:
            line = line.strip()
            if line:
                out[line] = NAMED_VIEWS.get(line, "unknown")
    # named views must win even if the dataset lacks them
    out.update(NAMED_VIEWS)
    return out


def extract_selectors(code: bytes) -> list[str]:
    """Walk the Solidity dispatcher and pull out every PUSH4 it compares.

    The pattern is: CALLDATALOAD(0) SHR(224) <PUSH4 sel> EQ JUMPI. We scan
    for PUSH4 and keep those followed by EQ, which is what a real dispatcher
    emits. Duplicate-free, order-preserving.
    """
    out: list[str] = []
    seen: set[str] = set()
    i = 0
    n = len(code)
    while i < n:
        op = code[i]
        if op == 0x63 and i + 5 <= n:  # PUSH4
            sel = "0x" + code[i + 1 : i + 5].hex()
            # the EQ/JUMPI lands after the 4 pushed bytes
            if i + 5 < n and code[i + 5] == 0x14:
                if sel not in seen:
                    seen.add(sel)
                    out.append(sel)
            i += 5
            continue
        if 0x60 <= op <= 0x7F:  # PUSH1..PUSH32: skip the pushed payload
            i += 1 + (op - 0x5F)
            continue
        i += 1
    return out


def resolve_proxy(rpc: Rpc, addr: str) -> str:
    """Follow an EIP-1967/1822 proxy to its logic contract."""
    for slot in (EIP1967_IMPL_SLOT, EIP1822_SLOT):
        raw = rpc.storage_at(addr, int(slot, 16))
        if raw and int(raw, 16) != 0:
            return "0x" + raw[-40:]
    return addr


def quick(rpc: Rpc, addr: str, sigs: dict[str, str]) -> dict:
    """The quick pass: proxy, selectors, named views, storage 0..4."""
    t0 = time.perf_counter()
    code = rpc.code(addr)
    t_code = time.perf_counter() - t0

    t0 = time.perf_counter()
    logic = resolve_proxy(rpc, addr)
    t_proxy = time.perf_counter() - t0

    if logic.lower() != addr.lower():
        code = rpc.code(logic)

    t0 = time.perf_counter()
    sels = extract_selectors(code)
    t_sel = time.perf_counter() - t0

    t0 = time.perf_counter()
    views: dict[str, str] = {}
    for sel, name in NAMED_VIEWS.items():
        try:
            views[name] = rpc.call_view(addr, sel)
        except Exception as exc:  # noqa: BLE001 - triage, not correctness
            views[name] = f"err: {exc}"
    t_views = time.perf_counter() - t0

    t0 = time.perf_counter()
    slots = {str(i): rpc.storage_at(addr, i) for i in range(5)}
    t_slots = time.perf_counter() - t0

    return {
        "logic": logic,
        "is_proxy": logic.lower() != addr.lower(),
        "code_bytes": len(code),
        "selectors": len(sels),
        "named": [sigs.get(s, "unknown") for s in sels if s in sigs],
        "views": views,
        "slots": slots,
        "timings": {
            "eth_getCode": t_code,
            "proxy_resolve": t_proxy,
            "selector_extract": t_sel,
            "named_views": t_views,
            "storage_0_4": t_slots,
        },
    }


def deep(rpc: Rpc, addr: str, sigs: dict[str, str]) -> dict:
    """Quick + write-opcode scan + eth_call every selector as a stranger."""
    res = quick(rpc, addr, sigs)
    code = rpc.code(res["logic"])

    t0 = time.perf_counter()
    write_regions = sum(1 for i, b in enumerate(code) if b in WRITE_OPcodes)
    t_scan = time.perf_counter() - t0

    t0 = time.perf_counter()
    reachable: list[str] = []
    for sel in extract_selectors(code):
        try:
            out = rpc.call_view(addr, sel + "0" * 64)
            if out != "0x":
                reachable.append(sel)
        except Exception:  # noqa: BLE001 - a revert is the expected answer
            pass
    t_probe = time.perf_counter() - t0

    res["write_opcodes"] = write_regions
    res["reachable"] = len(reachable)
    res["timings"]["write_scan"] = t_scan
    res["timings"]["probe_all_selectors"] = t_probe
    return res


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 1
    rpc_url, addr = sys.argv[1], sys.argv[2]
    mode = sys.argv[3] if len(sys.argv) > 3 else "quick"
    # "eth" expands to the public endpoint pool, matching the Rust binary
    rpc = Rpc() if rpc_url == "eth" else Rpc((rpc_url,))

    t_load = time.perf_counter()
    sigs = load_signatures()
    t_load = time.perf_counter() - t_load

    t_total = time.perf_counter()
    res = deep(rpc, addr, sigs) if mode == "deep" else quick(rpc, addr, sigs)
    t_total = time.perf_counter() - t_total

    print(f"logic          : {res['logic']}")
    print(f"proxy          : {res['is_proxy']}")
    print(f"code_bytes     : {res['code_bytes']}")
    print(f"selectors      : {res['selectors']}")
    print(f"signature_load : {t_load * 1000:.1f} ms")
    for k, v in res["timings"].items():
        print(f"{k:16}: {v * 1000:.1f} ms")
    print(f"{'total':16}: {t_total * 1000:.1f} ms")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
