use crate::proxy;
use crate::rpc::Rpc;
use crate::scan_mode::ScanMode;
use crate::selectors;
use crate::strings;
use crate::vm::Vm;
use std::time::Instant;

pub fn probe(
    rpc: &mut Rpc,
    chain: &str,
    addr: &str,
    mode: &ScanMode,
    extra: &[String],
    timings: bool,
) -> Result<(), String> {
    let addr = normalize_addr(addr)?;
    let code = rpc.code(&addr)?;
    if code == "0x" || code.is_empty() {
        println!("[FAIL] {addr} has no code (EOA or wrong chain)");
        return Ok(());
    }
    let code_bytes = selectors::decode(&code)?;

    println!("[TARGET] {addr} on {chain}");
    println!("[CODE]   {} bytes", code_bytes.len());

    // resolve-only modes want a clean stream; everything else benefits from
    // the raw string dump
    let quiet = *mode == ScanMode::Proxy || *mode == ScanMode::Events;
    if !quiet {
        let strs = strings::extract(&code_bytes);
        if !strs.is_empty() {
            println!("\n[STRINGS]");
            for s in strs.iter().take(60) {
                println!("  {s}");
            }
        }
    }

    match mode {
        ScanMode::Quick => {
            // --timings prints a stage table matching bench/go and bench/python
            // so one harness compares all three ports with identical stages
            let t0 = Instant::now();
            detect_standards(rpc, &addr);
            let t_code = t0.elapsed().as_secs_f64() * 1000.0;

            let s = Instant::now();
            let logic = follow_proxy(rpc, &addr);
            let t_proxy = s.elapsed().as_secs_f64() * 1000.0;

            let s = Instant::now();
            read_slots(rpc, &logic, 0, 4);
            let t_slots = s.elapsed().as_secs_f64() * 1000.0;

            let total = t0.elapsed().as_secs_f64() * 1000.0;
            if timings {
                println!("\n[TIMINGS]");
                println!("eth_getCode     : {t_code:.1} ms");
                println!("proxy_resolve   : {t_proxy:.1} ms");
                println!("storage_0_4     : {t_slots:.1} ms");
                println!("total           : {total:.1} ms");
            }
        }
        ScanMode::Deep => {
            detect_standards(rpc, &addr);
            let logic = follow_proxy(rpc, &addr);
            // the implementation holds the selectors and the auth checks
            let logic_code = if logic != addr {
                rpc.code(&logic).unwrap_or_else(|_| code.clone())
            } else {
                code.clone()
            };
            let logic_bytes = selectors::decode(&logic_code)?;
            let sels = selectors::extract_selectors(&logic_bytes);
            println!("\n[SELECTORS] {} unique", sels.len());
            for s in &sels {
                println!("  0x{}  {}", selectors::hex4(s), selectors::label(s));
            }
            find_greedy(rpc, &addr, &sels);
            find_unauthenticated(rpc, &addr, &sels);
            find_number_gate(&code_bytes);
            read_slots(rpc, &addr, 0, 32);
            simulate(rpc, &addr, &code);
        }
        ScanMode::Slot => {
            let req = parse_slots(extra)?;
            if req.is_empty() {
                read_slots(rpc, &addr, 0, 4);
            } else {
                for s in &req {
                    read_slots(rpc, &addr, *s, 1);
                }
            }
        }
        ScanMode::Proxy => {
            // resolve-only mode: print the stack without running the probes.
            // Useful on its own to confirm a target is a proxy before a deep
            // pass, or to script against (one line per layer).
            let chain = proxy::resolve_chain(rpc, &addr)?;
            if chain.len() <= 1 {
                println!("logic contract (not a proxy)");
            } else {
                for layer in &chain {
                    let tag = match &layer.kind {
                        proxy::ProxyKind::Eip1967 => "eip1967",
                        proxy::ProxyKind::Eip1822 => "eip1822",
                        proxy::ProxyKind::Beacon => "beacon",
                        proxy::ProxyKind::Clone => "clone1167",
                        proxy::ProxyKind::Fallback(f) => f,
                        proxy::ProxyKind::DiamondFacet => "diamond",
                        proxy::ProxyKind::Logic => "logic",
                    };
                    println!(
                        "{tag} 0x{} 0x{}",
                        addr_low(&layer.via),
                        addr_low(&layer.target)
                    );
                }
                println!("# terminal: 0x{}", addr_low(&chain.last().unwrap().target));
            }
        }
        ScanMode::Events => {
            // recent events: the actors that called privileged functions or
            // moved funds. Falls back from head when no range is given.
            let n = extra
                .first()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(1000);
            let head = rpc.block_number()?;
            let from = head.saturating_sub(n);
            let logs = rpc.logs(&addr, from, head)?;
            if logs.is_empty() {
                println!("\n[EVENTS] none in blocks {from}..{head}");
            } else {
                println!("\n[EVENTS] {} logs in blocks {from}..{head}", logs.len());
                for log in logs.iter().take(200) {
                    let ev = proxy::decode_event(log);
                    let args = if ev.args.is_empty() {
                        String::new()
                    } else {
                        format!("  {}", ev.args.join(" "))
                    };
                    let blk =
                        u64::from_str_radix(log.block.trim_start_matches("0x"), 16).unwrap_or(0);
                    println!("  #{blk} {}  {args}", ev.signature);
                }
            }
        }
        ScanMode::Scan => unreachable!(),
        ScanMode::Replay => {
            // replay a specific selector in the local VM with state seeded from
            // the chain. This is what turns "[UNAUTHENTICATED?]" into a proof.
            let sel_arg = extra.first().ok_or_else(|| {
                "replay needs a selector: evmghost <RPC> <ADDR> replay 0x40c10f19".to_string()
            })?;
            let sel = selectors::parse_selector(sel_arg)
                .ok_or_else(|| format!("bad selector: {sel_arg}"))?;
            let logic = follow_proxy(rpc, &addr);
            let code = if logic != addr {
                rpc.code(&logic)?
            } else {
                code.clone()
            };
            let _bytes = selectors::decode(&code)?;
            let label = selectors::label(&sel);
            let arity = arg_count(&label);
            let mut calldata = selectors::hex4(&sel);
            calldata.push_str(&"0".repeat(64 * arity));
            println!(
                "\n[REPLAY] 0x{} {label}  ({arity} args)",
                selectors::hex4(&sel)
            );
            let mut vm = Vm::new(&code, &format!("0x{calldata}"))?;
            vm.storage.seed_from_rpc(rpc, &logic, 64)?;
            let res = vm.run(30_000_000);
            println!("  result      : {res:?}");
            println!("  gas_used    : {}", vm.gas_used);
            println!("  selfdestruct: {}", vm.selfdestruct);
            if !vm.storage_writes.is_empty() {
                println!("  storage writes:");
                for (k, v) in vm.storage_writes.iter().take(20) {
                    println!("    {} := {}", hex::encode(k), hex::encode(v));
                }
            }
            if !vm.logs.is_empty() {
                println!("  logs:");
                for l in vm.logs.iter().take(20) {
                    println!("    {l}");
                }
            }
            if !vm.returndata.is_empty() {
                println!("  returndata: 0x{}", hex::encode(&vm.returndata));
            }
            if !vm.revert_data.is_empty() {
                let dec = decode_revert_reason(&vm.revert_data);
                println!("  revert data: 0x{} {dec}", hex::encode(&vm.revert_data));
            }
        }
    }

    Ok(())
}

/// Read well-known view functions without an ABI. Owner/paused/reserves are
/// the highest-value reads for planning an exploit.
fn detect_standards(rpc: &mut Rpc, addr: &str) {
    let checks = [
        ("name", "0x06fdde03"),
        ("symbol", "0x95d89b41"),
        ("decimals", "0x313ce567"),
        ("totalSupply", "0x18160ddd"),
        ("owner", "0x8da5cb5b"),
        ("paused", "0x5c975abb"),
        ("getReserves", "0x0902f1ac"),
        ("claimable", "0x5be1ea5c"),
    ];

    let mut hits = Vec::new();
    for (name, sig) in checks {
        if let Ok(res) = rpc.eth_call(addr, sig, "latest") {
            if res != "0x" && !res.is_empty() {
                let bytes = selectors::decode(&res).unwrap_or_default();
                if bytes.len() >= 32 {
                    let raw = &bytes[..32];
                    let low = u128::from_be_bytes(raw[16..32].try_into().unwrap_or([0u8; 16]));
                    let addr_hex = hex::encode(&raw[12..]);
                    let pretty = if low > 0 && low < 10_000_000_000 {
                        format!("{low} (or 0x{addr_hex})")
                    } else {
                        format!("0x{addr_hex}")
                    };
                    hits.push((name, pretty));
                }
            }
        }
    }
    if !hits.is_empty() {
        println!("\n[ABI-LESS READS] live eth_call, no source needed");
        for (n, v) in &hits {
            println!("  {n}() = {v}");
        }
    }
}

/// Machine-readable report for `--json`. Covers the findings that matter for
/// scripting: the resolved proxy stack, extracted selectors, and the
/// auth-probe results. Everything else stays in the human form.
pub fn json_report(rpc: &mut Rpc, addr: &str, mode: &ScanMode) -> Result<(), String> {
    use serde_json::json;
    // proxy resolution is part of every report: knowing whether the target is
    // a proxy and where its logic lives is the first thing a pipeline needs
    let chain = proxy::resolve_chain(rpc, addr)?;
    let logic = chain
        .last()
        .map(|l| l.target.clone())
        .unwrap_or_else(|| addr.to_string());
    let stack: Vec<serde_json::Value> = chain
        .iter()
        .map(|l| {
            let kind = match &l.kind {
                proxy::ProxyKind::Eip1967 => "eip1967",
                proxy::ProxyKind::Eip1822 => "eip1822",
                proxy::ProxyKind::Beacon => "beacon",
                proxy::ProxyKind::Clone => "clone1167",
                proxy::ProxyKind::Fallback(f) => f,
                proxy::ProxyKind::DiamondFacet => "diamond",
                proxy::ProxyKind::Logic => "logic",
            };
            json!({ "kind": kind, "from": l.via.to_lowercase(), "to": l.target.to_lowercase() })
        })
        .collect();

    let report = match mode {
        ScanMode::Proxy => json!({
            "address": addr.to_lowercase(),
            "proxy_stack": stack,
            "logic": logic.to_lowercase(),
        }),
        _ => {
            // deep/quick: add selectors and the auth probes from the logic
            let code = rpc.code(&logic)?;
            let bytes = selectors::decode(&code)?;
            let sels = selectors::extract_selectors(&bytes);
            let sel_json: Vec<serde_json::Value> = sels
                .iter()
                .map(|s| {
                    json!({
                        "selector": format!("0x{}", selectors::hex4(s)),
                        "label": selectors::label(s),
                    })
                })
                .collect();
            json!({
                "address": addr.to_lowercase(),
                "proxy_stack": stack,
                "logic": logic.to_lowercase(),
                "code_bytes": bytes.len(),
                "selectors": sel_json,
            })
        }
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    );
    Ok(())
}

/// Resolve the proxy stack and follow it to the logic contract. Probes are
/// then run against the implementation, which is where selectors and access
/// control actually live. Returns the terminal logic address (which equals
/// `addr` when the target is not a proxy).
fn follow_proxy(rpc: &mut Rpc, addr: &str) -> String {
    match proxy::resolve_chain(rpc, addr) {
        Ok(chain) => {
            if chain.len() > 1 {
                println!("\n[PROXY] stack depth {}", chain.len() - 1);
                for layer in &chain {
                    let tag = match &layer.kind {
                        proxy::ProxyKind::Eip1967 => "EIP-1967",
                        proxy::ProxyKind::Eip1822 => "EIP-1822 UUPS",
                        proxy::ProxyKind::Beacon => "EIP-1967 beacon",
                        proxy::ProxyKind::Clone => "EIP-1167 clone",
                        proxy::ProxyKind::Fallback(f) => f,
                        proxy::ProxyKind::DiamondFacet => "diamond facet",
                        proxy::ProxyKind::Logic => "logic",
                    };
                    println!(
                        "  {tag}: 0x{} -> 0x{}",
                        addr_low(&layer.via),
                        addr_low(&layer.target)
                    );
                }
                let logic = chain.last().expect("chain nonempty").target.clone();
                println!("  probing implementation: 0x{}", addr_low(&logic));
                logic
            } else {
                addr.to_string()
            }
        }
        Err(e) => {
            println!("\n[PROXY] resolution failed: {e}");
            addr.to_string()
        }
    }
}

/// lowercase hex address without the leading 0x, for compact display
fn addr_low(a: &str) -> String {
    a.strip_prefix("0x").unwrap_or(a).to_lowercase()
}

/// Storage slot dumper; interprets each 32-byte word as address | uint128 pair.
fn read_slots(rpc: &mut Rpc, addr: &str, start: u64, count: u64) {
    println!("\n[STORAGE] slots {start}..{}", start + count - 1);
    for slot in start..start + count {
        match rpc.storage(addr, slot, None) {
            Ok(v) if !is_zero_word(&v) => print_slot(slot, &v),
            Ok(_) => {}
            Err(e) => println!("  slot {slot}: [FAIL] {e}"),
        }
    }
}

fn is_zero_word(hex_word: &str) -> bool {
    let s = hex_word.strip_prefix("0x").unwrap_or(hex_word);
    s.is_empty() || s.bytes().all(|c| c == b'0')
}

fn print_slot(slot: u64, hex_word: &str) {
    let bytes = selectors::decode(hex_word).unwrap_or_default();
    if bytes.len() != 32 {
        println!("  slot {slot}: {hex_word} (short)");
        return;
    }
    let addr = format!("0x{}", hex::encode(&bytes[12..]));
    let low = u128::from_be_bytes(bytes[16..32].try_into().unwrap_or([0u8; 16]));
    let high = u128::from_be_bytes(bytes[..16].try_into().unwrap_or([0u8; 16]));
    println!("  slot {slot}: {hex_word} | addr? {addr} | low128 {low} | high128 {high}");
}

/// Selectors whose output changes when an address arg changes — the signature
/// of missing-auth read primitives (IDOR-style drain primitives).
/// Detect getters whose output depends on a caller-supplied address without
/// any access control — the IDOR pattern for on-chain data. A value that
/// changes with the address arg is only interesting when both values are
/// non-zero, otherwise it is just "this address has nothing".
fn find_greedy(rpc: &mut Rpc, addr: &str, sels: &[[u8; 4]]) {
    let mut greedy = Vec::new();
    for s in sels {
        // ABI: selector(4) + 12 zero bytes + 20-byte address. Word 1 = 0..32.
        let mut zero = [0u8; 36];
        zero[..4].copy_from_slice(s);
        let Ok(r0) = rpc.eth_call(addr, &format!("0x{}", hex::encode(zero)), "latest") else {
            continue;
        };
        if r0 == "0x" || r0.is_empty() {
            continue;
        };
        let mut one = zero;
        // a real-looking but non-special address: 0x1111...1111
        for b in one[16..36].iter_mut() {
            *b = 0x11;
        }
        let Ok(r1) = rpc.eth_call(addr, &format!("0x{}", hex::encode(one)), "latest") else {
            continue;
        };
        // only report when the address arg yields a *different nonzero* value:
        // a getter returning zero for an empty address is normal, not IDOR
        if r0 != r1 && r1 != "0x" && !r1.is_empty() {
            greedy.push((selectors::hex4(s), r0, r1));
        }
    }
    if !greedy.is_empty() {
        println!("\n[GREEDY] output depends on a single address arg — check auth on these");
        for (sel, a, b) in &greedy {
            println!("  0x{sel}: default -> {a} | addr -> {b}");
        }
    }
}

/// An eth_call from the default (non-owner, zero-balance) caller is the
/// cheapest reliable probe for missing access control: a state-changing
/// function that does not revert for a nobody is unauthenticated. eth_call
/// cannot mutate state, so success means "reachable by anyone", not
/// "exploitable" — but it is the cheapest way to shortlist targets.
fn find_unauthenticated(rpc: &mut Rpc, addr: &str, sels: &[[u8; 4]]) {
    // names that SHOULD be gated — calling them as a nobody is the red flag
    // (lowercase — the label is lowercased before comparison)
    const GATED_HINTS: [&str; 12] = [
        "mint",
        "burn",
        "withdraw",
        "claim",
        "kill",
        "pause",
        "unpause",
        "execute",
        "grantrole",
        "revokerole",
        "set",
        "transferownership",
    ];
    // names that are permissionless by design; reporting them is noise
    // (lowercase — the label is lowercased before comparison)
    const PERMISSIONLESS: [&str; 8] = [
        "transfer",
        "transferfrom",
        "approve",
        "deposit",
        "swap",
        "name",
        "symbol",
        "decimals",
    ];
    // pure getters: never interesting for access control (lowercase — the
    // label is lowercased before comparison)
    const VIEWS: [&str; 6] = [
        "owner",
        "totalsupply",
        "balanceof",
        "allowance",
        "paused",
        "getreserves",
    ];
    let mut gated = Vec::new();
    let mut open: Vec<([u8; 4], String, String)> = Vec::new();
    for s in sels {
        let label = selectors::label(s);
        let lower = label.to_lowercase();
        let named = !lower.starts_with("not in 4byte");
        if named && PERMISSIONLESS.iter().any(|h| lower.starts_with(h)) {
            continue;
        }
        if named && VIEWS.iter().any(|h| lower.starts_with(h)) {
            continue;
        }
        let arity = arg_count(&label);
        let mut calldata = selectors::hex4(s);
        calldata.push_str(&"0".repeat(64 * arity));
        let calldata = format!("0x{calldata}");
        let Ok(res) = rpc.eth_call(addr, &calldata, "latest") else {
            continue;
        };
        if named && GATED_HINTS.iter().any(|h| lower.starts_with(h)) {
            gated.push((label, res));
        } else {
            open.push((*s, label, res));
        }
    }
    if !gated.is_empty() {
        println!("\n[UNAUTHENTICATED?] gated-name selectors that did NOT revert for a nobody");
        println!("  (eth_call cannot change state — this means reachable, not exploitable)");
        for (label, res) in &gated {
            let r = if res == "0x" || res.is_empty() {
                "no return data"
            } else {
                res
            };
            println!("  {label}: {r}");
        }
    }
    if !open.is_empty() {
        println!("\n[REACHABLE] unnamed/other selectors that did not revert");
        for (sel, label, res) in open.iter().take(12) {
            let r = if res == "0x" || res.is_empty() {
                "no return data"
            } else {
                res
            };
            println!("  0x{}  {label}: {r}", selectors::hex4(sel));
        }
    }
}

/// Count the comma-separated params in a labelled signature so the probe can
/// pad the right number of zeroed words. Returns 0 for unknown selectors
/// (which probe with a bare selector, the safest fallback).
fn arg_count(label: &str) -> usize {
    let Some(start) = label.find('(') else {
        return 0;
    };
    let inner = &label[start + 1..label.len().saturating_sub(1)];
    if inner.is_empty() {
        return 0;
    }
    inner.split(',').count()
}

/// NUMBER opcode gating — "unlock after block X" logic, often inverted or
/// wrong-typed.
fn find_number_gate(code: &[u8]) {
    if code.contains(&0x43) {
        let pos = code.iter().position(|&b| b == 0x43).unwrap_or(0);
        println!("\n[INFO] NUMBER opcode at byte {pos} — block-height gating present");
    }
}

/// Run the runtime bytecode in the built-in EVM with real state seeded from
/// the chain so the replay follows the same branches as on-chain execution.
/// Empty calldata exercises the dispatcher; callers replay specific selectors
/// through the library API.
fn simulate(rpc: &mut Rpc, addr: &str, code_hex: &str) {
    println!("\n[VM] local bytecode simulation (state seeded from chain)");
    let mut vm = match Vm::new(code_hex, "0x") {
        Ok(v) => v,
        Err(e) => {
            println!("  [FAIL] vm init: {e}");
            return;
        }
    };
    if let Err(e) = vm.storage.seed_from_rpc(rpc, addr, 64) {
        println!("  [WARN] could not seed storage: {e}");
    }
    let res = vm.run(30_000_000);
    println!("  result      : {res:?}");
    println!("  gas_used    : {}", vm.gas_used);
    println!("  selfdestruct: {}", vm.selfdestruct);
    if !vm.storage_writes.is_empty() {
        println!("  storage writes on entry:");
        for (k, v) in vm.storage_writes.iter().take(20) {
            println!("    {} := {}", hex::encode(k), hex::encode(v));
        }
    }
    if !vm.logs.is_empty() {
        println!("  logs:");
        for l in vm.logs.iter().take(20) {
            println!("    {l}");
        }
    }
    if !vm.returndata.is_empty() {
        println!("  returndata: 0x{}", hex::encode(&vm.returndata));
    }
    if !vm.revert_data.is_empty() {
        let dec = decode_revert_reason(&vm.revert_data);
        println!("  revert data: 0x{} {}", hex::encode(&vm.revert_data), dec);
    }
}

/// Decode a standard Solidity revert string from REVERT data, which is
/// `selector(string) + offset + len + bytes`. Unprintable data is skipped.
fn decode_revert_reason(data: &[u8]) -> String {
    if data.len() < 68 {
        return String::new();
    }
    // 4-byte selector 0x08c379a0 = Error(string)
    if data[0..4] != [0x08, 0xc3, 0x79, 0xa0] {
        return String::new();
    }
    let len = u64::from_be_bytes(data[36..44].try_into().unwrap_or([0u8; 8])) as usize;
    let start = 68;
    let end = (start + len).min(data.len());
    if end <= start {
        return String::new();
    }
    let s = &data[start..end];
    if s.iter().all(|&b| (0x20..0x7f).contains(&b)) {
        format!("\"{}\"", String::from_utf8_lossy(s))
    } else {
        String::new()
    }
}

fn normalize_addr(a: &str) -> Result<String, String> {
    if !a.starts_with("0x") || a.len() != 42 {
        return Err("address must be 0x + 40 hex chars".into());
    }
    Ok(a.to_lowercase())
}

fn parse_slots(extra: &[String]) -> Result<Vec<u64>, String> {
    let mut out = Vec::new();
    for a in extra {
        let s = a.trim_start_matches("0x");
        let n = s
            .parse::<u64>()
            .or_else(|_| u64::from_str_radix(s, 16).map_err(|e| format!("bad slot {a}: {e}")))?;
        out.push(n);
    }
    Ok(out)
}

/// Passive scan: walk blocks, flag freshly deployed contracts whose runtime
/// contains selfdestruct / delegatecall / tx.origin.
pub fn passive_scan(rpc: &mut Rpc, chain: &str, extra: &[String]) -> Result<(), String> {
    if extra.len() < 2 {
        return Err("scan needs a block range: --scan 19000000 19001000".into());
    }
    let from = extra[0]
        .parse::<u64>()
        .map_err(|e| format!("from block: {e}"))?;
    let to = extra[1]
        .parse::<u64>()
        .map_err(|e| format!("to block: {e}"))?;
    if to < from {
        return Err("to-block must be >= from-block".into());
    }
    println!("[SCAN] blocks {from}..{to} on {chain}");

    let mut hits = 0;
    for n in from..=to {
        let blk = rpc.block_tx(n)?;
        let Some(txs) = blk["transactions"].as_array() else {
            continue;
        };
        for t in txs {
            let to = t["to"].as_str().unwrap_or("");
            if !to.is_empty() {
                continue; // contract creation only
            }
            let input = t["input"].as_str().unwrap_or("0x");
            let deployer = t["from"].as_str().unwrap_or("");
            let hash = t["hash"].as_str().unwrap_or("");
            let code = selectors::decode(input).unwrap_or_default();
            if code.len() < 10 {
                continue;
            }
            let runtime = extract_runtime(&code);
            if runtime.len() < 20 {
                continue;
            }
            let mut flags = Vec::new();
            if runtime.contains(&0xff) {
                flags.push("selfdestruct");
            }
            if runtime.contains(&0xf4) {
                flags.push("delegatecall");
            }
            if runtime.contains(&0x32) {
                flags.push("tx.origin");
            }
            if !flags.is_empty() {
                hits += 1;
                println!("\n[HIT] block {n} deployer {deployer}");
                println!("  tx   {hash}");
                println!("  flags: {}", flags.join(", "));
            }
        }
    }
    println!("\n[SCAN] done, {hits} interesting deployments");
    Ok(())
}

fn extract_runtime(deploy: &[u8]) -> &[u8] {
    // Deployment bytecode = init code + runtime + constructor args. The runtime
    // is what runs after deployment; find it after the last RETURN (0xf3).
    let last = deploy.iter().rposition(|&b| b == 0xf3);
    match last {
        Some(i) if i + 1 < deploy.len() => &deploy[i + 1..],
        _ => &deploy[deploy.len()..],
    }
}
