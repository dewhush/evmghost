use rustc_hex::FromHex;

/// Selector → canonical signature table. The canonical 4byte dataset ships
/// selector + deployment frequency only (no names), so two sources are used:
///   1. a hardcoded table for the high-value signatures every target has
///   2. the embedded 289k-entry dataset to confirm a selector is real and to
///      report how often it has been deployed (a proxy for "standard" vs
///      bespoke/target-specific code)
const EMBEDDED: &str = include_str!("../signatures.txt");

/// Extract 4-byte function selectors from deployed runtime bytecode.
/// PUSHn payloads are skipped so selectors embedded as immediates inside
/// other pushes are not mistaken for dispatch entries.
pub fn extract_selectors(code: &[u8]) -> Vec<[u8; 4]> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut i = 0;
    while i < code.len() {
        if code[i] == 0x63 && i + 4 < code.len() {
            // PUSH4 followed by the selector
            let mut sel = [0u8; 4];
            sel.copy_from_slice(&code[i + 1..i + 5]);
            if sel != [0, 0, 0, 0] && sel != [0xff, 0xff, 0xff, 0xff] && seen.insert(sel) {
                out.push(sel);
            }
            i += 5;
            continue;
        }
        let op = code[i];
        i += 1;
        if (0x60..=0x7f).contains(&op) {
            i += (op as usize) - 0x5f;
        }
    }
    out
}

pub fn hex4(sel: &[u8; 4]) -> String {
    hex::encode(sel)
}

/// Parse a selector from either "0xdeadbeef" or "deadbeef" form.
pub fn parse_selector(s: &str) -> Option<[u8; 4]> {
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    let b = hex::decode(s).ok()?;
    if b.len() != 4 {
        return None;
    }
    let mut out = [0u8; 4];
    out.copy_from_slice(&b);
    Some(out)
}

/// Well-known signatures. These are the ones worth naming inline because they
/// appear in nearly every target and drive the exploit hypotheses.
fn known(sel_hex: &str) -> &'static str {
    match sel_hex {
        "8da5cb5b" => "owner()",
        "06fdde03" => "name()",
        "95d89b41" => "symbol()",
        "313ce567" => "decimals()",
        "70a08231" => "balanceOf(address)",
        "a9059cbb" => "transfer(address,uint256)",
        "23b872dd" => "transferFrom(address,address,uint256)",
        "095ea7b3" => "approve(address,uint256)",
        "dd62ed3e" => "allowance(address,address)",
        "18160ddd" => "totalSupply()",
        "2e1a7d4d" => "withdraw(uint256)",
        "3ccfd60b" => "withdraw()",
        "4e71d92d" => "claim()",
        "f2fde38b" => "transferOwnership(address)",
        "715018a6" => "renounceOwnership()",
        "5c975abb" => "paused()",
        "8456cb59" => "pause()",
        "3f4ba83a" => "unpause()",
        "40c10f19" => "mint(address,uint256)",
        "79cc6790" => "burnFrom(address,uint256)",
        "42966c68" => "burn(uint256)",
        "2f2ff15d" => "grantRole(bytes32,address)",
        "d547741f" => "revokeRole(bytes32,address)",
        "91d14854" => "hasRole(bytes32,address)",
        "0902f1ac" => "getReserves()",
        "022c0d9f" => "swap(uint256,uint256,address,bytes)",
        "fb3bdb41" => "skim(address)",
        "30adf81f" => "sync()",
        "f305d719" => "addLiquidityETH(address,uint256,uint256,uint256,address,uint256)",
        "7ff36ab5" => "swapExactETHForTokens(uint256,uint256,address[],address,uint256)",
        "38ed1739" => "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)",
        "414bf389" => "swapExactTokensForTokensSupportingFeeOnTransferTokens(...)",
        "5ae401dc" => "execute(bytes,bytes)",
        "1cff79cd" => "proxyCall(bytes,bytes)",
        "41c0e1b5" => "kill()",
        "e2bbb158" => "mintTokensTo(address)",
        "9189fed5" => "getPrice()",
        "5be1ea5c" => "claimable(address)",
        "26782247" => "round()",
        _ => "",
    }
}

/// Best-effort label: known name when we have it, otherwise mark it as a
/// confirmed on-chain selector with its deployment count (high count =
/// standard library code, low/1 = bespoke target-specific function — the more
/// interesting attack surface).
pub fn label(sel: &[u8; 4]) -> String {
    let h = hex4(sel);
    let name = known(&h);
    if !name.is_empty() {
        return name.to_string();
    }
    match embedded_count(&h) {
        Some(n) => format!("unknown selector, deployed {n}x on-chain"),
        None => "not in 4byte dataset (bespoke/private)".to_string(),
    }
}

/// Deployment frequency from the embedded dataset, or None when the selector
/// is absent (a private or new signature — worth manual review).
fn embedded_count(needle: &str) -> Option<u64> {
    for line in EMBEDDED.lines() {
        if let Some(rest) = line.strip_prefix("0x") {
            if let Some((sig, count)) = rest.split_once('-') {
                if sig == needle {
                    return count.trim().parse::<u64>().ok();
                }
            }
        }
    }
    None
}

/// Decode hex string with optional 0x prefix → bytes.
pub fn decode(hex_str: &str) -> Result<Vec<u8>, String> {
    let s = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    s.from_hex::<Vec<u8>>()
        .map_err(|e| format!("hex decode: {e}"))
}
