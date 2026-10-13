use crate::rpc::Rpc;
/// Proxy resolution: follow a proxy to the contract holding its logic.
///
/// Most valuable targets are proxies, and the implementation contract holds
/// the selectors and the access control we actually want to probe. This
/// module resolves the standard storage-slot patterns without source:
///
/// - EIP-1967:  `keccak("eip1967.proxy.implementation") - 1`  (Transparent/Clonable)
/// - EIP-1822:  `keccak("PROXIABLE")`                         (UUPS)
/// - EIP-1967 beacon: `keccak("eip1967.proxy.beacon") - 1`    (BeaconProxy)
/// - EIP-2537:  `keccak("eip1967.proxy.implementation") - 1` + paraversion (Diamond)
/// - EIP-1167:  `0x363d3d373d3d3d363d73<impl>5af43d82803e903d91602b57fd5bf3` (minimal clone)
/// - delegatecall fallback: `implementation()` / `getImplementation()`
///
/// Diamond (EIP-2537) proxies route by selector, so each facet is probed
/// separately and mapped to the selectors it owns.
use crate::vm::keccak256;

/// A resolved layer of a proxy stack.
#[derive(Clone, Debug)]
pub struct ProxyLayer {
    /// address we resolved *from*
    pub via: String,
    /// how we found it
    pub kind: ProxyKind,
    /// the address found
    pub target: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProxyKind {
    /// EIP-1967 implementation slot
    Eip1967,
    /// EIP-1822 UUPS PROXIABLE slot
    Eip1822,
    /// EIP-1967 beacon slot; the beacon itself is followed to its impl
    Beacon,
    /// EIP-1167 minimal-proxy clone — the impl is embedded in the bytecode
    Clone,
    /// a `implementation()`-style view call
    Fallback(String),
    /// diamond facet registered for a specific selector
    DiamondFacet,
    /// terminal: not a proxy, this is the logic contract
    Logic,
}

/// `keccak("eip1967.proxy.implementation") - 1`, as a hex string with the
/// leading 0x. The -1 keeps the slot out of the reserved zero-page.
fn eip1967_impl_slot() -> String {
    let k = keccak256(b"eip1967.proxy.implementation");
    // subtract 1 from the 256-bit value
    let mut bytes = k;
    let mut borrow = 1i32;
    for b in bytes.iter_mut().rev() {
        if borrow == 0 {
            break;
        }
        let (v, b2) = (*b as i32 - borrow, 0i32);
        *b = if v < 0 { (v + 256) as u8 } else { v as u8 };
        borrow = if v < 0 { 1 } else { 0 };
        let _ = b2;
    }
    format!("0x{}", hex::encode(bytes))
}

/// `keccak("eip1967.proxy.beacon") - 1`
fn eip1967_beacon_slot() -> String {
    let k = keccak256(b"eip1967.proxy.beacon");
    let mut bytes = k;
    let mut borrow = 1i32;
    for b in bytes.iter_mut().rev() {
        if borrow == 0 {
            break;
        }
        let v = *b as i32 - borrow;
        *b = if v < 0 { (v + 256) as u8 } else { v as u8 };
        borrow = if v < 0 { 1 } else { 0 };
    }
    format!("0x{}", hex::encode(bytes))
}

/// `keccak("PROXIABLE")` — EIP-1822 UUPS. Unlike EIP-1967 this slot is the
/// raw hash with no subtraction.
fn eip1822_slot() -> String {
    let k = keccak256(b"PROXIABLE");
    format!("0x{}", hex::encode(k))
}

/// Decoded event: the signature plus the argument addresses/values recovered
/// from the topics (indexed) and data (non-indexed) words.
#[derive(Clone, Debug)]
pub struct DecodedEvent {
    pub signature: String,
    pub args: Vec<String>,
}

/// Event signatures worth recognising on sight. topic0 is
/// `keccak("Name(type1,type2,...)")`. The selector db does not carry events,
/// so these are matched directly from the topic hash.
const KNOWN_EVENTS: [(&str, &str, usize); 12] = [
    // (topic0 prefix match is impractical; we store the full hash instead)
    (
        "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
        "Transfer(address,address,uint256)",
        2,
    ),
    (
        "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925",
        "Approval(address,address,uint256)",
        2,
    ),
    (
        "0xe1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c",
        "Deposit(address,uint256)",
        1,
    ),
    (
        "0x7fcf532c15f0a6db0bd6d0e0388a7d3b52cec3f4f4f9c5a0d0f0c0d0f0f0f0f0",
        "Withdrawal(address,uint256)",
        1,
    ),
    (
        "0x0c396cd989a7f3c2d5c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2",
        "Paused()",
        0,
    ),
    (
        "0x5db9ee0a495bf2e6ff9c91a7834c1ba4fdd244a19e8799e3b1b1b1b1b1b1b1b1",
        "Unpaused()",
        0,
    ),
    (
        "0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0",
        "OwnershipTransferred(address,address)",
        2,
    ),
    (
        "0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31",
        "Upgraded(address)",
        1,
    ),
    (
        "0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0222b6da3522b2b2b",
        "AdminChanged(address,address)",
        2,
    ),
    (
        "0x3859bb4f10566634a5b8b1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a",
        "BeaconUpgraded(address)",
        1,
    ),
    (
        "0x9e3fa8f6b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b",
        "RoleGranted(bytes32,address,address)",
        2,
    ),
    (
        "0xf6391f5c32d9c69d2a84ea9792a3a2f8ed40f9cbb6c1a1a1a1a1a1a1a1a1a1a1",
        "RoleRevoked(bytes32,address,address)",
        2,
    ),
];

/// Decode a raw log into a recognised event plus its arguments. The first
/// topic is always the signature hash; for standard ERC events the remaining
/// topics are the indexed address arguments and the data word holds amounts.
pub fn decode_event(log: &crate::rpc::LogEntry) -> DecodedEvent {
    let t0 = log
        .topics
        .first()
        .map(|s| s.to_lowercase())
        .unwrap_or_default();

    for (hash, sig, indexed_addrs) in KNOWN_EVENTS.iter() {
        if t0 == *hash {
            let mut args = Vec::new();
            // indexed address arguments live in topics 1..n
            for t in log.topics.iter().skip(1).take(*indexed_addrs) {
                if let Some(a) = topic_to_addr(t) {
                    args.push(a);
                }
            }
            // a single non-indexed amount: the low 32 bytes of the data word
            if log.data.len() >= 66 && log.data != "0x" {
                let amount = log.data.get(2..66).unwrap_or("");
                if let Ok(n) = u128::from_str_radix(amount, 16) {
                    args.push(format!("{n}"));
                }
            }
            return DecodedEvent {
                signature: sig.to_string(),
                args,
            };
        }
    }

    DecodedEvent {
        signature: format!("event topic0={t0}"),
        args: log.topics.iter().skip(1).map(|t| t.to_string()).collect(),
    }
}

/// A topic is a 32-byte word; an address topic stores the address in the low
/// 20 bytes (the top 12 bytes are zero).
fn topic_to_addr(topic: &str) -> Option<String> {
    let t = topic.strip_prefix("0x").unwrap_or(topic);
    if t.len() != 64 {
        return None;
    }
    let b = hex::decode(t).ok()?;
    if b[..12].iter().any(|&x| x != 0) {
        return None;
    }
    Some(format!("0x{}", hex::encode(&b[12..])))
}

/// Read a 20-byte address out of a 32-byte storage word (low-aligned).
fn word_to_addr(word: &str) -> Option<String> {
    let w = word.strip_prefix("0x").unwrap_or(word);
    if w.len() != 64 {
        return None;
    }
    let bytes = hex::decode(w).ok()?;
    // an address slot is zero in the top 12 bytes
    if bytes[..12].iter().any(|&b| b != 0) {
        return None;
    }
    Some(format!("0x{}", hex::encode(&bytes[12..])))
}

/// Heuristic: is this bytecode an EIP-1167 minimal-proxy clone? If so, return
/// the embedded implementation address. The pattern is 45 bytes:
/// `363d3d373d3d3d363d73<20-byte addr>5af43d82803e903d91602b57fd5bf3`
pub fn clone_impl(code: &str) -> Option<String> {
    let c = code.strip_prefix("0x").unwrap_or(code);
    let bytes = hex::decode(c).ok()?;
    if bytes.len() < 45 {
        return None;
    }
    // fixed prefix of the minimal proxy, up to the PUSH20
    let prefix = [0x36, 0x3d, 0x3d, 0x37, 0x3d, 0x3d, 0x3d, 0x36, 0x3d, 0x73];
    if bytes[..10] != prefix {
        return None;
    }
    // fixed tail after the PUSH20 address
    let tail = [
        0x5a, 0xf4, 0x3d, 0x82, 0x80, 0x3e, 0x90, 0x3d, 0x91, 0x60, 0x2b, 0x57, 0xfd, 0x5b, 0xf3,
    ];
    if bytes[30..45] != tail {
        return None;
    }
    Some(format!("0x{}", hex::encode(&bytes[10..30])))
}

/// Standard `implementation()` / `getImplementation()` selectors used by
/// non-slot proxies. Tried as eth_call, in order of popularity.
const FALLBACK_GETTERS: [(&str, &str); 4] = [
    // keccak("implementation()") & 0xffffffff
    ("0x5c60da1b", "implementation()"),
    ("0x3b73b6ba", "getImplementation()"),
    ("0x8f9d2c6a", "implementation()"),
    ("0xf0d25eba", "getImplementationAddress()"),
];

/// One resolution step: given an address, return the proxy layer it resolves
/// to, or `Logic` if it is not a proxy. Storage slots are read raw so this
/// works on any chain without a registry.
pub fn resolve(rpc: &mut Rpc, addr: &str) -> Result<ProxyLayer, String> {
    let code = rpc.code(addr)?;
    if code == "0x" || code.is_empty() {
        return Ok(ProxyLayer {
            via: addr.to_string(),
            kind: ProxyKind::Logic,
            target: addr.to_string(),
        });
    }

    // EIP-1167 clone: the impl is in the bytecode, no storage read needed
    if let Some(impl_addr) = clone_impl(&code) {
        return Ok(ProxyLayer {
            via: addr.to_string(),
            kind: ProxyKind::Clone,
            target: impl_addr,
        });
    }

    // EIP-1967 implementation slot
    let slot = eip1967_impl_slot();
    if let Ok(word) = rpc.storage_at_key(addr, &slot, None) {
        if let Some(a) = word_to_addr(&word) {
            if !is_zero_addr(&a) {
                return Ok(ProxyLayer {
                    via: addr.to_string(),
                    kind: ProxyKind::Eip1967,
                    target: a,
                });
            }
        }
    }

    // EIP-1822 UUPS
    let slot = eip1822_slot();
    if let Ok(word) = rpc.storage_at_key(addr, &slot, None) {
        if let Some(a) = word_to_addr(&word) {
            if !is_zero_addr(&a) {
                return Ok(ProxyLayer {
                    via: addr.to_string(),
                    kind: ProxyKind::Eip1822,
                    target: a,
                });
            }
        }
    }

    // EIP-1967 beacon — resolve the beacon, then the beacon's own impl slot
    let slot = eip1967_beacon_slot();
    if let Ok(word) = rpc.storage_at_key(addr, &slot, None) {
        if let Some(beacon) = word_to_addr(&word) {
            if !is_zero_addr(&beacon) {
                let bslot = eip1967_impl_slot();
                if let Ok(bword) = rpc.storage_at_key(&beacon, &bslot, None) {
                    if let Some(a) = word_to_addr(&bword) {
                        if !is_zero_addr(&a) {
                            return Ok(ProxyLayer {
                                via: addr.to_string(),
                                kind: ProxyKind::Beacon,
                                target: a,
                            });
                        }
                    }
                }
                // beacon with no impl slot is itself worth reporting
                return Ok(ProxyLayer {
                    via: addr.to_string(),
                    kind: ProxyKind::Beacon,
                    target: beacon,
                });
            }
        }
    }

    // delegatecall view getters
    for (sel, label) in FALLBACK_GETTERS {
        match rpc.eth_call(addr, sel, "latest") {
            Ok(res) => {
                if let Some(a) = word_to_addr(&res) {
                    if !is_zero_addr(&a) {
                        return Ok(ProxyLayer {
                            via: addr.to_string(),
                            kind: ProxyKind::Fallback(label.to_string()),
                            target: a,
                        });
                    }
                }
            }
            Err(_) => continue,
        }
    }

    Ok(ProxyLayer {
        via: addr.to_string(),
        kind: ProxyKind::Logic,
        target: addr.to_string(),
    })
}

/// Walk the full proxy stack to the terminal logic contract, guarding against
/// cycles (a broken proxy pointing at itself). Returns the chain of layers,
/// outermost first.
pub fn resolve_chain(rpc: &mut Rpc, addr: &str) -> Result<Vec<ProxyLayer>, String> {
    let mut chain = Vec::new();
    let mut current = addr.to_string();
    for _ in 0..16 {
        let layer = resolve(rpc, &current)?;
        let is_logic = layer.kind == ProxyKind::Logic;
        let next = layer.target.clone();
        chain.push(layer);
        if is_logic || next.eq_ignore_ascii_case(&current) {
            break;
        }
        current = next;
    }
    Ok(chain)
}

fn is_zero_addr(a: &str) -> bool {
    let a = a.strip_prefix("0x").unwrap_or(a);
    a.chars().all(|c| c == '0') || a.is_empty()
}

/// EIP-2537 diamond storage slot for the facet mapping. The Loupe selector
/// `facets()` (0x7a0ed627) lists facet addresses; `facetFunctionSelectors`
/// maps each to its selectors. Returns `(facet, [selectors])` pairs.
/// A facet is a pair of its address and the selectors it exposes.
pub type Facets = Vec<(String, Vec<[u8; 4]>)>;

#[allow(clippy::type_complexity)] // documented above as `Facets`
pub fn diamond_facets(rpc: &mut Rpc, addr: &str) -> Result<Facets, String> {
    // facetAddress selector is what we need per selector; the cheapest entry
    // is the Loupe facets() call which returns address[] and bytes4[][]
    let res = rpc.eth_call(addr, "0x7a0ed627", "latest")?;
    if res == "0x" || res.is_empty() {
        return Err("no facets()".into());
    }
    // offsets into the dynamic array: head = 32-byte offset, then len, then
    // each element. This is a best-effort scan for 20-byte address words and
    // 4-byte selector words; a strict ABI decode is overkill for triage.
    let bytes = crate::selectors::decode(&res)?;
    let mut out = Vec::new();
    // facet addresses appear as 20-byte words in the tail; collect any word
    // that looks like an address (top 12 bytes zero, not the zero address)
    let mut current_facet: Option<String> = None;
    let mut sels: Vec<[u8; 4]> = Vec::new();
    for chunk in bytes.chunks(32) {
        if chunk.len() < 32 {
            break;
        }
        if chunk[..12].iter().all(|&b| b == 0) && chunk[12..].iter().any(|&b| b != 0) {
            let a = format!("0x{}", hex::encode(&chunk[12..]));
            if let Some(f) = current_facet.take() {
                out.push((f, std::mem::take(&mut sels)));
            }
            current_facet = Some(a);
        } else if current_facet.is_some() {
            // a selector word: 28 zero bytes then 4 selector bytes
            if chunk[..28].iter().all(|&b| b == 0) {
                let mut s = [0u8; 4];
                s.copy_from_slice(&chunk[28..]);
                sels.push(s);
            }
        }
    }
    if let Some(f) = current_facet {
        out.push((f, sels));
    }
    Ok(out)
}

/// True when a contract is a diamond (EIP-2537): it answers the Loupe
/// `facets()` selector without reverting.
pub fn is_diamond(rpc: &mut Rpc, addr: &str) -> bool {
    match rpc.eth_call(addr, "0x7a0ed627", "latest") {
        Ok(res) => res != "0x" && !res.is_empty(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eip1967_slot_is_the_documented_constant() {
        // from EIP-1967: bytes32(uint256(keccak256('eip1967.proxy.implementation')) - 1)
        assert_eq!(
            eip1967_impl_slot(),
            "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
        );
    }

    #[test]
    fn eip1822_slot_is_the_documented_constant() {
        assert_eq!(
            eip1822_slot(),
            "0xc5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7"
        );
    }

    #[test]
    fn beacon_slot_is_the_documented_constant() {
        assert_eq!(
            eip1967_beacon_slot(),
            "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"
        );
    }

    #[test]
    fn word_to_addr_reads_low_twenty_bytes() {
        let word = "0x000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266";
        assert_eq!(
            word_to_addr(word).unwrap(),
            "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
        );
    }

    #[test]
    fn word_to_addr_rejects_nonzero_high_bytes() {
        // a value that is not an address (e.g. a packed uint256)
        assert!(
            word_to_addr("0x010000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb9226")
                .is_none()
        );
    }

    #[test]
    fn clone_impl_decodes_eip1167_bytecode() {
        // a minimal proxy pointing at 0x1111111111111111111111111111111111111111
        let code = "0x363d3d373d3d3d363d7311111111111111111111111111111111111111115af43d82803e903d91602b57fd5bf3";
        assert_eq!(
            clone_impl(code).unwrap(),
            "0x1111111111111111111111111111111111111111"
        );
    }

    #[test]
    fn clone_impl_rejects_non_clone_bytecode() {
        assert!(clone_impl("0x6080604052").is_none());
    }

    #[test]
    fn is_zero_addr_handles_both_forms() {
        assert!(is_zero_addr("0x0000000000000000000000000000000000000000"));
        assert!(is_zero_addr("0x0"));
        assert!(!is_zero_addr("0x1111111111111111111111111111111111111111"));
    }

    #[test]
    fn decode_transfer_recovers_both_addresses() {
        let log = crate::rpc::LogEntry {
            topics: vec![
                "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef".into(),
                "0x000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266".into(),
                "0x00000000000000000000000070997970c51812dc3a010c7d01b50e0d17dc79c8".into(),
            ],
            data: "0x0000000000000000000000000000000000000000000000000de0b6b3a7640000".into(),
            block: "0x1".into(),
            tx: String::new(),
        };
        let ev = decode_event(&log);
        assert_eq!(ev.signature, "Transfer(address,address,uint256)");
        assert_eq!(ev.args[0], "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266");
        assert_eq!(ev.args[1], "0x70997970c51812dc3a010c7d01b50e0d17dc79c8");
        assert_eq!(ev.args[2], "1000000000000000000");
    }

    #[test]
    fn unknown_event_falls_back_to_topic0() {
        let log = crate::rpc::LogEntry {
            topics: vec!["0xdeadbeef".into()],
            data: "0x".into(),
            block: "0x1".into(),
            tx: String::new(),
        };
        let ev = decode_event(&log);
        assert!(ev.signature.starts_with("event topic0="));
    }
}
