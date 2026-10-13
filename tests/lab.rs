use evmghost::rpc::Rpc;

/// Integration tests against the live anvil lab contract. The lab
/// (0x5FbDB...80aa3) is deliberately vulnerable; these prove the read path
/// and the access-control probes agree with the chain's ground truth.
const LAB: &str = "0x5FbDB2315678afecb367f032d93F642f64180aa3";
const RPC: &str = "http://127.0.0.1:8545";

fn rpc() -> Rpc {
    Rpc::new(RPC)
}

#[test]
fn reads_owner_without_source() {
    let mut rpc = rpc();
    // owner() read live with no ABI and no source
    let res = rpc.eth_call(LAB, "0x8da5cb5b", "latest").unwrap();
    let bytes = evmghost::selectors::decode(&res).unwrap();
    assert_eq!(
        hex::encode(&bytes[12..]),
        "f39fd6e51aad88f6f4ce6ab8827279cfffb92266",
        "owner should be anvil account 0"
    );
}

#[test]
fn reads_total_supply() {
    let mut rpc = rpc();
    let supply = rpc.eth_call(LAB, "0x18160ddd", "latest").unwrap();
    let bytes = evmghost::selectors::decode(&supply).unwrap();
    let n = u128::from_be_bytes(bytes[16..32].try_into().unwrap());
    assert_eq!(n, 1_000_000_000_000_000_000_000_000); // 1e6 * 1e18
}

#[test]
fn storage_slots_expose_owner_and_supply() {
    let mut rpc = rpc();
    let s0 = rpc.storage(LAB, 0, None).unwrap();
    assert!(s0.contains("f39fd6e51aad88f6f4ce6ab8827279cfffb92266"));
    let s2 = rpc.storage(LAB, 2, None).unwrap();
    assert!(s2 != "0x0000000000000000000000000000000000000000000000000000000000000000");
}

/// Ground truth for the lab's unauthenticated selfdestruct: kill() called by
/// the default (non-owner) eth_call caller returns successfully rather than
/// reverting. That is the exploit signature.
#[test]
fn kill_is_reachable_from_a_non_owner() {
    let mut rpc = rpc();
    let res = rpc.eth_call(LAB, "0x41c0e1b5", "latest");
    assert!(res.is_ok(), "kill() reverted for a non-owner: {res:?}");
    assert_eq!(res.unwrap(), "0x"); // no return data — never RETURNs
}

/// mint() has no access control. An eth_call from a non-owner succeeds.
#[test]
fn mint_from_non_owner_does_not_revert() {
    let mut cd = hex::decode("40c10f19").unwrap();
    cd.extend_from_slice(&[0u8; 32]); // to
    cd.extend_from_slice(&[0u8; 32]); // amount
    let mut rpc = rpc();
    let res = rpc.eth_call(LAB, &format!("0x{}", hex::encode(&cd)), "latest");
    assert!(res.is_ok(), "mint() reverted for a non-owner: {res:?}");
}

/// transferFrom omits the allowance check. A zero-amount call to a zero
/// balance account still succeeds — no approval check of any kind ran.
#[test]
fn transferfrom_has_no_approval_check() {
    let mut cd = hex::decode("23b872dd").unwrap();
    cd.extend_from_slice(&[0u8; 32]); // from (zero balance)
    cd.extend_from_slice(&[0u8; 32]); // to
    cd.extend_from_slice(&[0u8; 32]); // amount 0
    let mut rpc = rpc();
    let res = rpc.eth_call(LAB, &format!("0x{}", hex::encode(&cd)), "latest");
    assert!(res.is_ok(), "expected no allowance check: {res:?}");
}

/// The lab's withdraw() uses tx.origin == owner. An eth_call from a non-owner
/// must revert — this is what makes the bug phishable rather than directly
/// callable, and confirms the tool's read path reflects the real guard.
#[test]
fn withdraw_reverts_for_non_owner() {
    let mut cd = hex::decode("2e1a7d4d").unwrap();
    cd.extend_from_slice(&[0u8; 32]); // amount
    let mut rpc = rpc();
    let res = rpc.eth_call(LAB, &format!("0x{}", hex::encode(&cd)), "latest");
    assert!(
        res.is_err(),
        "withdraw() should revert for non-owner: {res:?}"
    );
}

#[test]
fn resolve_aave_v3_proxy_on_mainnet() {
    let mut rpc = evmghost::rpc::Rpc::new("https://ethereum-rpc.publicnode.com");
    let chain =
        evmghost::proxy::resolve_chain(&mut rpc, "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2")
            .unwrap();
    println!("chain len: {}", chain.len());
    for l in &chain {
        println!("  {:?} {} -> {}", l.kind, l.via, l.target);
    }
    assert!(chain.len() >= 2);
    let logic = chain.last().unwrap();
    assert_eq!(
        logic.target.to_lowercase(),
        "0x728a138a4823392c2efa55e028d434f526fe03cf"
    );
}
