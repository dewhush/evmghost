use evmghost::vm::{self, RunResult, Vm};

#[test]
fn vm_runs_solidity_dispatcher() {
    // Minimal solidith-ish runtime: PUSH0, calldataload, lt, jumpi over a
    // selector compare, then STOP. Must execute without hitting Unsupported.
    let code = "0x5f5f3560e01c5761000d575f5f5f5f";
    let mut v = Vm::new(code, "0x").unwrap();
    let r = v.run(1_000_000);
    assert!(
        matches!(r, RunResult::Success | RunResult::Revert),
        "got {r:?}"
    );
}

#[test]
fn vm_captures_selfdestruct() {
    // PUSH1 0; SELFDESTRUCT
    let code = "0x6000ff";
    let mut v = Vm::new(code, "0x").unwrap();
    let r = v.run(1_000_000);
    assert_eq!(r, RunResult::SelfDestruct);
    assert!(v.selfdestruct);
}

#[test]
fn vm_captures_sstore() {
    // PUSH1 42; PUSH1 0; SSTORE; STOP
    let code = "0x602a60005500";
    let mut v = Vm::new(code, "0x").unwrap();
    v.run(1_000_000);
    assert_eq!(v.storage_writes.len(), 1);
    assert_eq!(vm::low64(&v.storage_writes[0].1), 42);
}

#[test]
fn vm_revert_returns_data() {
    // PUSH1 4; PUSH1 0; REVERT (empty)
    let code = "0x60046000fd";
    let mut v = Vm::new(code, "0x").unwrap();
    let r = v.run(1_000_000);
    assert_eq!(r, RunResult::Revert);
    assert!(v.reverted);
}

#[test]
fn vm_jump_requires_jumpdest() {
    // PUSH1 4; JUMP; STOP; JUMPDEST; STOP  → jump target 4 is a real JUMPDEST
    let code = "0x600456005b00";
    let mut v = Vm::new(code, "0x").unwrap();
    let r = v.run(1_000_000);
    assert_eq!(r, RunResult::Success);
}

#[test]
fn vm_jump_to_non_jumpdest_fails() {
    // PUSH1 2; JUMP; STOP; STOP → target 2 is STOP, not JUMPDEST
    let code = "0x6002560000";
    let mut v = Vm::new(code, "0x").unwrap();
    let r = v.run(1_000_000);
    assert_eq!(r, RunResult::BadJump);
}

#[test]
fn selector_extraction_skips_push_payloads() {
    use evmghost::selectors::extract_selectors;
    // PUSH4 selector then PUSH1 data that must NOT be read as a selector
    let code = [
        0x63, 0xa9, 0x05, 0x9c, 0xbb, 0x60, 0x63, 0xde, 0xad, 0xbe, 0xef,
    ];
    let sels = extract_selectors(&code);
    assert_eq!(sels.len(), 1);
    assert_eq!(hex::encode(sels[0]), "a9059cbb");
}

#[test]
fn calldataload_reads_selector_from_offset_zero() {
    // PUSH1 0; CALLDATALOAD. CALLDATALOAD is left-aligned, so a 4-byte
    // selector lands in bytes 0..4 (the high end), not the low 4.
    let code = "0x600035";
    let mut v = Vm::new(code, "0x41c0e1b5").unwrap();
    v.run(1_000_000);
    let top = v.stack.last().unwrap();
    assert_eq!(
        hex::encode(&top[..4]),
        "41c0e1b5",
        "got {}",
        hex::encode(top)
    );
}

#[test]
fn shr_shifts_selector_to_low_bytes() {
    // Solidity's dispatcher: CALLDATALOAD (selector in low bytes), then
    // PUSH 0xe0 as the shift on top, then SHR. The selector must end up
    // in the low 4 bytes so the EQ compare matches a PUSH4.
    let code = "0x5f3560e01c";
    let mut v = Vm::new(code, "0x41c0e1b5").unwrap();
    v.run(1_000_000);
    let top = v.stack.last().unwrap();
    assert_eq!(
        hex::encode(&top[28..]),
        "41c0e1b5",
        "got {}",
        hex::encode(top)
    );
}

#[test]
fn push4_pushes_four_bytes() {
    // PUSH4 0x41c0e1b5
    let code = "0x6341c0e1b5";
    let mut v = Vm::new(code, "0x").unwrap();
    v.run(1_000_000);
    let top = v.stack.last().unwrap();
    assert_eq!(
        hex::encode(&top[28..]),
        "41c0e1b5",
        "got {}",
        hex::encode(top)
    );
}

#[test]
fn vm_stores_calldata() {
    let v = Vm::new("0x00", "0x41c0e1b5").unwrap();
    assert_eq!(
        hex::encode(&v.calldata),
        "41c0e1b5",
        "calldata was {}",
        hex::encode(&v.calldata)
    );
}

#[test]
fn debug_shr_value() {
    let code = "0x60e06341c0e1b51c";
    let mut v = Vm::new(code, "0x").unwrap();
    v.run(1_000_000);
    println!(
        "full stack: {:?}",
        v.stack.iter().map(hex::encode).collect::<Vec<_>>()
    );
}

/// The decisive check: the exact dispatcher pattern Solidity emits, verified
/// against what the chain does. CALLDATALOAD + PUSH 0xe0 + SHR + PUSH4 + EQ.
#[test]
fn dispatcher_shr_matches_push4() {
    // PUSH1 0; CALLDATALOAD; PUSH1 0xe0; SHR; PUSH4 0x41c0e1b5; EQ
    let code = "0x60003560e01c6341c0e1b514";
    let mut v = Vm::new(code, "0x41c0e1b5").unwrap();
    v.run(1_000_000);
    let top = v.stack.last().unwrap();
    assert_eq!(
        top[31],
        1,
        "selector compare must be true, got {}",
        hex::encode(top)
    );
}

#[test]
fn debug_shr_operands() {
    // PUSH1 0xe0; PUSH4 selector; SHR  → inspect the raw stack at each step
    let code = "0x60e06341c0e1b51c";
    let mut v = Vm::new(code, "0x").unwrap();
    for _ in 0..4 {
        let pc = v.pc;
        let op = code_bytes_at(&v, pc);
        let _ = v.step();
        println!(
            "pc={pc} op=0x{op:02x} stack={:?}",
            v.stack
                .iter()
                .rev()
                .take(3)
                .map(hex::encode)
                .collect::<Vec<_>>()
        );
    }
    let top = v.stack.last().unwrap();
    println!("FINAL: {}", hex::encode(top));
}

fn code_bytes_at(v: &Vm, pc: usize) -> u8 {
    // code is stored decoded; reach into it via a tiny wrapper
    v.code.get(pc).copied().unwrap_or(0)
}

#[test]
fn mul_is_exact_for_small_values() {
    // PUSH1 6; PUSH1 7; MUL
    let code = "0x6006600702";
    let mut v = Vm::new(code, "0x").unwrap();
    v.run(1_000_000);
    let top = v.stack.last().unwrap();
    assert_eq!(
        hex::encode(&top[31..]),
        "2a",
        "6*7=42, got {}",
        hex::encode(top)
    );
}

#[test]
fn mul_wraps_at_256_bits() {
    // 2^128 * 2^128 = 2^256 = 0 in EVM
    let mut a = [0u8; 32];
    a[16] = 1; // 2^128
    let b = a;
    let r = evmghost::vm::mul_pub(&a, &b);
    assert_eq!(hex::encode(r), hex::encode([0u8; 32]));
}
