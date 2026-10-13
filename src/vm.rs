use crate::{bin, cmp, tri, un};
use rustc_hex::FromHex;
use tiny_keccak::{Hasher, Keccak};

pub type U256 = [u8; 32];

pub const ZERO: U256 = [0u8; 32];

/// Backing store for SLOAD during local replay. When a target's control flow
/// depends on stored state (owner, balances, roles, thresholds), seed this from
/// `eth_getStorageAt` and the VM will follow the same branches as the chain.
#[derive(Clone, Default)]
pub struct Storage {
    pub slots: std::collections::HashMap<U256, U256>,
}

impl Storage {
    pub fn get(&self, key: &U256) -> U256 {
        self.slots.get(key).copied().unwrap_or(ZERO)
    }

    pub fn set(&mut self, key: U256, val: U256) {
        if val == ZERO {
            self.slots.remove(&key);
        } else {
            self.slots.insert(key, val);
        }
    }

    /// Seed `count` slots from an RPC endpoint so the VM sees real state.
    pub fn seed_from_rpc(
        &mut self,
        rpc: &mut crate::rpc::Rpc,
        addr: &str,
        count: u64,
    ) -> Result<(), String> {
        for slot in 0..count {
            let word = rpc.storage(addr, slot, None)?;
            let bytes = crate::selectors::decode(&word)?;
            if bytes.len() == 32 && bytes != [0u8; 32] {
                let mut key = ZERO;
                key.copy_from_slice(&[
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, slot as u8,
                ]);
                let mut val = ZERO;
                val.copy_from_slice(&bytes);
                self.set(key, val);
            }
        }
        Ok(())
    }
}

/// Call-frame context: the values opcodes like CALLER/ORIGIN/BALANCE return.
/// Defaults to the zero account; set `caller` to the address you intend to
/// attack from so auth checks follow the right branch.
#[derive(Clone)]
pub struct CallContext {
    pub caller: U256,
    pub origin: U256,
    pub address: U256,
    pub value: U256,
}

impl Default for CallContext {
    fn default() -> Self {
        Self {
            caller: ZERO,
            origin: ZERO,
            address: ZERO,
            value: ZERO,
        }
    }
}

#[derive(Clone)]
pub struct Vm {
    pub code: Vec<u8>,
    pub pc: usize,
    pub stack: Vec<U256>,
    pub mem: Vec<u8>,
    pub calldata: Vec<u8>,
    pub returndata: Vec<u8>,
    pub logs: Vec<String>,
    pub reverted: bool,
    pub revert_data: Vec<u8>,
    pub gas_used: u64,
    pub selfdestruct: bool,
    pub storage_writes: Vec<(U256, U256)>,
    pub result: RunResult,
    pub storage: Storage,
    pub ctx: CallContext,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RunResult {
    Success,
    Revert,
    Invalid,
    BadJump,
    OutOfGas,
    SelfDestruct,
    Unsupported(u8),
}

pub fn from_be(b: &[u8]) -> U256 {
    let mut out = ZERO;
    let n = b.len().min(32);
    let start = 32 - n;
    out[start..].copy_from_slice(&b[b.len() - n..]);
    out
}

pub fn low64(u: &U256) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&u[24..]);
    u64::from_be_bytes(buf)
}

pub fn to_usize(u: &U256) -> usize {
    low64(u) as usize
}

pub fn is_zero(u: &U256) -> bool {
    u.iter().all(|&b| b == 0)
}

fn add(a: &U256, b: &U256) -> U256 {
    let mut out = ZERO;
    let mut carry = 0u16;
    for i in (0..32).rev() {
        let s = a[i] as u16 + b[i] as u16 + carry;
        out[i] = (s & 0xff) as u8;
        carry = s >> 8;
    }
    out
}

fn sub(a: &U256, b: &U256) -> U256 {
    // ponytail: panics on underflow — fine for tracing control flow, not for
    // verifying arithmetic results. Add wrapping semantics if a target's
    // balance math matters.
    let mut out = ZERO;
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let d = a[i] as i16 - b[i] as i16 - borrow;
        out[i] = (d & 0xff) as u8;
        borrow = if d < 0 { 1 } else { 0 };
    }
    out
}

/// EVM EXP: base^exponent mod 2^256. Solidity emits it to pack/unpack storage
/// slots (e.g. reading a bool or uint8 from a packed word), so it appears in
/// nearly every function that touches storage.
fn exp(base: &U256, exponent: &U256) -> U256 {
    let b = u128::from_be_bytes(base[16..32].try_into().unwrap_or([0u8; 16]));
    let e = u128::from_be_bytes(exponent[16..32].try_into().unwrap_or([0u8; 16]));
    if b == 0 {
        return ZERO;
    }
    // exponent > 2^128 would overflow any nonzero base anyway
    if e >= 128 {
        return ZERO;
    }
    let e = e as u32;
    let r = b.checked_pow(e);
    match r {
        Some(v) => {
            let mut out = ZERO;
            out[16..].copy_from_slice(&v.to_be_bytes());
            out
        }
        None => ZERO,
    }
}

/// DIV on the low 128 bits (the width Solidity's ABI decode and SafeMath use
/// in practice; a full 256-bit divide needs bignum, which the EVM needs too).
/// ponytail: upgrade to a full-width divide if a target divides values > 2^128.
/// MUL: full 256-bit product of two 256-bit operands, keeping the low 256
/// bits (EVM semantics). Schoolbook on 128-bit halves with carry.
pub fn mul_pub(a: &U256, b: &U256) -> U256 {
    mul(a, b)
}

fn mul(a: &U256, b: &U256) -> U256 {
    // widen to u128 limbs: a = a0*2^128 + a1 (a0 = high half)
    let a0 = u128::from_be_bytes(a[..16].try_into().unwrap_or([0u8; 16]));
    let a1 = u128::from_be_bytes(a[16..].try_into().unwrap_or([0u8; 16]));
    let b0 = u128::from_be_bytes(b[..16].try_into().unwrap_or([0u8; 16]));
    let b1 = u128::from_be_bytes(b[16..].try_into().unwrap_or([0u8; 16]));

    // products that can reach the low 256 bits
    let lolo = a1.wrapping_mul(b1);
    // a1*b0 and a0*b1 contribute to bits 128..256 via their low halves
    let cross = (a1 >> 64).wrapping_mul(b0 & 0xffff_ffff_ffff_ffff)
        + (b1 >> 64).wrapping_mul(a0 & 0xffff_ffff_ffff_ffff)
        + (a1 & 0xffff_ffff_ffff_ffff).wrapping_mul(b0 >> 64)
        + (b1 & 0xffff_ffff_ffff_ffff).wrapping_mul(a0 >> 64);

    let mut out = ZERO;
    out[16..].copy_from_slice(&lolo.to_be_bytes());
    // cross occupies bits 64..192; add it into the high half
    let high = (cross << 64) | (lolo >> 64);
    out[..16].copy_from_slice(&high.to_be_bytes());
    out
}

fn div(a: &U256, b: &U256) -> U256 {
    let an = u128::from_be_bytes(a[16..32].try_into().unwrap_or([0u8; 16]));
    let bn = u128::from_be_bytes(b[16..32].try_into().unwrap_or([0u8; 16]));
    if bn == 0 {
        return ZERO; // EVM: div by zero is zero, not a trap
    }
    let mut out = ZERO;
    out[16..].copy_from_slice(&(an / bn).to_be_bytes());
    out
}

fn rem(a: &U256, b: &U256) -> U256 {
    let an = u128::from_be_bytes(a[16..32].try_into().unwrap_or([0u8; 16]));
    let bn = u128::from_be_bytes(b[16..32].try_into().unwrap_or([0u8; 16]));
    if bn == 0 {
        return ZERO;
    }
    let mut out = ZERO;
    out[16..].copy_from_slice(&(an % bn).to_be_bytes());
    out
}

fn addmod(a: &U256, b: &U256, n: &U256) -> U256 {
    let an = u128::from_be_bytes(a[16..32].try_into().unwrap_or([0u8; 16]));
    let bn = u128::from_be_bytes(b[16..32].try_into().unwrap_or([0u8; 16]));
    let nn = u128::from_be_bytes(n[16..32].try_into().unwrap_or([0u8; 16]));
    if nn == 0 {
        return ZERO;
    }
    // addmod wraps at 2^256; the low-128 approximation is exact when inputs fit
    let s = an.wrapping_add(bn);
    let mut out = ZERO;
    out[16..].copy_from_slice(&(s % nn).to_be_bytes());
    out
}

fn lt(a: &U256, b: &U256) -> bool {
    for i in 0..32 {
        if a[i] != b[i] {
            return a[i] < b[i];
        }
    }
    false
}

/// Signed less-than: interpret both operands as two's-complement 256-bit.
fn slt(a: &U256, b: &U256) -> bool {
    let aneg = a[0] & 0x80 != 0;
    let bneg = b[0] & 0x80 != 0;
    match (aneg, bneg) {
        (false, false) => lt(a, b), // both positive: unsigned compare
        (true, false) => true,      // negative < positive
        (false, true) => false,     // positive < negative is false
        (true, true) => lt(b, a),   // both negative: larger magnitude is smaller
    }
}

fn and(a: &U256, b: &U256) -> U256 {
    let mut out = ZERO;
    for i in 0..32 {
        out[i] = a[i] & b[i];
    }
    out
}

fn or(a: &U256, b: &U256) -> U256 {
    let mut out = ZERO;
    for i in 0..32 {
        out[i] = a[i] | b[i];
    }
    out
}

fn xor(a: &U256, b: &U256) -> U256 {
    let mut out = ZERO;
    for i in 0..32 {
        out[i] = a[i] ^ b[i];
    }
    out
}

fn not(a: &U256) -> U256 {
    let mut out = ZERO;
    for i in 0..32 {
        out[i] = !a[i];
    }
    out
}

/// EVM SHL: `value << shift`. Bytes are big-endian (byte 0 is most
/// significant), so a left shift moves bits toward byte 0.
#[allow(clippy::needless_range_loop)] // byte-indexed
fn shl(shift: &U256, val: &U256) -> U256 {
    let s = low64(shift);
    if s >= 256 {
        return ZERO;
    }
    let s = s as usize;
    if s == 0 {
        return *val;
    }
    let byte_shift = s / 8;
    let bit_shift = s % 8;
    let mut out = ZERO;
    for i in 0..32 {
        // out[i] receives bits from the byte byte_shift positions below it
        let src = i as isize - byte_shift as isize;
        if src < 0 {
            continue;
        }
        let src = src as usize;
        let mut v = (val[src] as u16) << bit_shift;
        if src + 1 < 32 {
            v |= (val[src + 1] as u16) >> (8 - bit_shift);
        }
        out[i] = (v & 0xff) as u8;
    }
    out
}

/// EVM SHR: `value >> shift`. Big-endian bytes (byte 0 = most significant),
/// so a right shift moves bits toward byte 31. `0x41c0e1b500..00 >> 224`
/// yields `0x00..0041c0e1b5` — exactly what Solidity's selector compare needs.
#[allow(clippy::needless_range_loop)] // byte-indexed
fn shr(shift: &U256, val: &U256) -> U256 {
    let s = low64(shift);
    if s >= 256 {
        return ZERO;
    }
    let s = s as usize;
    if s == 0 {
        return *val;
    }
    let byte_shift = s / 8;
    let bit_shift = s % 8;
    let mut out = ZERO;
    for i in 0..32 {
        // out[i] takes the byte byte_shift positions MORE significant (lower
        // index) and shifts it down; the low bits of the next byte fill in
        let src = i as isize - byte_shift as isize;
        if src < 0 {
            continue;
        }
        let src = src as usize;
        let mut v = (val[src] as u16) << bit_shift;
        if src + 1 < 32 {
            v |= (val[src + 1] as u16) >> (8 - bit_shift);
        }
        out[i] = (v & 0xff) as u8;
    }
    out
}

pub fn keccak256(input: &[u8]) -> U256 {
    // Real keccak-f[1600]. Replaces the placeholder XOR hash, so branches that
    // gate on hashing (mapping slots, signature checks, Merkle roots) now
    // follow the same path as they do on-chain.
    let mut k = Keccak::v256();
    let mut out = [0u8; 32];
    k.update(input);
    k.finalize(&mut out);
    out
}

impl Vm {
    pub fn new(code: &str, calldata: &str) -> Result<Self, String> {
        let code = if code.is_empty() || code == "0x" {
            Vec::new()
        } else {
            code.strip_prefix("0x")
                .unwrap_or(code)
                .from_hex::<Vec<u8>>()
                .map_err(|e| format!("code hex: {e}"))?
        };
        let calldata = if calldata.is_empty() || calldata == "0x" {
            Vec::new()
        } else {
            calldata
                .strip_prefix("0x")
                .unwrap_or(calldata)
                .from_hex::<Vec<u8>>()
                .map_err(|e| format!("calldata hex: {e}"))?
        };
        Ok(Self {
            code,
            pc: 0,
            stack: Vec::with_capacity(64),
            mem: vec![0; 512],
            calldata,
            returndata: Vec::new(),
            logs: Vec::new(),
            reverted: false,
            revert_data: Vec::new(),
            gas_used: 0,
            selfdestruct: false,
            storage_writes: Vec::new(),
            result: RunResult::Success,
            storage: Storage::default(),
            ctx: CallContext::default(),
        })
    }

    fn push(&mut self, u: U256) {
        if self.stack.len() < 1024 {
            self.stack.push(u);
        }
    }

    fn pop(&mut self) -> U256 {
        self.stack.pop().unwrap_or(ZERO)
    }

    fn peek(&self, n: usize) -> U256 {
        let len = self.stack.len();
        if len <= n {
            return ZERO;
        }
        self.stack[len - 1 - n]
    }

    fn ensure_mem(&mut self, end: usize) -> bool {
        // EVM memory expansion is gas-metered per word; cap it so pathological
        // memory writes (solidity's ever-growing free memory pointer) cannot
        // exhaust the host. 64KiB is far beyond any legitimate frame.
        const MAX_MEM: usize = 64 * 1024;
        if end > MAX_MEM {
            self.reverted = true;
            self.result = RunResult::OutOfGas;
            return false;
        }
        if end > self.mem.len() {
            self.mem.resize(end, 0);
        }
        true
    }

    fn mload(&mut self, offset: &U256) -> U256 {
        let off = to_usize(offset);
        if !self.ensure_mem(off + 32) {
            return ZERO;
        }
        let mut out = ZERO;
        out.copy_from_slice(&self.mem[off..off + 32]);
        out
    }

    fn mstore(&mut self, offset: &U256, val: &U256) {
        let off = to_usize(offset);
        if !self.ensure_mem(off + 32) {
            return;
        }
        self.mem[off..off + 32].copy_from_slice(val);
    }

    fn mstore8(&mut self, offset: &U256, val: u8) {
        let off = to_usize(offset);
        if !self.ensure_mem(off + 1) {
            return;
        }
        self.mem[off] = val;
    }

    fn memslice(&mut self, offset: &U256, size: &U256) -> Vec<u8> {
        let off = to_usize(offset);
        let sz = to_usize(size);
        if !self.ensure_mem(off + sz) {
            return Vec::new();
        }
        self.mem[off..off + sz].to_vec()
    }

    #[allow(clippy::needless_range_loop)] // byte-indexed
    fn calldataload(&self, offset: &U256) -> U256 {
        let off = to_usize(offset);
        let mut out = ZERO;
        for i in 0..32 {
            if off + i < self.calldata.len() {
                out[i] = self.calldata[off + i];
            }
        }
        out
    }

    fn jump(&mut self, dest: usize) -> bool {
        if dest >= self.code.len() || self.code[dest] != 0x5b {
            return false;
        }
        self.pc = dest;
        true
    }

    /// Execute exactly one instruction and stop. Used by tracers and by callers
    /// that need per-opcode control. Terminal opcodes (STOP/REVERT/etc.)
    /// return their RunResult; a normal opcode returns `Success`.
    pub fn step(&mut self) -> RunResult {
        if self.pc >= self.code.len() {
            self.result = RunResult::Success;
            return RunResult::Success;
        }
        // run() charges gas before each opcode and trips on the budget, so a
        // tiny limit cannot execute even one op. Give it enough budget for a
        // single opcode and stop afterwards by capping the step count to 1.
        self.gas_used = 0;
        self.result = RunResult::Success;
        self.execute_one()
    }

    /// Run a single opcode without the loop/gas wrapper. Returns the opcode's
    /// outcome; Success means "continue", anything else is terminal.
    fn execute_one(&mut self) -> RunResult {
        let op = self.code[self.pc];
        self.pc += 1;
        self.gas_used += 3;
        self.dispatch(op)
    }

    /// Execute to completion (or gas/steps limit). Check `result`, `reverted`,
    /// `selfdestruct`, and `storage_writes` afterwards.
    pub fn run(&mut self, gas_limit: u64) -> RunResult {
        let mut steps = 0u64;
        while self.pc < self.code.len() {
            if steps >= 200_000 || self.gas_used > gas_limit {
                self.result = RunResult::OutOfGas;
                return RunResult::OutOfGas;
            }
            steps += 1;
            let op = self.code[self.pc];
            self.pc += 1;
            self.gas_used += 3;

            let res = self.dispatch(op);
            if !matches!(res, RunResult::Success) {
                return res;
            }
            // STOP returns Success and halts; pc is already past the code
            if self.pc >= self.code.len() {
                self.result = RunResult::Success;
                return RunResult::Success;
            }
        }
        self.result = RunResult::Success;
        RunResult::Success
    }

    /// Execute one opcode. STOP returns Success *and* halts the caller's loop
    /// because it leaves pc past the end or the caller checks `pc < code.len()`.
    fn dispatch(&mut self, op: u8) -> RunResult {
        match op {
            0x00 => return RunResult::Success,   // STOP
            0x01 => bin!(self, add),             // ADD
            0x02 => bin!(self, mul),             // MUL
            0x03 => bin!(self, sub),             // SUB
            0x04 => bin!(self, div),             // DIV
            0x06 => bin!(self, rem),             // MOD
            0x08 => tri!(self, addmod),          // ADDMOD
            0x0a => bin!(self, exp),             // EXP
            0x10 => cmp!(self, lt),              // LT: a < b (a is top)
            0x11 => cmp!(self, |a, b| lt(b, a)), // GT: a > b
            // SLT/SGT: signed compares. Solidity's ABI decoder emits SLT
            // for its calldata bounds check, so these are required to
            // replay any function that takes arguments.
            0x12 => cmp!(self, slt),              // SLT
            0x13 => cmp!(self, |a, b| slt(b, a)), // SGT
            0x14 => cmp!(self, |a, b| a == b),    // EQ
            0x15 => un!(self, is_zero),           // ISZERO
            0x16 => bin!(self, and),              // AND
            0x17 => bin!(self, or),               // OR
            0x18 => bin!(self, xor),              // XOR
            0x19 => {
                // NOT
                let a = self.pop();
                self.push(not(&a));
            }
            0x1b => bin!(self, shl), // SHL: shift is top
            0x1c => bin!(self, shr), // SHR: shift is top
            0x20 => {
                // KECCAK256
                let offset = self.pop();
                let size = self.pop();
                let data = self.memslice(&offset, &size);
                self.push(keccak256(&data));
            }
            0x30 => self.push(self.ctx.address), // ADDRESS
            0x31 => {
                // BALANCE — unknown in local replay; zero is the safe
                // answer for a target that checks its own balance
                self.push(ZERO)
            }
            0x32 => self.push(self.ctx.origin), // ORIGIN
            0x33 => self.push(self.ctx.caller), // CALLER
            0x34 => self.push(self.ctx.value),  // CALLVALUE
            0x35 => {
                // CALLDATALOAD
                let offset = self.pop();
                self.push(self.calldataload(&offset));
            }
            0x36 => self.push(from_u64(self.calldata.len() as u64)), // CALLDATASIZE
            0x37 => {
                // CALLDATACOPY
                let dest = self.pop();
                let off = self.pop();
                let size = self.pop();
                let d = to_usize(&dest);
                let sz = to_usize(&size);
                if !self.ensure_mem(d + sz) {
                    return RunResult::OutOfGas;
                }
                for i in 0..sz {
                    let src = to_usize(&off) + i;
                    self.mem[d + i] = self.calldata.get(src).copied().unwrap_or(0);
                }
            }
            0x38 => self.push(from_u64(self.code.len() as u64)), // CODESIZE
            0x39 => {
                // CODECOPY
                let dest = self.pop();
                let off = self.pop();
                let size = self.pop();
                let d = to_usize(&dest);
                let sz = to_usize(&size);
                if !self.ensure_mem(d + sz) {
                    return RunResult::OutOfGas;
                }
                for i in 0..sz {
                    let src = to_usize(&off) + i;
                    self.mem[d + i] = self.code.get(src).copied().unwrap_or(0);
                }
            }
            0x3d => self.push(from_u64(self.returndata.len() as u64)), // RETURNDATASIZE
            0x5a => self.push(from_u64(1_000_000)),                    // GAS: ample for replay
            0x5e => {
                // MCOPY: copy within memory; a no-op copy is safe for
                // replay since the source and dest are both zeroed frames
                let dest = self.pop();
                let off = self.pop();
                let size = self.pop();
                let d = to_usize(&dest);
                let o = to_usize(&off);
                let sz = to_usize(&size);
                if self.ensure_mem(d + sz) && self.ensure_mem(o + sz) {
                    let (lo, hi) = if d < o { (d, o) } else { (o, d) };
                    let buf = self.mem[lo..lo + sz].to_vec();
                    self.mem[hi..hi + sz].copy_from_slice(&buf);
                }
            }
            0x50 => {
                let _ = self.pop(); // POP
            }
            0x51 => {
                // MLOAD
                let offset = self.pop();
                let v = self.mload(&offset);
                self.push(v);
            }
            0x52 => {
                // MSTORE
                let offset = self.pop();
                let val = self.pop();
                self.mstore(&offset, &val);
            }
            0x53 => {
                // MSTORE8
                let offset = self.pop();
                let val = self.pop();
                self.mstore8(&offset, val[31]);
            }
            0x54 => {
                // SLOAD — read from the seeded backing store
                let key = self.pop();
                self.push(self.storage.get(&key));
            }
            0x55 => {
                // SSTORE — apply the write to the backing store and record
                // it so callers can diff state after replay
                let key = self.pop();
                let val = self.pop();
                self.storage.set(key, val);
                self.storage_writes.push((key, val));
            }
            0x56 => {
                // JUMP
                let dest = self.pop();
                if !self.jump(to_usize(&dest)) {
                    self.reverted = true;
                    self.result = RunResult::BadJump;
                    return RunResult::BadJump;
                }
            }
            0x57 => {
                // JUMPI
                let dest = self.pop();
                let cond = self.pop();
                if !is_zero(&cond) && !self.jump(to_usize(&dest)) {
                    self.reverted = true;
                    self.result = RunResult::BadJump;
                    return RunResult::BadJump;
                }
            }
            0x58 => self.push(from_u64(self.pc as u64 - 1)), // PC
            0x59 => self.push(from_u64(self.mem.len() as u64)), // MSIZE
            0x5b => {}                                       // JUMPDEST
            0x5f => self.push(ZERO),                         // PUSH0: pushes a zero word
            0x80..=0x8f => {
                // DUP1..DUP16
                let v = self.peek((op - 0x80) as usize);
                self.push(v);
            }
            0x90..=0x9f => {
                // SWAP1..SWAP16
                let n = (op - 0x8f) as usize;
                let len = self.stack.len();
                if len > n {
                    self.stack.swap(len - 1, len - 1 - n);
                }
            }
            0xa0..=0xa4 => {
                // LOG0..LOG4
                let topics = (op - 0xa0) as usize;
                let offset = self.pop();
                let size = self.pop();
                for _ in 0..topics {
                    let _ = self.pop();
                }
                let data = self.memslice(&offset, &size);
                self.logs
                    .push(format!("log{topics} {}", hex::encode(&data)));
            }
            0xf0 => {
                // CREATE — fake deterministic address
                let _size = self.pop();
                let _off = self.pop();
                let _val = self.pop();
                let mut addr = ZERO;
                addr[31] = 0xfa;
                self.push(addr);
            }
            0xf3 => {
                // RETURN
                let offset = self.pop();
                let size = self.pop();
                self.returndata = self.memslice(&offset, &size);
                self.result = RunResult::Success;
                return RunResult::Success;
            }
            0xfd => {
                // REVERT
                let offset = self.pop();
                let size = self.pop();
                self.revert_data = self.memslice(&offset, &size);
                self.reverted = true;
                self.result = RunResult::Revert;
                return RunResult::Revert;
            }
            0xfe => {
                // INVALID
                self.reverted = true;
                self.result = RunResult::Invalid;
                return RunResult::Invalid;
            }
            0xff => {
                // SELFDESTRUCT — primary vuln signal
                let _ = self.pop();
                self.selfdestruct = true;
                self.result = RunResult::SelfDestruct;
                return RunResult::SelfDestruct;
            }
            0x60..=0x7f => {
                // PUSH1..PUSH32
                let n = (op - 0x5f) as usize;
                let mut val = ZERO;
                for i in 0..n {
                    if self.pc + i < self.code.len() {
                        val[32 - n + i] = self.code[self.pc + i];
                    }
                }
                self.pc += n;
                self.push(val);
            }
            _ => {
                self.reverted = true;
                self.result = RunResult::Unsupported(op);
                return RunResult::Unsupported(op);
            }
        }
        RunResult::Success
    }
}

pub fn from_u64(n: u64) -> U256 {
    let mut out = ZERO;
    out[24..].copy_from_slice(&n.to_be_bytes());
    out
}

#[macro_export]
macro_rules! tri {
    ($vm:expr, $f:ident) => {{
        let a = $vm.pop();
        let b = $vm.pop();
        let n = $vm.pop();
        $vm.push($f(&a, &b, &n));
    }};
}

#[macro_export]
macro_rules! bin {
    ($vm:expr, $f:expr) => {{
        let a = $vm.pop();
        let b = $vm.pop();
        $vm.push($f(&a, &b));
    }};
}

#[macro_export]
macro_rules! un {
    ($vm:expr, $f:ident) => {{
        let a = $vm.pop();
        let mut r = $crate::vm::ZERO;
        r[31] = $f(&a) as u8;
        $vm.push(r);
    }};
}

#[macro_export]
macro_rules! cmp {
    ($vm:expr, $f:expr) => {{
        let a = $vm.pop();
        let b = $vm.pop();
        let mut r = $crate::vm::ZERO;
        r[31] = $f(&a, &b) as u8;
        $vm.push(r);
    }};
}
