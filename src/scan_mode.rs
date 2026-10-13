#[derive(PartialEq, Eq, Clone, Copy)]
pub enum ScanMode {
    Quick,
    Deep,
    Slot,
    Scan,
    /// resolve the proxy stack only and print each layer
    Proxy,
    /// read and decode recent events/logs
    Events,
    /// replay one selector in the local VM against seeded chain state
    Replay,
}
