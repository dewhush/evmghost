/// Extract printable ASCII strings from bytecode — surfaces token names,
/// URLs, revert reasons, error strings, and sometimes stored hints.
pub fn extract(code: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut buf = String::new();
    for &b in code {
        if (0x20..0x7f).contains(&b) {
            buf.push(b as char);
        } else if !buf.is_empty() {
            if buf.len() >= 4 {
                out.push(std::mem::take(&mut buf));
            } else {
                buf.clear();
            }
        }
    }
    if buf.len() >= 4 {
        out.push(buf);
    }
    out
}
