//! rootgate: run root commands only after a human approves them on their phone.
//!
//! Flow: `ask-root` (unprivileged) -> Unix socket -> `rootgated` (root) -> TCP over
//! Tailscale -> phone app. The phone shows the exact argv and the "why", the user
//! approves with a key held in the Android Keystore, and the phone signs the
//! canonical encoding of the request. The daemon only executes requests that carry
//! a valid signature from an enrolled key, once, before they expire.

pub mod daemon;
pub mod exec;
pub mod net;
pub mod proto;
pub mod trust;

/// Lowercase hex encoding (no extra crate needed).
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    s
}

/// Decode lowercase/uppercase hex. Returns None on bad input.
pub fn unhex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// Fill a buffer from the OS CSPRNG.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).expect("OS random number generator failed");
    b
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let b = [0u8, 1, 0xab, 0xff];
        assert_eq!(hex(&b), "0001abff");
        assert_eq!(unhex("0001ABff").unwrap(), b);
        assert!(unhex("abc").is_none());
        assert!(unhex("zz").is_none());
    }
}
