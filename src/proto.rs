//! Wire messages, input validation and the canonical bytes the phone signs.

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::pkcs8::{DecodePublicKey, EncodePublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Domain separation prefix; bump the version if the encoding ever changes.
pub const MAGIC: &[u8] = b"ROOTGATE-V1\n";
pub const PROTO_VERSION: u32 = 2;
/// Domain separation for the daemon's own signatures (never valid as approvals).
pub const HELLO_MAGIC: &[u8] = b"ROOTGATE-HELLO-V2\n";
pub const DREQ_MAGIC: &[u8] = b"ROOTGATE-DREQ-V2\n";

pub const MAX_ARGS: usize = 64;
pub const MAX_ARG_BYTES: usize = 4096;
pub const MAX_TOTAL_ARG_BYTES: usize = 16 * 1024;
pub const MAX_WHY_CHARS: usize = 500;
/// Max size of one JSON line on requests (client submit, approver decisions).
pub const MAX_LINE: usize = 64 * 1024;
/// Max size of a DER-encoded P-256 signature (72 bytes) with slack.
const MAX_SIG_DER: usize = 80;

/// A pending request exactly as it is shown on the phone and signed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Request {
    /// 32 hex chars, random.
    pub id: String,
    /// base64 of 32 random bytes; makes every signature single-use.
    pub nonce: String,
    /// Unix seconds (daemon clock).
    pub created: u64,
    pub expires: u64,
    pub uid: u32,
    pub user: String,
    pub host: String,
    /// argv[0] is an absolute path. Executed without a shell.
    pub argv: Vec<String>,
    /// Free-text reason written by the requester. A hint, not proof.
    pub why: String,
}

impl Request {
    /// Unambiguous, length-prefixed encoding. The phone must build exactly the same
    /// bytes from the fields it displays and sign those (SHA256withECDSA).
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(MAGIC);
        put_str(&mut out, &self.id);
        put_str(&mut out, &self.nonce);
        out.extend_from_slice(&self.created.to_be_bytes());
        out.extend_from_slice(&self.expires.to_be_bytes());
        out.extend_from_slice(&self.uid.to_be_bytes());
        put_str(&mut out, &self.user);
        put_str(&mut out, &self.host);
        out.extend_from_slice(&(self.argv.len() as u32).to_be_bytes());
        for a in &self.argv {
            put_str(&mut out, a);
        }
        put_str(&mut out, &self.why);
        out
    }

    /// Short code shown both in the terminal and on the phone so the user can
    /// check they are approving the request they just triggered.
    pub fn code(&self) -> String {
        short_code(&Sha256::digest(self.canonical_bytes()))
    }
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s.as_bytes());
}

/// 6 characters, 30 bits, from an alphabet without look-alikes (no I, O, 0, 1).
pub fn short_code(hash: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let v = u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]);
    (0..6)
        .map(|i| ALPHABET[((v >> (27 - 5 * i)) & 31) as usize] as char)
        .collect()
}

// ---------------------------------------------------------------- messages

/// ask-root -> daemon
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMsg {
    Submit { argv: Vec<String>, why: String },
}

/// daemon -> ask-root
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ToClient {
    Pending {
        id: String,
        code: String,
        expires: u64,
    },
    Result {
        exit_code: Option<i32>,
        signal: Option<i32>,
        timed_out: bool,
        stdout: String,
        stderr: String,
        stdout_truncated: bool,
        stderr_truncated: bool,
    },
    Denied {
        id: String,
    },
    Expired {
        id: String,
    },
    Error {
        message: String,
    },
}

/// daemon -> phone
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ToApprover {
    /// Answer to the phone's challenge. `sig` proves the daemon holds the private
    /// half of `daemon_key` (base64 SPKI), which the phone pins.
    Hello { host: String, proto: u32, daemon_key: String, sig: String },
    /// `warnings` are the daemon's findings about the command (e.g. a script your
    /// user can edit). `dsig` = daemon signature over `daemon_request_bytes`.
    Request { request: Request, code: String, warnings: Vec<String>, dsig: String },
    /// The request is gone (approved, denied, expired or the requester left).
    Cancel { id: String, reason: String },
    Error { id: Option<String>, message: String },
    Ping,
}

/// phone -> daemon
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FromApprover {
    /// First message on every connection: 32 random bytes, base64.
    Hello { challenge: String },
    /// `sig` is required for approve: base64 DER ECDSA-P256-SHA256 over
    /// `Request::canonical_bytes()`.
    Decision {
        id: String,
        approve: bool,
        sig: Option<String>,
    },
    Pong,
}

// -------------------------------------------------------------- validation

/// Characters that can hide or disguise what a command really does on screen.
pub fn is_suspicious_char(c: char, allow_newline: bool) -> bool {
    if c == '\n' && allow_newline {
        return false;
    }
    c.is_control()
        || matches!(c,
            '\u{00AD}'                // soft hyphen
            | '\u{061C}'              // arabic letter mark
            | '\u{180E}'              // mongolian vowel separator
            | '\u{200B}'..='\u{200F}' // zero-width, LRM/RLM
            | '\u{2028}'..='\u{202E}' // line/para separators, bidi embeddings/overrides
            | '\u{2060}'..='\u{2064}' // word joiner, invisible operators
            | '\u{2066}'..='\u{2069}' // bidi isolates
            | '\u{FEFF}'              // BOM / zero-width no-break space
            | '\u{FFF9}'..='\u{FFFB}' // interlinear annotations
            // Blank-looking letters and odd spaces (pentest finding)
            | '\u{00A0}' | '\u{1680}' | '\u{2000}'..='\u{200A}' | '\u{202F}' | '\u{205F}'
            | '\u{3000}' | '\u{3164}' | '\u{FFA0}' | '\u{2800}' | '\u{115F}' | '\u{1160}'
            | '\u{034F}' | '\u{17B4}' | '\u{17B5}'
            // Combining marks can overlay/strike characters
            | '\u{0300}'..='\u{036F}' | '\u{1AB0}'..='\u{1AFF}' | '\u{1DC0}'..='\u{1DFF}'
            | '\u{20D0}'..='\u{20FF}' | '\u{FE20}'..='\u{FE2F}'
            // Variation selectors, tags, private use
            | '\u{FE00}'..='\u{FE0F}' | '\u{E0000}'..='\u{E007F}' | '\u{E0100}'..='\u{E01EF}'
            | '\u{E000}'..='\u{F8FF}' | '\u{F0000}'..='\u{10FFFF}'
        )
}

pub fn validate_argv(argv: &[String]) -> Result<(), String> {
    if argv.is_empty() {
        return Err("empty command".into());
    }
    if argv.len() > MAX_ARGS {
        return Err(format!("too many arguments (max {MAX_ARGS})"));
    }
    let mut total = 0usize;
    for (i, a) in argv.iter().enumerate() {
        if a.len() > MAX_ARG_BYTES {
            return Err(format!("argument {i} is too long (max {MAX_ARG_BYTES} bytes)"));
        }
        total += a.len();
        if let Some(c) = a.chars().find(|&c| is_suspicious_char(c, false)) {
            return Err(format!(
                "argument {i} contains a hidden/control character U+{:04X}",
                c as u32
            ));
        }
    }
    if total > MAX_TOTAL_ARG_BYTES {
        return Err(format!("arguments too long in total (max {MAX_TOTAL_ARG_BYTES} bytes)"));
    }
    let exe = &argv[0];
    if !exe.starts_with('/') {
        return Err("argv[0] must be an absolute path".into());
    }
    if exe.split('/').any(|c| c == "." || c == "..") || exe.contains("//") || exe.ends_with('/') {
        return Err("argv[0] must be a plain absolute path (no '.', '..', '//')".into());
    }
    Ok(())
}

/// Default policy: arguments are printable ASCII only, so nothing can look like
/// something else (homoglyphs, blank letters). Can be relaxed in the config.
pub fn check_ascii_args(argv: &[String]) -> Result<(), String> {
    for (i, a) in argv.iter().enumerate() {
        if let Some(c) = a.chars().find(|c| !(' '..='~').contains(c)) {
            return Err(format!(
                "argument {i} contains non-ASCII character U+{:04X} (set allow_non_ascii_args to permit)",
                c as u32
            ));
        }
    }
    Ok(())
}

pub fn validate_why(why: &str) -> Result<(), String> {
    if why.trim().is_empty() {
        return Err("a reason (why) is required".into());
    }
    if why.chars().count() > MAX_WHY_CHARS {
        return Err(format!("reason too long (max {MAX_WHY_CHARS} characters)"));
    }
    if let Some(c) = why.chars().find(|&c| is_suspicious_char(c, true)) {
        return Err(format!("reason contains a hidden/control character U+{:04X}", c as u32));
    }
    Ok(())
}

// ---------------------------------------------------------------- crypto

/// Parse an enrolled phone key: base64 of X.509 SubjectPublicKeyInfo DER,
/// which is what Android's `PublicKey.getEncoded()` returns.
pub fn parse_public_key(b64: &str) -> Result<VerifyingKey, String> {
    let der = B64
        .decode(b64.trim())
        .map_err(|e| format!("public key is not base64: {e}"))?;
    VerifyingKey::from_public_key_der(&der).map_err(|e| format!("not a P-256 public key: {e}"))
}

pub fn encode_public_key(vk: &VerifyingKey) -> String {
    let doc = vk.to_public_key_der().expect("encoding a valid key cannot fail");
    B64.encode(doc.as_bytes())
}

/// True if `sig_b64` is a valid signature over `canonical` by one of `keys`.
pub fn verify_approval(keys: &[VerifyingKey], canonical: &[u8], sig_b64: &str) -> bool {
    if sig_b64.len() > 200 {
        return false;
    }
    let Ok(der) = B64.decode(sig_b64.trim()) else {
        return false;
    };
    if der.len() > MAX_SIG_DER {
        return false;
    }
    let Ok(sig) = Signature::from_der(&der) else {
        return false;
    };
    // Android may produce high-S signatures; accept both forms.
    let sig = sig.normalize_s();
    keys.iter().any(|k| k.verify(canonical, &sig).is_ok())
}

fn put_str2(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s.as_bytes());
}

/// What the daemon signs to answer the phone's challenge.
pub fn hello_bytes(challenge: &str, host: &str, daemon_key: &str) -> Vec<u8> {
    let mut out = HELLO_MAGIC.to_vec();
    put_str2(&mut out, challenge);
    put_str2(&mut out, host);
    put_str2(&mut out, daemon_key);
    out
}

/// What the daemon signs for every request it shows on the phone.
pub fn daemon_request_bytes(req: &Request, warnings: &[String]) -> Vec<u8> {
    let mut out = DREQ_MAGIC.to_vec();
    let c = req.canonical_bytes();
    out.extend_from_slice(&(c.len() as u32).to_be_bytes());
    out.extend_from_slice(&c);
    out.extend_from_slice(&(warnings.len() as u32).to_be_bytes());
    for w in warnings {
        put_str2(&mut out, w);
    }
    out
}

/// Base64 DER ECDSA-P256-SHA256 signature over `msg`.
pub fn sign_bytes(sk: &SigningKey, msg: &[u8]) -> String {
    let sig: Signature = sk.sign(msg);
    B64.encode(sig.to_der().as_bytes())
}

/// SHA-256 of the SPKI, first 8 bytes, "AB:CD:..." (same as the app shows).
pub fn fingerprint(vk: &VerifyingKey) -> String {
    let doc = vk.to_public_key_der().expect("valid key");
    Sha256::digest(doc.as_bytes())[..8]
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Sign a request (used by the dev approver and the tests; the phone does the
/// equivalent with SHA256withECDSA in the Android Keystore).
pub fn sign_request(sk: &SigningKey, req: &Request) -> String {
    let sig: Signature = sk.sign(&req.canonical_bytes());
    B64.encode(sig.to_der().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Request {
        Request {
            id: "00112233445566778899aabbccddeeff".into(),
            nonce: "bm9uY2U=".into(),
            created: 1_000,
            expires: 1_120,
            uid: 1000,
            user: "alice".into(),
            host: "laptop".into(),
            argv: vec!["/usr/sbin/ufw".into(), "status".into()],
            why: "check firewall".into(),
        }
    }

    /// Cross-checked with an independent Python implementation of the encoding.
    const KNOWN_SHA256: &str = "01456f2b5905c964399d2d52ad5a40db00347009233e83e0a32630de68170037";

    fn key() -> SigningKey {
        SigningKey::from_slice(&[7u8; 32]).unwrap()
    }

    #[test]
    fn canonical_is_deterministic_and_unambiguous() {
        let a = sample();
        assert_eq!(a.canonical_bytes(), a.clone().canonical_bytes());
        // Moving a character between adjacent args must change the bytes.
        let mut b = a.clone();
        b.argv = vec!["/usr/sbin/uf".into(), "wstatus".into()];
        assert_ne!(a.canonical_bytes(), b.canonical_bytes());
        // Moving text between argv and why must change the bytes.
        let mut c = a.clone();
        c.argv = vec!["/usr/sbin/ufw".into()];
        c.why = "status".into();
        assert_ne!(a.canonical_bytes(), c.canonical_bytes());
        assert!(a.canonical_bytes().starts_with(MAGIC));
    }

    #[test]
    fn canonical_known_answer() {
        // Pinned so the Android implementation can be checked against it.
        let bytes = sample().canonical_bytes();
        // magic, id, nonce, created, expires, uid, user, host, argc, argv[0], argv[1], why
        assert_eq!(bytes.len(), 12 + 36 + 12 + 8 + 8 + 4 + 9 + 10 + 4 + 17 + 10 + 18);
        assert_eq!(crate::hex(&Sha256::digest(&bytes)), KNOWN_SHA256);
    }

    #[test]
    fn short_code_format() {
        let code = sample().code();
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| "ABCDEFGHJKLMNPQRSTUVWXYZ23456789".contains(c)));
        let mut other = sample();
        other.argv[1] = "disable".into();
        assert_ne!(code, other.code());
    }

    #[test]
    fn sign_and_verify() {
        let sk = key();
        let vk = *sk.verifying_key();
        let req = sample();
        let sig = sign_request(&sk, &req);
        assert!(verify_approval(&[vk], &req.canonical_bytes(), &sig));

        let mut tampered = req.clone();
        tampered.argv[1] = "disable".into();
        assert!(!verify_approval(&[vk], &tampered.canonical_bytes(), &sig));

        let other = SigningKey::from_slice(&[9u8; 32]).unwrap();
        assert!(!verify_approval(&[*other.verifying_key()], &req.canonical_bytes(), &sig));

        assert!(!verify_approval(&[vk], &req.canonical_bytes(), "not base64!"));
        assert!(!verify_approval(&[vk], &req.canonical_bytes(), ""));
        assert!(!verify_approval(&[], &req.canonical_bytes(), &sig));
    }

    #[test]
    fn public_key_roundtrip() {
        let vk = *key().verifying_key();
        let enc = encode_public_key(&vk);
        assert_eq!(parse_public_key(&enc).unwrap(), vk);
        assert!(parse_public_key("AAAA").is_err());
    }

    #[test]
    fn argv_validation() {
        let ok = |v: &[&str]| validate_argv(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        assert!(ok(&["/usr/sbin/ufw", "status"]).is_ok());
        assert!(ok(&[]).is_err());
        assert!(ok(&["ufw"]).is_err());
        assert!(ok(&["/usr/../bin/sh"]).is_err());
        assert!(ok(&["/usr/bin/./sh"]).is_err());
        assert!(ok(&["/usr//bin/sh"]).is_err());
        assert!(ok(&["/usr/bin/echo", "a\nb"]).is_err());
        assert!(ok(&["/usr/bin/echo", "a\tb"]).is_err());
        assert!(ok(&["/usr/bin/echo", "safe\u{202E}fdp.exe"]).is_err());
        assert!(ok(&["/usr/bin/echo", "zero\u{200B}width"]).is_err());
        assert!(ok(&["/usr/bin/echo", "\u{1b}[2J"]).is_err());
        assert!(ok(&["/usr/bin/echo", "čeština je ok"]).is_ok());
        let long = "x".repeat(MAX_ARG_BYTES + 1);
        assert!(ok(&["/usr/bin/echo", &long]).is_err());
        let many: Vec<&str> = std::iter::once("/usr/bin/echo").chain(std::iter::repeat_n("a", MAX_ARGS)).collect();
        assert!(ok(&many).is_err());
        let chunk = "x".repeat(MAX_ARG_BYTES);
        let total: Vec<&str> = std::iter::once("/usr/bin/echo").chain(std::iter::repeat_n(chunk.as_str(), 5)).collect();
        assert!(ok(&total).is_err());
    }

    #[test]
    fn why_validation() {
        assert!(validate_why("Open RDP for lab PC\nonly this IP").is_ok());
        assert!(validate_why("   ").is_err());
        assert!(validate_why(&"á".repeat(MAX_WHY_CHARS)).is_ok());
        assert!(validate_why(&"á".repeat(MAX_WHY_CHARS + 1)).is_err());
        assert!(validate_why("harmless\u{202E}").is_err());
        assert!(validate_why("bell\u{7}").is_err());
    }
}
