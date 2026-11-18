//! Cross-language check: a signature made by Java's SHA256withECDSA (same as the
//! Android Keystore) over the known-answer request must verify in the daemon.
//! The Android unit tests write the vector:
//!   (cd android && ./gradlew testDebugUnitTest)
//!   cargo test --test cross_verify -- --ignored

use rootgate::proto::{self, Request};

#[test]
#[ignore]
fn java_signature_verifies_in_rust() {
    let path = std::env::var("ROOTGATE_VECTOR")
        .unwrap_or_else(|_| "android/app/build/rootgate-cross-vector.txt".into());
    let text = std::fs::read_to_string(&path).expect("run the Android unit tests first");
    let mut lines = text.lines();
    let pubkey = proto::parse_public_key(lines.next().unwrap()).unwrap();
    let sig = lines.next().unwrap();
    let req = Request {
        id: "00112233445566778899aabbccddeeff".into(),
        nonce: "bm9uY2U=".into(),
        created: 1000,
        expires: 1120,
        uid: 1000,
        user: "alice".into(),
        host: "laptop".into(),
        argv: vec!["/usr/sbin/ufw".into(), "status".into()],
        why: "check firewall".into(),
    };
    assert_eq!(req.code(), "AFCY8L");
    assert!(proto::verify_approval(&[pubkey], &req.canonical_bytes(), sig), "Java signature rejected");
    let mut tampered = req.clone();
    tampered.argv[1] = "disable".into();
    assert!(!proto::verify_approval(&[pubkey], &tampered.canonical_bytes(), sig));
}
