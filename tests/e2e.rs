//! End-to-end tests: a real daemon (as the current user), a fake phone over TCP
//! and a client over the Unix socket.

use p256::ecdsa::SigningKey;
use rootgate::daemon::{self, Config, Handle};
use rootgate::net::{read_line_bounded, send_json};
use rootgate::proto::{self, ClientMsg, FromApprover, Request, ToApprover, ToClient};
use std::io::{BufReader, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::{Duration, Instant};

const BIG: usize = 16 * 1024 * 1024;

fn phone_key() -> SigningKey {
    SigningKey::from_slice(&[42u8; 32]).unwrap()
}

fn config(tag: &str) -> Config {
    let dir = std::env::temp_dir().join(format!("rootgate-e2e-{tag}-{}", rootgate::hex(&rootgate::random_bytes::<4>())));
    std::fs::create_dir_all(&dir).unwrap();
    Config {
        socket_path: dir.join("s.sock"),
        listen: "127.0.0.1:0".into(),
        bind_device: None,
        approver_ips: vec!["127.0.0.1".parse().unwrap()],
        approver_pubkeys: vec![proto::encode_public_key(phone_key().verifying_key())],
        allowed_uids: vec![unsafe { libc::getuid() }],
        request_ttl_secs: 30,
        exec_timeout_secs: 10,
        output_cap_bytes: 64 * 1024,
        max_pending: 8,
        max_approvers: 4,
        max_clients: 16,
        ping_secs: 30,
        require_trusted_exe: true,
        daemon_key_path: dir.join("daemon.key"),
        allow_non_ascii_args: false,
    }
}

struct Phone {
    r: BufReader<TcpStream>,
    w: TcpStream,
    daemon_key: String,
    last_warnings: Vec<String>,
}
/// Phone side of the v2 handshake: send a challenge, check the daemon's answer.
fn phone_hello(w: &mut TcpStream) -> String {
    use base64::{Engine, engine::general_purpose::STANDARD as B64};
    let challenge = B64.encode(rootgate::random_bytes::<32>());
    send_json(w, &FromApprover::Hello { challenge: challenge.clone() }).unwrap();
    challenge
}


impl Phone {
    fn connect(h: &Handle) -> Phone {
        let s = TcpStream::connect(h.tcp_addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut p = Phone { w: s.try_clone().unwrap(), r: BufReader::new(s), daemon_key: h.daemon_key.clone(), last_warnings: vec![] };
        let challenge = phone_hello(&mut p.w);
        match p.recv() {
            ToApprover::Hello { host, proto: 2, daemon_key, sig } => {
                assert_eq!(daemon_key, h.daemon_key, "daemon must present its pinned key");
                let vk = proto::parse_public_key(&daemon_key).unwrap();
                assert!(proto::verify_approval(&[vk], &proto::hello_bytes(&challenge, &host, &daemon_key), &sig));
            }
            other => panic!("expected hello, got {other:?}"),
        }
        p
    }
    fn recv(&mut self) -> ToApprover {
        let line = read_line_bounded(&mut self.r, BIG).unwrap().expect("daemon closed");
        serde_json::from_str(&line).unwrap()
    }
    fn next_request(&mut self) -> (Request, String) {
        loop {
            match self.recv() {
                ToApprover::Request { request, code, warnings, dsig } => {
                    let vk = proto::parse_public_key(&self.daemon_key).unwrap();
                    assert!(
                        proto::verify_approval(&[vk], &proto::daemon_request_bytes(&request, &warnings), &dsig),
                        "request not signed by daemon"
                    );
                    self.last_warnings = warnings;
                    return (request, code);
                }
                ToApprover::Ping => {}
                other => panic!("expected request, got {other:?}"),
            }
        }
    }
    fn send(&mut self, m: &FromApprover) {
        send_json(&mut self.w, m).unwrap();
    }
    fn approve(&mut self, req: &Request) {
        let sig = proto::sign_request(&phone_key(), req);
        self.send(&FromApprover::Decision { id: req.id.clone(), approve: true, sig: Some(sig) });
    }
}

struct Client {
    r: BufReader<UnixStream>,
    #[allow(dead_code)]
    w: UnixStream,
}

impl Client {
    fn submit(h: &Handle, argv: &[&str], why: &str) -> Client {
        let s = UnixStream::connect(&h.socket_path).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
        let mut w = s.try_clone().unwrap();
        send_json(&mut w, &ClientMsg::Submit { argv: argv.iter().map(|s| s.to_string()).collect(), why: why.into() }).unwrap();
        Client { r: BufReader::new(s), w }
    }
    fn recv(&mut self) -> ToClient {
        let line = read_line_bounded(&mut self.r, BIG).unwrap().expect("daemon closed");
        serde_json::from_str(&line).unwrap()
    }
    fn pending(&mut self) -> String {
        match self.recv() {
            ToClient::Pending { code, .. } => code,
            other => panic!("expected pending, got {other:?}"),
        }
    }
}

fn start(cfg: Config) -> Handle {
    daemon::start(cfg).unwrap()
}

fn echo() -> &'static str {
    "/usr/bin/echo"
}

#[test]
fn approved_command_runs_and_codes_match() {
    let h = start(config("approve"));
    let mut phone = Phone::connect(&h);
    let mut c = Client::submit(&h, &[echo(), "hello", "$(id)"], "say hello");
    let code = c.pending();
    let (req, phone_code) = phone.next_request();
    assert_eq!(code, phone_code);
    assert_eq!(req.code(), code, "phone can recompute the code");
    assert_eq!(req.argv, vec![echo(), "hello", "$(id)"]);
    assert_eq!(req.why, "say hello");
    phone.approve(&req);
    match c.recv() {
        ToClient::Result { exit_code, stdout, timed_out, .. } => {
            assert_eq!(exit_code, Some(0));
            assert_eq!(stdout, "hello $(id)\n");
            assert!(!timed_out);
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(phone.recv(), ToApprover::Cancel { reason, .. } if reason == "approved"));
    h.shutdown();
}

#[test]
fn denied_command_does_not_run() {
    let h = start(config("deny"));
    let mut phone = Phone::connect(&h);
    let marker = std::env::temp_dir().join(format!("rootgate-deny-{}", rootgate::hex(&rootgate::random_bytes::<4>())));
    let mut c = Client::submit(&h, &["/usr/bin/touch", marker.to_str().unwrap()], "should not happen");
    c.pending();
    let (req, _) = phone.next_request();
    phone.send(&FromApprover::Decision { id: req.id, approve: false, sig: None });
    assert!(matches!(c.recv(), ToClient::Denied { .. }));
    assert!(!marker.exists());
    h.shutdown();
}

#[test]
fn forged_or_mismatched_signatures_are_rejected_and_request_stays_pending() {
    let h = start(config("forged"));
    let mut phone = Phone::connect(&h);
    let mut c = Client::submit(&h, &[echo(), "safe"], "harmless");
    c.pending();
    let (req, _) = phone.next_request();

    // 1. Signature over a different command.
    let mut evil = req.clone();
    evil.argv = vec!["/usr/bin/rm".into(), "-rf".into(), "/".into()];
    let sig = proto::sign_request(&phone_key(), &evil);
    phone.send(&FromApprover::Decision { id: req.id.clone(), approve: true, sig: Some(sig) });
    assert!(matches!(phone.recv(), ToApprover::Error { message, .. } if message == "invalid signature"));

    // 2. Right request, wrong key.
    let other = SigningKey::from_slice(&[1u8; 32]).unwrap();
    let sig = proto::sign_request(&other, &req);
    phone.send(&FromApprover::Decision { id: req.id.clone(), approve: true, sig: Some(sig) });
    assert!(matches!(phone.recv(), ToApprover::Error { message, .. } if message == "invalid signature"));

    // 3. Approve without a signature.
    phone.send(&FromApprover::Decision { id: req.id.clone(), approve: true, sig: None });
    assert!(matches!(phone.recv(), ToApprover::Error { message, .. } if message == "invalid signature"));

    // 4. Garbage.
    phone.send(&FromApprover::Decision { id: req.id.clone(), approve: true, sig: Some("AAAA".repeat(100)) });
    assert!(matches!(phone.recv(), ToApprover::Error { .. }));

    // Still pending: the real approval works.
    phone.approve(&req);
    assert!(matches!(c.recv(), ToClient::Result { exit_code: Some(0), .. }));
    h.shutdown();
}

#[test]
fn approvals_cannot_be_replayed() {
    let h = start(config("replay"));
    let mut phone = Phone::connect(&h);
    let mut c = Client::submit(&h, &[echo(), "once"], "replay test");
    c.pending();
    let (req, _) = phone.next_request();
    let sig = proto::sign_request(&phone_key(), &req);
    phone.send(&FromApprover::Decision { id: req.id.clone(), approve: true, sig: Some(sig.clone()) });
    assert!(matches!(c.recv(), ToClient::Result { .. }));
    assert!(matches!(phone.recv(), ToApprover::Cancel { .. }));

    // Same decision again: request is gone.
    phone.send(&FromApprover::Decision { id: req.id.clone(), approve: true, sig: Some(sig.clone()) });
    assert!(matches!(phone.recv(), ToApprover::Error { message, .. } if message.starts_with("unknown request")));

    // Old signature on a new, identical-looking request: new id and nonce, so invalid.
    let mut c2 = Client::submit(&h, &[echo(), "once"], "replay test");
    c2.pending();
    let (req2, _) = phone.next_request();
    assert_ne!(req2.nonce, req.nonce);
    phone.send(&FromApprover::Decision { id: req2.id.clone(), approve: true, sig: Some(sig) });
    assert!(matches!(phone.recv(), ToApprover::Error { message, .. } if message == "invalid signature"));
    h.shutdown();
}

#[test]
fn requests_expire() {
    let mut cfg = config("expire");
    cfg.request_ttl_secs = 1;
    let h = start(cfg);
    let mut phone = Phone::connect(&h);
    let mut c = Client::submit(&h, &[echo(), "late"], "expiry test");
    c.pending();
    let (req, _) = phone.next_request();
    assert!(matches!(c.recv(), ToClient::Expired { .. }));
    assert!(matches!(phone.recv(), ToApprover::Cancel { reason, .. } if reason == "expired"));
    phone.approve(&req);
    assert!(matches!(phone.recv(), ToApprover::Error { .. }));
    h.shutdown();
}

#[test]
fn untrusted_and_malformed_requests_are_refused() {
    let h = start(config("refuse"));
    let dir = std::env::temp_dir().join(format!("rootgate-untrusted-{}", rootgate::hex(&rootgate::random_bytes::<4>())));
    std::fs::create_dir_all(&dir).unwrap();
    let script = dir.join("x.sh");
    std::fs::write(&script, "#!/bin/sh\nid\n").unwrap();
    std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();

    let cases: Vec<(Vec<&str>, &str)> = vec![
        (vec![script.to_str().unwrap()], "user-owned script"),
        (vec!["echo", "x"], "relative path"),
        (vec![echo(), "a\u{202E}b"], "bidi override"),
        (vec![echo(), "x"], ""),
        (vec![echo(), "x"], "bad\u{7}why"),
        (vec![], "empty"),
    ];
    for (argv, why) in cases {
        let mut c = Client::submit(&h, &argv, why);
        assert!(matches!(c.recv(), ToClient::Error { .. }), "{argv:?} / {why:?} should be refused");
    }
    std::fs::remove_dir_all(&dir).unwrap();
    h.shutdown();
}

#[test]
fn other_users_are_refused() {
    let mut cfg = config("uid");
    cfg.allowed_uids = vec![unsafe { libc::getuid() } + 4242];
    let h = start(cfg);
    let mut c = Client::submit(&h, &[echo(), "x"], "not me");
    assert!(matches!(c.recv(), ToClient::Error { message } if message.contains("not allowed")));
    h.shutdown();
}

#[test]
fn unknown_approver_ips_are_dropped() {
    let mut cfg = config("ip");
    cfg.approver_ips = vec!["127.0.0.2".parse().unwrap()];
    let h = start(cfg);
    let s = TcpStream::connect(h.tcp_addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let mut r = BufReader::new(s);
    // No hello, connection closed.
    assert!(matches!(read_line_bounded(&mut r, 1024), Ok(None) | Err(_)));
    h.shutdown();
}

#[test]
fn requester_leaving_withdraws_the_request() {
    let h = start(config("withdraw"));
    let mut phone = Phone::connect(&h);
    let mut c = Client::submit(&h, &[echo(), "bye"], "withdraw test");
    c.pending();
    let (req, _) = phone.next_request();
    drop(c);
    assert!(matches!(phone.recv(), ToApprover::Cancel { id, reason } if id == req.id && reason == "requester disconnected"));
    h.shutdown();
}

#[test]
fn late_phone_sees_pending_requests() {
    let h = start(config("late"));
    let mut c = Client::submit(&h, &[echo(), "queued"], "phone connects later");
    let code = c.pending();
    let mut phone = Phone::connect(&h);
    let (req, phone_code) = phone.next_request();
    assert_eq!(code, phone_code);
    phone.approve(&req);
    assert!(matches!(c.recv(), ToClient::Result { .. }));
    h.shutdown();
}

#[test]
fn exec_timeout_is_reported() {
    let mut cfg = config("timeout");
    cfg.exec_timeout_secs = 1;
    let h = start(cfg);
    let mut phone = Phone::connect(&h);
    let mut c = Client::submit(&h, &["/usr/bin/sleep", "30"], "timeout test");
    c.pending();
    let (req, _) = phone.next_request();
    let t = Instant::now();
    phone.approve(&req);
    assert!(matches!(c.recv(), ToClient::Result { timed_out: true, .. }));
    assert!(t.elapsed() < Duration::from_secs(6));
    h.shutdown();
}

#[test]
fn pending_limit_and_oversized_input() {
    let mut cfg = config("limits");
    cfg.max_pending = 2;
    let h = start(cfg);
    let mut a = Client::submit(&h, &[echo(), "1"], "one");
    a.pending();
    let mut b = Client::submit(&h, &[echo(), "2"], "two");
    b.pending();
    let mut c = Client::submit(&h, &[echo(), "3"], "three");
    assert!(matches!(c.recv(), ToClient::Error { message } if message.contains("too many")));

    // A huge line without newline must not be buffered forever.
    let mut s = UnixStream::connect(&h.socket_path).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let junk = vec![b'x'; 200 * 1024];
    let _ = s.write_all(&junk);
    let mut r = BufReader::new(s);
    assert!(matches!(read_line_bounded(&mut r, 1024), Ok(None) | Err(_)));
    h.shutdown();
}

#[test]
fn shutdown_removes_socket() {
    let h = start(config("shutdown"));
    let p: PathBuf = h.socket_path.clone();
    assert!(p.exists());
    h.shutdown();
    assert!(!p.exists());
}

#[test]
fn daemon_key_persists_and_impostor_is_detected() {
    // Same key file -> same identity across restarts.
    let cfg = config("ident");
    let key_path = cfg.daemon_key_path.clone();
    let h = start(cfg.clone());
    let first = h.daemon_key.clone();
    h.shutdown();
    let mut cfg2 = cfg.clone();
    cfg2.socket_path = cfg.socket_path.with_extension("2");
    let h2 = start(cfg2);
    assert_eq!(h2.daemon_key, first);
    h2.shutdown();
    // A different daemon (copied code, pasted phone key) has a different identity.
    let impostor = start(config("impostor"));
    assert_ne!(impostor.daemon_key, first, "an impostor must not share the identity");
    // Its answer to our challenge does not verify against the pinned key.
    let s = TcpStream::connect(impostor.tcp_addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut w = s.try_clone().unwrap();
    let mut r = BufReader::new(s);
    let challenge = phone_hello(&mut w);
    let line = read_line_bounded(&mut r, 1 << 16).unwrap().unwrap();
    let ToApprover::Hello { host, sig, .. } = serde_json::from_str(&line).unwrap() else { panic!() };
    let pinned = proto::parse_public_key(&first).unwrap();
    assert!(!proto::verify_approval(&[pinned], &proto::hello_bytes(&challenge, &host, &first), &sig));
    impostor.shutdown();
    assert!(key_path.exists());
}

#[test]
fn non_ascii_args_refused_and_warnings_sent() {
    let h = start(config("ascii"));
    let mut c = Client::submit(&h, &[echo(), "1\u{041E}\u{041E}.0.0.1"], "cyrillic O");
    assert!(matches!(c.recv(), ToClient::Error { message } if message.contains("non-ASCII")));
    let mut c = Client::submit(&h, &[echo(), "a\u{3164}b"], "hangul filler");
    assert!(matches!(c.recv(), ToClient::Error { .. }));
    // Czech in the reason is fine.
    let mut phone = Phone::connect(&h);
    let mut c = Client::submit(&h, &["/usr/bin/sh", "-c", "id"], "česky: spustit shell");
    c.pending();
    let (req, _) = phone.next_request();
    assert_eq!(phone.last_warnings.len(), 1, "{:?}", phone.last_warnings);
    phone.send(&FromApprover::Decision { id: req.id, approve: false, sig: None });
    assert!(matches!(c.recv(), ToClient::Denied { .. }));
    h.shutdown();
}

#[test]
fn phone_that_skips_the_challenge_gets_nothing() {
    let h = start(config("nochal"));
    let mut c = Client::submit(&h, &[echo(), "secret-ish"], "should not leak");
    c.pending();
    let s = TcpStream::connect(h.tcp_addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
    let mut r = BufReader::new(s);
    // Never sends hello: must be dropped without seeing the pending request.
    assert!(matches!(read_line_bounded(&mut r, 1 << 16), Ok(None) | Err(_)));
    h.shutdown();
}
