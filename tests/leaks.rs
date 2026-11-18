//! Leak check: many full request cycles (approve, deny, withdraw, expire, phone
//! reconnects) must not grow file descriptors, threads or memory.
//! Run alone: cargo test --release --test leaks -- --ignored --nocapture

use p256::ecdsa::SigningKey;
use rootgate::daemon::{self, Config};
use rootgate::net::{read_line_bounded, send_json};
use rootgate::proto::{self, ClientMsg, FromApprover, ToApprover, ToClient};
use std::io::BufReader;
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::time::Duration;

fn key() -> SigningKey {
    SigningKey::from_slice(&[42u8; 32]).unwrap()
}

fn count(dir: &str) -> usize {
    std::fs::read_dir(dir).unwrap().count()
}

fn rss_kib() -> usize {
    let s = std::fs::read_to_string("/proc/self/status").unwrap();
    s.lines()
        .find(|l| l.starts_with("VmRSS:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .unwrap()
}

fn recv<T: serde::de::DeserializeOwned, R: std::io::BufRead>(r: &mut R) -> T {
    serde_json::from_str(&read_line_bounded(r, 1 << 24).unwrap().unwrap()).unwrap()
}

/// Wait for the request carrying `tag`. A fresh phone connection also receives
/// requests that are still pending from before (e.g. one being withdrawn), and the
/// phone must answer pings, like the real app.
fn next_request(r: &mut BufReader<TcpStream>, w: &mut TcpStream, tag: &str) -> proto::Request {
    loop {
        match recv::<ToApprover, _>(r) {
            ToApprover::Request { request, .. } if request.argv.get(1).map(String::as_str) == Some(tag) => return request,
            ToApprover::Ping => send_json(w, &FromApprover::Pong).unwrap(),
            _ => {}
        }
    }
}


/// Phone side of the v2 handshake: send a challenge, check the daemon's answer.
fn phone_hello(w: &mut TcpStream) -> String {
    use base64::{Engine, engine::general_purpose::STANDARD as B64};
    let challenge = B64.encode(rootgate::random_bytes::<32>());
    send_json(w, &FromApprover::Hello { challenge: challenge.clone() }).unwrap();
    challenge
}

#[test]
#[ignore]
fn no_growth_over_many_cycles() {
    let dir = std::env::temp_dir().join(format!("rootgate-leak-{}", rootgate::hex(&rootgate::random_bytes::<4>())));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = Config {
        socket_path: dir.join("s.sock"),
        listen: "127.0.0.1:0".into(),
        bind_device: None,
        approver_ips: vec!["127.0.0.1".parse().unwrap()],
        approver_pubkeys: vec![proto::encode_public_key(key().verifying_key())],
        allowed_uids: vec![unsafe { libc::getuid() }],
        request_ttl_secs: 30,
        exec_timeout_secs: 10,
        output_cap_bytes: 64 * 1024,
        max_pending: 8,
        max_approvers: 4,
        max_clients: 16,
        ping_secs: 1,
        require_trusted_exe: true,
        daemon_key_path: dir.join("daemon.key"),
        allow_non_ascii_args: false,
    };
    let h = daemon::start(cfg).unwrap();

    let cycle = |i: usize| {
        // A fresh phone connection every 10 cycles exercises connect/disconnect.
        let s = TcpStream::connect(h.tcp_addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut pw = s.try_clone().unwrap();
        let mut pr = BufReader::new(s);
        phone_hello(&mut pw);
        for j in 0..10 {
            let c = UnixStream::connect(&h.socket_path).unwrap();
            c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            let mut cw = c.try_clone().unwrap();
            let mut cr = BufReader::new(c);
            let tag = format!("{i}-{j}");
            send_json(&mut cw, &ClientMsg::Submit { argv: vec!["/usr/bin/echo".into(), tag.clone()], why: "leak test".into() }).unwrap();
            assert!(matches!(recv::<ToClient, _>(&mut cr), ToClient::Pending { .. }));
            let req = next_request(&mut pr, &mut pw, &tag);
            match j % 3 {
                0 => {
                    let sig = proto::sign_request(&key(), &req);
                    send_json(&mut pw, &FromApprover::Decision { id: req.id, approve: true, sig: Some(sig) }).unwrap();
                    assert!(matches!(recv::<ToClient, _>(&mut cr), ToClient::Result { .. }));
                }
                1 => {
                    send_json(&mut pw, &FromApprover::Decision { id: req.id, approve: false, sig: None }).unwrap();
                    assert!(matches!(recv::<ToClient, _>(&mut cr), ToClient::Denied { .. }));
                }
                _ => {
                    // Bad signature, then the requester walks away.
                    send_json(&mut pw, &FromApprover::Decision { id: req.id, approve: true, sig: Some("AAAA".into()) }).unwrap();
                    drop(cr);
                    drop(cw);
                }
            }
        }
        // Phone goes away abruptly.
        drop(pr);
        drop(pw);
    };

    // Warm-up so lazily allocated things (thread stacks, caches) are counted once.
    for i in 0..3 {
        cycle(i);
    }
    std::thread::sleep(Duration::from_millis(1500));
    let (fd0, th0, rss0) = (count("/proc/self/fd"), count("/proc/self/task"), rss_kib());

    for i in 3..53 {
        cycle(i); // 500 requests
    }
    std::thread::sleep(Duration::from_millis(1500));
    let (fd1, th1, rss1) = (count("/proc/self/fd"), count("/proc/self/task"), rss_kib());

    println!("fds {fd0} -> {fd1}, threads {th0} -> {th1}, rss {rss0} KiB -> {rss1} KiB");
    assert!(fd1 <= fd0 + 2, "fd leak: {fd0} -> {fd1}");
    assert!(th1 <= th0 + 1, "thread leak: {th0} -> {th1}");
    assert!(rss1 <= rss0 + 4096, "memory grew: {rss0} -> {rss1} KiB");

    h.shutdown();
    std::fs::remove_dir_all(&dir).unwrap();
}
