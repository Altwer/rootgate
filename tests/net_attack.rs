//! Network attack tests against the phone port (and the local socket).
//! Every test ends by proving the daemon still works for the real phone.

use p256::ecdsa::SigningKey;
use rootgate::daemon::{self, Config, Handle};
use rootgate::net::{read_line_bounded, send_json};
use rootgate::proto::{self, ClientMsg, FromApprover, Request, ToApprover, ToClient};
use std::io::{BufReader, Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

/// These tests count process-wide threads, so they must not overlap.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|p| p.into_inner())
}

fn key() -> SigningKey {
    SigningKey::from_slice(&[42u8; 32]).unwrap()
}

fn config(tag: &str) -> Config {
    let dir = std::env::temp_dir().join(format!("rootgate-atk-{tag}-{}", rootgate::hex(&rootgate::random_bytes::<4>())));
    std::fs::create_dir_all(&dir).unwrap();
    Config {
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
        ping_secs: 30,
        require_trusted_exe: true,
    }
}

fn threads() -> usize {
    std::fs::read_dir("/proc/self/task").unwrap().count()
}

fn connect(h: &Handle) -> TcpStream {
    let s = TcpStream::connect(h.tcp_addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s
}

/// True if the daemon closes the connection without sending a single byte.
fn closed_silently(mut s: TcpStream) -> bool {
    let mut b = [0u8; 1];
    matches!(s.read(&mut b), Ok(0) | Err(_))
}

/// Full happy path: submit, approve from a fresh phone, get the result.
fn still_works(h: &Handle) {
    let s = connect(h);
    let mut pw = s.try_clone().unwrap();
    let mut pr = BufReader::new(s);
    let tag = rootgate::hex(&rootgate::random_bytes::<4>());
    let c = UnixStream::connect(&h.socket_path).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut cw = c.try_clone().unwrap();
    let mut cr = BufReader::new(c);
    send_json(&mut cw, &ClientMsg::Submit { argv: vec!["/usr/bin/echo".into(), tag.clone()], why: "health check".into() }).unwrap();
    let req: Request = loop {
        let line = read_line_bounded(&mut pr, 1 << 20).unwrap().expect("phone port closed");
        if let Ok(ToApprover::Request { request, .. }) = serde_json::from_str(&line)
            && request.argv[1] == tag {
                break request;
            }
    };
    let sig = proto::sign_request(&key(), &req);
    send_json(&mut pw, &FromApprover::Decision { id: req.id, approve: true, sig: Some(sig) }).unwrap();
    loop {
        let line = read_line_bounded(&mut cr, 1 << 24).unwrap().unwrap();
        match serde_json::from_str::<ToClient>(&line).unwrap() {
            ToClient::Pending { .. } => {}
            ToClient::Result { stdout, .. } => {
                assert_eq!(stdout, format!("{tag}\n"));
                return;
            }
            other => panic!("daemon broken: {other:?}"),
        }
    }
}

#[test]
fn flood_from_unknown_ip_gets_nothing_and_costs_nothing() {
    let _g = serial();
    let mut cfg = config("flood");
    cfg.approver_ips = vec!["127.0.0.2".parse().unwrap()];
    let h = daemon::start(cfg).unwrap();
    let t0 = threads();
    let start = Instant::now();
    let mut conns = Vec::new();
    for _ in 0..300 {
        let mut s = connect(&h);
        let _ = s.write_all(b"{\"type\":\"decision\",\"id\":\"x\",\"approve\":true,\"sig\":\"AAAA\"}\n");
        conns.push(s);
    }
    for s in conns {
        assert!(closed_silently(s), "unknown peer received data");
    }
    assert!(threads() <= t0 + 1, "flood spawned threads: {t0} -> {}", threads());
    assert!(start.elapsed() < Duration::from_secs(30));
    h.shutdown();
}

#[test]
fn approver_slots_are_capped() {
    let _g = serial();
    let h = daemon::start(config("slots")).unwrap();
    let mut greeted = 0;
    let mut keep = Vec::new();
    for _ in 0..20 {
        let s = connect(&h);
        let mut r = BufReader::new(s.try_clone().unwrap());
        match read_line_bounded(&mut r, 4096) {
            Ok(Some(l)) if l.contains("hello") => {
                greeted += 1;
                keep.push(s);
            }
            _ => {}
        }
    }
    assert_eq!(greeted, 4, "max_approvers not enforced");
    drop(keep);
    std::thread::sleep(Duration::from_millis(500));
    still_works(&h); // slots were freed
    h.shutdown();
}

#[test]
fn garbage_and_fuzz_do_not_break_anything() {
    let _g = serial();
    let h = daemon::start(config("fuzz")).unwrap();
    let t0 = threads();
    let nested = format!("{}{}", "[".repeat(50_000), "]".repeat(50_000));
    let payloads: Vec<Vec<u8>> = vec![
        b"\n".to_vec(),
        b"not json\n".to_vec(),
        b"{}\n".to_vec(),
        b"{\"type\":\"nope\"}\n".to_vec(),
        b"{\"type\":\"decision\"}\n".to_vec(),
        b"{\"type\":\"decision\",\"id\":123,\"approve\":\"yes\"}\n".to_vec(),
        b"{\"type\":\"decision\",\"id\":\"\",\"approve\":true,\"sig\":null}\n".to_vec(),
        format!("{{\"type\":\"decision\",\"id\":\"{}\",\"approve\":true,\"sig\":\"{}\"}}\n", "a".repeat(30_000), "B".repeat(30_000)).into_bytes(),
        format!("{nested}\n").into_bytes(),
        b"{\"type\":\"pong\",\"extra\":1e999999}\n".to_vec(),
        b"\x00\x01\x02\xff\xfe\n".to_vec(),
        "{\"type\":\"decision\",\"id\":\"\u{202E}\u{0000}\",\"approve\":true,\"sig\":\"\u{1F600}\"}\n".as_bytes().to_vec(),
    ];
    for p in &payloads {
        let mut s = connect(&h);
        let _ = s.write_all(p);
        let _ = s.shutdown(std::net::Shutdown::Write);
        let mut sink = Vec::new();
        let _ = s.take(1 << 20).read_to_end(&mut sink);
    }
    // Random bytes, many rounds, with newlines sprinkled in.
    for round in 0..300 {
        let mut s = connect(&h);
        let mut junk: Vec<u8> = rootgate::random_bytes::<512>().to_vec();
        for i in (0..junk.len()).step_by(37 + round % 50) {
            junk[i] = b'\n';
        }
        let _ = s.write_all(&junk);
    }
    std::thread::sleep(Duration::from_millis(500));
    assert!(threads() <= t0 + 2, "threads {t0} -> {}", threads());
    still_works(&h);
    h.shutdown();
}

#[test]
fn oversized_line_is_cut_off() {
    let _g = serial();
    let h = daemon::start(config("big")).unwrap();
    let mut s = connect(&h);
    let mut r = BufReader::new(s.try_clone().unwrap());
    assert!(read_line_bounded(&mut r, 4096).unwrap().unwrap().contains("hello"));
    let chunk = vec![b'x'; 64 * 1024];
    let mut sent = 0usize;
    for _ in 0..64 {
        if s.write_all(&chunk).is_err() {
            break;
        }
        sent += chunk.len();
    }
    // Connection must be closed rather than buffering megabytes.
    let mut rest = Vec::new();
    let _ = r.read_to_end(&mut rest);
    assert!(sent < 4 * 1024 * 1024 || rest.is_empty());
    still_works(&h);
    h.shutdown();
}

#[test]
fn silent_phone_is_dropped_and_slot_freed() {
    let _g = serial();
    let mut cfg = config("silent");
    cfg.ping_secs = 1; // read timeout = 3*1+5 = 8 s
    cfg.max_approvers = 1;
    let h = daemon::start(cfg).unwrap();
    let s = TcpStream::connect(h.tcp_addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    let start = Instant::now();
    let mut r = BufReader::new(s);
    // Read pings but never answer: daemon must hang up.
    while let Ok(Some(_)) = read_line_bounded(&mut r, 4096) {}
    let took = start.elapsed();
    assert!(took >= Duration::from_secs(7) && took < Duration::from_secs(15), "took {took:?}");
    std::thread::sleep(Duration::from_millis(300));
    still_works(&h); // the only slot is free again
    h.shutdown();
}

#[test]
fn phone_that_stops_reading_cannot_stall_the_daemon() {
    let _g = serial();
    let h = daemon::start(config("stall")).unwrap();
    // A connected approver that never reads.
    let stuck = connect(&h);
    std::thread::sleep(Duration::from_millis(200));
    let big_arg = "y".repeat(4000);
    let start = Instant::now();
    for i in 0..400 {
        let c = UnixStream::connect(&h.socket_path).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut cw = c.try_clone().unwrap();
        let mut cr = BufReader::new(c);
        let argv = vec!["/usr/bin/echo".into(), big_arg.clone(), big_arg.clone(), big_arg.clone(), i.to_string()];
        send_json(&mut cw, &ClientMsg::Submit { argv, why: "fill the pipe".into() }).unwrap();
        let line = read_line_bounded(&mut cr, 1 << 20).unwrap().unwrap();
        assert!(line.contains("pending"), "{line}");
        // Walk away: request withdrawn, another broadcast.
    }
    // 400 x ~12 KiB x 2 messages: far beyond socket buffers. The daemon must have
    // kept answering quickly and dropped the stuck phone instead of blocking.
    assert!(start.elapsed() < Duration::from_secs(60), "daemon stalled: {:?}", start.elapsed());
    drop(stuck);
    std::thread::sleep(Duration::from_secs(1));
    still_works(&h);
    h.shutdown();
}

#[test]
fn local_socket_idle_and_garbage_clients_time_out() {
    let _g = serial();
    let h = daemon::start(config("unix")).unwrap();
    // Idle: never sends anything.
    let idle = UnixStream::connect(&h.socket_path).unwrap();
    idle.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    // Garbage then idle.
    let mut g = UnixStream::connect(&h.socket_path).unwrap();
    g.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    g.write_all(b"\xff\xfe garbage").unwrap();
    let start = Instant::now();
    let mut b = [0u8; 1];
    let _ = (&idle).read(&mut b);
    let _ = (&g).read(&mut b);
    assert!(start.elapsed() < Duration::from_secs(15), "idle local clients kept forever");
    still_works(&h);
    h.shutdown();
}

#[test]
fn bind_device_rejects_traffic_from_other_interfaces() {
    let _g = serial();
    // Listener pinned to an interface the test traffic does not use: connections
    // over loopback must not even be accepted. (Unprivileged SO_BINDTODEVICE
    // needs Linux >= 5.7.)
    let mut cfg = config("dev");
    let other = std::fs::read_dir("/sys/class/net")
        .unwrap()
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .find(|n| n != "lo")
        .expect("some non-loopback interface");
    cfg.bind_device = Some(other.clone());
    cfg.listen = "0.0.0.0:0".into();
    let h = daemon::start(cfg).unwrap();
    let port = h.tcp_addr.port();
    let r = TcpStream::connect_timeout(&format!("127.0.0.1:{port}").parse().unwrap(), Duration::from_secs(3));
    match r {
        Err(_) => {}
        Ok(s) => {
            s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            assert!(closed_silently(s), "connection via lo reached a listener bound to {other}");
        }
    }
    h.shutdown();

    // Same with "lo" works.
    let mut cfg = config("devlo");
    cfg.bind_device = Some("lo".into());
    let h = daemon::start(cfg).unwrap();
    still_works(&h);
    h.shutdown();
}
