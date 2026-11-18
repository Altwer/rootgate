//! rootgate-dev-approver — a terminal stand-in for the phone app, for testing.
//!
//!   rootgate-dev-approver keygen KEYFILE        create a test key, print its public key
//!   rootgate-dev-approver pubkey KEYFILE        print the public key again
//!   rootgate-dev-approver connect KEYFILE HOST:PORT
//!
//! The key file holds a raw P-256 private key in hex (mode 0600). Never enroll a
//! dev key on a real install: whoever can read the file can approve commands.

use p256::ecdsa::SigningKey;
use rootgate::net::read_line_bounded;
use rootgate::proto::{self, FromApprover, MAX_LINE, ToApprover};
use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, Write};
use std::net::TcpStream;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::process::exit;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

fn fail(msg: impl AsRef<str>) -> ! {
    eprintln!("rootgate-dev-approver: {}", msg.as_ref());
    exit(1);
}

fn load_key(path: &str) -> SigningKey {
    let meta = std::fs::metadata(path).unwrap_or_else(|e| fail(format!("{path}: {e}")));
    if meta.permissions().mode() & 0o077 != 0 {
        fail(format!("{path} is readable by others; chmod 600 it"));
    }
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| fail(format!("{path}: {e}")));
    let bytes = rootgate::unhex(&text).unwrap_or_else(|| fail("key file is not hex"));
    SigningKey::from_slice(&bytes).unwrap_or_else(|_| fail("invalid key"))
}

fn send(w: &Arc<Mutex<TcpStream>>, msg: &FromApprover) {
    let mut line = serde_json::to_string(msg).expect("serializable");
    line.push('\n');
    let mut s = w.lock().unwrap_or_else(|p| p.into_inner());
    if s.write_all(line.as_bytes()).is_err() {
        fail("connection lost");
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["keygen", path] => {
            let sk = loop {
                if let Ok(k) = SigningKey::from_slice(&rootgate::random_bytes::<32>()) {
                    break k;
                }
            };
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .unwrap_or_else(|e| fail(format!("{path}: {e}")));
            f.write_all(rootgate::hex(&sk.to_bytes()).as_bytes()).unwrap_or_else(|e| fail(e.to_string()));
            println!("{}", proto::encode_public_key(sk.verifying_key()));
        }
        ["pubkey", path] => println!("{}", proto::encode_public_key(load_key(path).verifying_key())),
        ["connect", path, addr] => connect(load_key(path), addr),
        _ => fail("usage: keygen KEYFILE | pubkey KEYFILE | connect KEYFILE HOST:PORT"),
    }
}

fn connect(sk: SigningKey, addr: &str) {
    use base64::{Engine, engine::general_purpose::STANDARD as B64};
    let s = TcpStream::connect(addr).unwrap_or_else(|e| fail(format!("{addr}: {e}")));
    let w = Arc::new(Mutex::new(s.try_clone().unwrap_or_else(|e| fail(e.to_string()))));
    let challenge = B64.encode(rootgate::random_bytes::<32>());
    send(&w, &FromApprover::Hello { challenge: challenge.clone() });
    // Pin the daemon key from the first hello (a real phone stores it).
    let mut daemon: Option<p256::ecdsa::VerifyingKey> = None;

    // Reader thread answers pings itself so the daemon doesn't drop us while
    // we are waiting at a prompt; everything else goes to the main thread.
    let (tx, rx) = mpsc::channel::<ToApprover>();
    {
        let w = w.clone();
        std::thread::spawn(move || {
            let mut r = BufReader::new(s);
            while let Ok(Some(line)) = read_line_bounded(&mut r, MAX_LINE) {
                match serde_json::from_str::<ToApprover>(&line) {
                    Ok(ToApprover::Ping) => send(&w, &FromApprover::Pong),
                    Ok(m) => {
                        if tx.send(m).is_err() {
                            break;
                        }
                    }
                    Err(e) => eprintln!("bad message from daemon: {e}"),
                }
            }
            eprintln!("disconnected");
            exit(0);
        });
    }

    let stdin = io::stdin();
    for msg in rx {
        match msg {
            ToApprover::Hello { host, proto, daemon_key, sig } => {
                let vk = proto::parse_public_key(&daemon_key).unwrap_or_else(|e| fail(e));
                if !proto::verify_approval(&[vk], &proto::hello_bytes(&challenge, &host, &daemon_key), &sig) {
                    fail("daemon failed the challenge: not the real daemon");
                }
                println!("connected to {host} (protocol {proto}), daemon fingerprint {}", proto::fingerprint(&vk));
                daemon = Some(vk);
            }
            ToApprover::Cancel { id, reason } => println!("[{}] {reason}", &id[..8.min(id.len())]),
            ToApprover::Error { id, message } => println!("error{}: {message}", id.map(|i| format!(" [{}]", &i[..8.min(i.len())])).unwrap_or_default()),
            ToApprover::Ping => {}
            ToApprover::Request { request, code, warnings, dsig } => {
                let Some(vk) = daemon else { fail("request before hello") };
                if !proto::verify_approval(&[vk], &proto::daemon_request_bytes(&request, &warnings), &dsig) {
                    println!("!!! request not signed by the daemon, ignoring");
                    continue;
                }
                // Recompute the code locally: what we show and sign must be what we got.
                let local = request.code();
                println!("\n=== root request {code} from {}@{} ===", request.user, request.host);
                if local != code {
                    println!("!!! code mismatch (daemon {code}, local {local}), denying");
                    send(&w, &FromApprover::Decision { id: request.id, approve: false, sig: None });
                    continue;
                }
                for (i, a) in request.argv.iter().enumerate() {
                    println!("  argv[{i}] = {}", serde_json::to_string(a).unwrap_or_default());
                }
                println!("  why: {}", request.why);
                for w in &warnings {
                    println!("  WARNING: {w}");
                }
                let left = request.expires.saturating_sub(rootgate::now_unix());
                print!("approve? type the code to approve, anything else denies ({left}s left): ");
                let _ = io::stdout().flush();
                let mut answer = String::new();
                if stdin.lock().read_line(&mut answer).is_err() {
                    fail("stdin closed");
                }
                let approve = answer.trim().eq_ignore_ascii_case(&code);
                let sig = approve.then(|| proto::sign_request(&sk, &request));
                send(&w, &FromApprover::Decision { id: request.id, approve, sig });
                println!("{}", if approve { "approved" } else { "denied" });
            }
        }
    }
}
