//! The root daemon: accepts requests on a Unix socket, forwards them to the phone
//! over TCP (Tailscale), and runs a request only after a valid signed approval.

use crate::exec;
use crate::net::{hostname, peer_cred, peer_hung_up, read_line_bounded, send_json, username};
use crate::proto::{
    self, ClientMsg, FromApprover, MAX_LINE, PROTO_VERSION, Request, ToApprover, ToClient,
};
use crate::trust;
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use p256::ecdsa::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{self, BufReader, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub const DEFAULT_CONFIG: &str = "/etc/rootgate/config.json";

fn d_ttl() -> u64 { 120 }
fn d_exec_timeout() -> u64 { 600 }
fn d_cap() -> usize { 1024 * 1024 }
fn d_max_pending() -> usize { 8 }
fn d_max_approvers() -> usize { 4 }
fn d_max_clients() -> usize { 16 }
fn d_ping() -> u64 { 30 }
fn d_true() -> bool { true }

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Unix socket for ask-root.
    pub socket_path: PathBuf,
    /// TCP address the phone connects to, e.g. "100.x.y.z:789" (Tailscale IP only).
    pub listen: String,
    /// Only these peer IPs may connect as approvers (your phone's Tailscale IP).
    pub approver_ips: Vec<IpAddr>,
    /// Enrolled phone keys: base64 X.509 SubjectPublicKeyInfo (P-256).
    pub approver_pubkeys: Vec<String>,
    /// Local users allowed to submit requests.
    pub allowed_uids: Vec<u32>,
    #[serde(default = "d_ttl")]
    pub request_ttl_secs: u64,
    #[serde(default = "d_exec_timeout")]
    pub exec_timeout_secs: u64,
    #[serde(default = "d_cap")]
    pub output_cap_bytes: usize,
    #[serde(default = "d_max_pending")]
    pub max_pending: usize,
    #[serde(default = "d_max_approvers")]
    pub max_approvers: usize,
    #[serde(default = "d_max_clients")]
    pub max_clients: usize,
    #[serde(default = "d_ping")]
    pub ping_secs: u64,
    /// Require argv[0] and the path to it to be root-controlled. Only turn off in tests.
    #[serde(default = "d_true")]
    pub require_trusted_exe: bool,
}

impl Config {
    pub fn load(path: &Path) -> Result<Config, String> {
        // When running as root, refuse a config that a normal user could have edited:
        // it decides which phone keys are trusted.
        if unsafe { libc::geteuid() } == 0 {
            trust::check_root_owned_file(path)?;
        }
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
    }
}

enum Outcome {
    Approved,
    Denied,
    Expired,
}

struct Pending {
    req: Request,
    canonical: Vec<u8>,
    code: String,
    reply: mpsc::Sender<Outcome>,
}

struct Approver {
    tx: SyncSender<String>,
    sock: TcpStream,
}

#[derive(Default)]
struct State {
    pending: HashMap<String, Pending>,
    approvers: HashMap<u64, Approver>,
    next_conn: u64,
}

struct Daemon {
    cfg: Config,
    keys: Vec<VerifyingKey>,
    host: String,
    state: Mutex<State>,
    shutdown: AtomicBool,
    clients: AtomicUsize,
}

pub struct Handle {
    pub tcp_addr: SocketAddr,
    pub socket_path: PathBuf,
    daemon: Arc<Daemon>,
    threads: Vec<JoinHandle<()>>,
}

impl Handle {
    /// Stop accepting, disconnect approvers and wait for the background threads.
    pub fn shutdown(self) {
        self.daemon.shutdown.store(true, Ordering::SeqCst);
        {
            let st = self.daemon.lock();
            for a in st.approvers.values() {
                let _ = a.sock.shutdown(Shutdown::Both);
            }
        }
        for t in self.threads {
            let _ = t.join();
        }
        let _ = std::fs::remove_file(&self.socket_path);
    }

    /// Block forever (used by the real daemon).
    pub fn wait(self) {
        for t in self.threads {
            let _ = t.join();
        }
    }
}

fn log(msg: impl AsRef<str>) {
    eprintln!("rootgated: {}", msg.as_ref());
}

impl Daemon {
    fn lock(&self) -> MutexGuard<'_, State> {
        // A panic in one handler must not take the whole daemon down.
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn line<T: Serialize>(msg: &T) -> String {
        serde_json::to_string(msg).expect("serializable")
    }

    /// Queue a message to every approver. Slow or dead approvers are dropped
    /// instead of buffering without limit.
    fn broadcast(st: &mut State, msg: &ToApprover) {
        let line = Self::line(msg);
        let mut dead = Vec::new();
        for (id, a) in &st.approvers {
            match a.tx.try_send(line.clone()) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => dead.push(*id),
            }
        }
        for id in dead {
            if let Some(a) = st.approvers.remove(&id) {
                let _ = a.sock.shutdown(Shutdown::Both);
                log(format!("approver #{id} dropped (not keeping up)"));
            }
        }
    }

    fn finish(st: &mut State, id: &str, outcome: Outcome, reason: &str) {
        if let Some(p) = st.pending.remove(id) {
            let _ = p.reply.send(outcome);
            Self::broadcast(st, &ToApprover::Cancel { id: id.to_string(), reason: reason.to_string() });
        }
    }
}

pub fn start(cfg: Config) -> Result<Handle, String> {
    let keys = cfg
        .approver_pubkeys
        .iter()
        .map(|k| proto::parse_public_key(k))
        .collect::<Result<Vec<_>, _>>()?;
    if keys.is_empty() {
        return Err("no approver_pubkeys configured".into());
    }
    if cfg.approver_ips.is_empty() {
        return Err("no approver_ips configured".into());
    }
    if cfg.allowed_uids.is_empty() {
        return Err("no allowed_uids configured".into());
    }

    // Replace a stale socket, but never delete something that is not a socket.
    if let Ok(m) = std::fs::symlink_metadata(&cfg.socket_path) {
        if m.file_type().is_socket() {
            let _ = std::fs::remove_file(&cfg.socket_path);
        } else {
            return Err(format!("{} exists and is not a socket", cfg.socket_path.display()));
        }
    }
    let ul = UnixListener::bind(&cfg.socket_path).map_err(|e| format!("{}: {e}", cfg.socket_path.display()))?;
    // Anyone may connect; the uid check (SO_PEERCRED) is the real gate.
    std::fs::set_permissions(&cfg.socket_path, std::fs::Permissions::from_mode(0o666))
        .map_err(|e| e.to_string())?;
    ul.set_nonblocking(true).map_err(|e| e.to_string())?;

    let tl = TcpListener::bind(&cfg.listen).map_err(|e| format!("{}: {e}", cfg.listen))?;
    tl.set_nonblocking(true).map_err(|e| e.to_string())?;
    let tcp_addr = tl.local_addr().map_err(|e| e.to_string())?;

    let socket_path = cfg.socket_path.clone();
    let d = Arc::new(Daemon {
        cfg,
        keys,
        host: hostname(),
        state: Mutex::new(State::default()),
        shutdown: AtomicBool::new(false),
        clients: AtomicUsize::new(0),
    });

    let mut threads = Vec::new();
    {
        let d = d.clone();
        threads.push(thread::spawn(move || accept_clients(d, ul)));
    }
    {
        let d = d.clone();
        threads.push(thread::spawn(move || accept_approvers(d, tl)));
    }
    {
        let d = d.clone();
        threads.push(thread::spawn(move || sweeper(d)));
    }
    log(format!("listening on {} and {tcp_addr}", socket_path.display()));
    Ok(Handle { tcp_addr, socket_path, daemon: d, threads })
}

// ------------------------------------------------------------------ clients

fn accept_clients(d: Arc<Daemon>, ul: UnixListener) {
    while !d.shutdown.load(Ordering::SeqCst) {
        match ul.accept() {
            Ok((s, _)) => {
                if d.clients.load(Ordering::SeqCst) >= d.cfg.max_clients {
                    let mut s = s;
                    let _ = send_json(&mut s, &ToClient::Error { message: "daemon busy".into() });
                    continue;
                }
                d.clients.fetch_add(1, Ordering::SeqCst);
                let d2 = d.clone();
                thread::spawn(move || {
                    // Decrement even if the handler panics, so slots can't leak.
                    struct Slot(Arc<Daemon>);
                    impl Drop for Slot {
                        fn drop(&mut self) {
                            self.0.clients.fetch_sub(1, Ordering::SeqCst);
                        }
                    }
                    let _slot = Slot(d2.clone());
                    if let Err(e) = handle_client(&d2, s) {
                        log(format!("client error: {e}"));
                    }
                });
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(50)),
            Err(e) => {
                log(format!("accept (unix): {e}"));
                thread::sleep(Duration::from_millis(200));
            }
        }
    }
}

fn reply_err(w: &mut UnixStream, msg: impl Into<String>) -> io::Result<()> {
    send_json(w, &ToClient::Error { message: msg.into() })
}

fn handle_client(d: &Arc<Daemon>, s: UnixStream) -> io::Result<()> {
    s.set_nonblocking(false)?;
    let mut w = s.try_clone()?;
    let (uid, pid) = peer_cred(&s)?;
    if !d.cfg.allowed_uids.contains(&uid) {
        log(format!("rejected request from uid {uid} (pid {pid}): not allowed"));
        return reply_err(&mut w, "this user is not allowed to use rootgate");
    }

    s.set_read_timeout(Some(Duration::from_secs(10)))?;
    w.set_write_timeout(Some(Duration::from_secs(10)))?;
    let mut reader = BufReader::new(s);
    let Some(line) = read_line_bounded(&mut reader, MAX_LINE)? else {
        return Ok(());
    };
    let (argv, why) = match serde_json::from_str::<ClientMsg>(&line) {
        Ok(ClientMsg::Submit { argv, why }) => (argv, why),
        Err(e) => return reply_err(&mut w, format!("bad request: {e}")),
    };
    if let Err(e) = proto::validate_argv(&argv).and_then(|_| proto::validate_why(&why)) {
        return reply_err(&mut w, e);
    }
    if d.cfg.require_trusted_exe {
        if let Err(e) = trust::resolve_trusted_exe(&argv[0]) {
            return reply_err(&mut w, format!("refusing untrusted executable: {e}"));
        }
    }

    let now = crate::now_unix();
    let req = Request {
        id: crate::hex(&crate::random_bytes::<16>()),
        nonce: B64.encode(crate::random_bytes::<32>()),
        created: now,
        expires: now + d.cfg.request_ttl_secs,
        uid,
        user: username(uid),
        host: d.host.clone(),
        argv,
        why,
    };
    let canonical = req.canonical_bytes();
    let code = req.code();
    let (tx, rx) = mpsc::channel();
    {
        let mut st = d.lock();
        if st.pending.len() >= d.cfg.max_pending {
            drop(st);
            return reply_err(&mut w, "too many pending requests");
        }
        Daemon::broadcast(&mut st, &ToApprover::Request { request: req.clone(), code: code.clone() });
        st.pending.insert(
            req.id.clone(),
            Pending { req: req.clone(), canonical, code: code.clone(), reply: tx },
        );
    }
    log(format!(
        "request {} code {code} from {} (pid {pid}): {} -- why: {}",
        req.id,
        req.user,
        serde_json::to_string(&req.argv).unwrap_or_default(),
        serde_json::to_string(&req.why).unwrap_or_default()
    ));
    send_json(&mut w, &ToClient::Pending { id: req.id.clone(), code, expires: req.expires })?;

    // Wait for the phone. If the requester goes away, withdraw the request so the
    // phone never shows something nobody is waiting for.
    let outcome = loop {
        match rx.recv_timeout(Duration::from_millis(250)) {
            Ok(o) => break o,
            Err(RecvTimeoutError::Timeout) => {
                if peer_hung_up(&w) || d.shutdown.load(Ordering::SeqCst) {
                    let mut st = d.lock();
                    if st.pending.contains_key(&req.id) {
                        Daemon::finish(&mut st, &req.id, Outcome::Expired, "requester disconnected");
                        drop(st);
                        log(format!("request {} withdrawn (requester gone)", req.id));
                        return Ok(());
                    }
                    // Decided in the meantime: fall through and pick up the outcome.
                }
            }
            Err(RecvTimeoutError::Disconnected) => return Ok(()),
        }
    };

    match outcome {
        Outcome::Denied => send_json(&mut w, &ToClient::Denied { id: req.id }),
        Outcome::Expired => send_json(&mut w, &ToClient::Expired { id: req.id }),
        Outcome::Approved => {
            // Re-check right before exec to keep the swap window as small as possible.
            let exe = if d.cfg.require_trusted_exe {
                match trust::resolve_trusted_exe(&req.argv[0]) {
                    Ok(p) => p,
                    Err(e) => {
                        log(format!("request {} approved but executable changed: {e}", req.id));
                        return reply_err(&mut w, format!("executable no longer trusted: {e}"));
                    }
                }
            } else {
                PathBuf::from(&req.argv[0])
            };
            log(format!("request {} approved, running", req.id));
            let t = Instant::now();
            let r = exec::run(
                &exe,
                &req.argv,
                Duration::from_secs(d.cfg.exec_timeout_secs),
                d.cfg.output_cap_bytes,
            );
            match r {
                Ok(o) => {
                    log(format!(
                        "request {} finished in {:.1}s: exit {:?} signal {:?}{}",
                        req.id,
                        t.elapsed().as_secs_f32(),
                        o.exit_code,
                        o.signal,
                        if o.timed_out { " (timed out)" } else { "" }
                    ));
                    send_json(
                        &mut w,
                        &ToClient::Result {
                            exit_code: o.exit_code,
                            signal: o.signal,
                            timed_out: o.timed_out,
                            stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
                            stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
                            stdout_truncated: o.stdout_truncated,
                            stderr_truncated: o.stderr_truncated,
                        },
                    )
                }
                Err(e) => {
                    log(format!("request {} failed to start: {e}", req.id));
                    reply_err(&mut w, format!("failed to start: {e}"))
                }
            }
        }
    }
}

// ---------------------------------------------------------------- approvers

fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

fn accept_approvers(d: Arc<Daemon>, tl: TcpListener) {
    while !d.shutdown.load(Ordering::SeqCst) {
        match tl.accept() {
            Ok((s, peer)) => {
                let ip = normalize_ip(peer.ip());
                if !d.cfg.approver_ips.contains(&ip) {
                    log(format!("rejected approver connection from {ip}"));
                    let _ = s.shutdown(Shutdown::Both);
                    continue;
                }
                if d.lock().approvers.len() >= d.cfg.max_approvers {
                    log(format!("rejected approver from {ip}: too many connections"));
                    let _ = s.shutdown(Shutdown::Both);
                    continue;
                }
                let d2 = d.clone();
                thread::spawn(move || {
                    if let Err(e) = handle_approver(&d2, s, ip) {
                        log(format!("approver {ip}: {e}"));
                    }
                });
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(50)),
            Err(e) => {
                log(format!("accept (tcp): {e}"));
                thread::sleep(Duration::from_millis(200));
            }
        }
    }
}

fn handle_approver(d: &Arc<Daemon>, s: TcpStream, ip: IpAddr) -> io::Result<()> {
    s.set_nonblocking(false)?;
    s.set_nodelay(true)?;
    // The phone answers pings, so silence for 3 ping intervals means it is gone.
    s.set_read_timeout(Some(Duration::from_secs(d.cfg.ping_secs * 3 + 5)))?;
    s.set_write_timeout(Some(Duration::from_secs(10)))?;

    let (tx, rx) = mpsc::sync_channel::<String>(64);
    let conn_id;
    {
        let mut st = d.lock();
        if st.approvers.len() >= d.cfg.max_approvers {
            return Ok(());
        }
        conn_id = st.next_conn;
        st.next_conn += 1;
        // Greeting and everything currently pending, in creation order.
        let _ = tx.try_send(Daemon::line(&ToApprover::Hello { host: d.host.clone(), proto: PROTO_VERSION }));
        let mut pending: Vec<&Pending> = st.pending.values().collect();
        pending.sort_by_key(|p| p.req.created);
        for p in pending {
            let _ = tx.try_send(Daemon::line(&ToApprover::Request { request: p.req.clone(), code: p.code.clone() }));
        }
        st.approvers.insert(conn_id, Approver { tx: tx.clone(), sock: s.try_clone()? });
    }
    log(format!("approver #{conn_id} connected from {ip}"));

    // Writer: owns the write half; ends when every sender is dropped or a write fails.
    let mut wsock = s.try_clone()?;
    let writer = thread::spawn(move || {
        for line in rx {
            if wsock.write_all(line.as_bytes()).and_then(|_| wsock.write_all(b"\n")).is_err() {
                break;
            }
        }
        let _ = wsock.shutdown(Shutdown::Both);
    });

    let mut reader = BufReader::new(s);
    let result = (|| -> io::Result<()> {
        while let Some(line) = read_line_bounded(&mut reader, MAX_LINE)? {
            match serde_json::from_str::<FromApprover>(&line) {
                Ok(FromApprover::Pong) => {}
                Ok(FromApprover::Decision { id, approve, sig }) => {
                    decide(d, &tx, conn_id, &id, approve, sig.as_deref());
                }
                Err(e) => {
                    let _ = tx.try_send(Daemon::line(&ToApprover::Error { id: None, message: format!("bad message: {e}") }));
                }
            }
        }
        Ok(())
    })();

    // Cleanup: deregister (drops the stored sender), drop ours, let the writer finish.
    if let Some(a) = d.lock().approvers.remove(&conn_id) {
        let _ = a.sock.shutdown(Shutdown::Both);
    }
    drop(tx);
    let _ = writer.join();
    log(format!("approver #{conn_id} disconnected"));
    result
}

fn decide(d: &Arc<Daemon>, tx: &SyncSender<String>, conn_id: u64, id: &str, approve: bool, sig: Option<&str>) {
    let err = |msg: &str| {
        let _ = tx.try_send(Daemon::line(&ToApprover::Error { id: Some(id.to_string()), message: msg.to_string() }));
    };
    let mut st = d.lock();
    let Some(p) = st.pending.get(id) else {
        drop(st);
        return err("unknown request (already decided, expired or withdrawn)");
    };
    if crate::now_unix() > p.req.expires {
        Daemon::finish(&mut st, id, Outcome::Expired, "expired");
        drop(st);
        return err("request expired");
    }
    if approve {
        let valid = sig.is_some_and(|s| proto::verify_approval(&d.keys, &p.canonical, s));
        if !valid {
            // Keep it pending: a broken or forged approval must not count as a decision.
            drop(st);
            log(format!("approver #{conn_id}: INVALID signature for request {id}"));
            return err("invalid signature");
        }
        Daemon::finish(&mut st, id, Outcome::Approved, "approved");
        drop(st);
        log(format!("request {id} approved by approver #{conn_id}"));
    } else {
        Daemon::finish(&mut st, id, Outcome::Denied, "denied");
        drop(st);
        log(format!("request {id} denied by approver #{conn_id}"));
    }
}

// ------------------------------------------------------------------ sweeper

fn sweeper(d: Arc<Daemon>) {
    let mut last_ping = Instant::now();
    while !d.shutdown.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_millis(200));
        let now = crate::now_unix();
        let mut st = d.lock();
        let expired: Vec<String> = st
            .pending
            .iter()
            .filter(|(_, p)| now > p.req.expires)
            .map(|(id, _)| id.clone())
            .collect();
        for id in expired {
            Daemon::finish(&mut st, &id, Outcome::Expired, "expired");
            log(format!("request {id} expired"));
        }
        if last_ping.elapsed() >= Duration::from_secs(d.cfg.ping_secs) {
            Daemon::broadcast(&mut st, &ToApprover::Ping);
            last_ping = Instant::now();
        }
    }
}
