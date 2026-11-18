//! Run an approved command: no shell, clean environment, bounded output, timeout,
//! and no threads or file descriptors left behind.

use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub const SAFE_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
/// After the main process exits, how long background children may keep the
/// output pipes open before the whole process group is killed.
const GRACE: Duration = Duration::from_secs(2);

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ExecOutcome {
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub timed_out: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
}

fn set_nonblocking(fd: i32) -> io::Result<()> {
    // SAFETY: plain fcntl on a valid fd we own.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0 || libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn kill_group(pgid: i32) {
    // SAFETY: signalling a process group; failure (ESRCH) is fine.
    unsafe {
        libc::kill(-pgid, libc::SIGKILL);
    }
}

/// Read what is available without blocking. Returns false once the pipe hit EOF.
/// Bytes beyond `cap` are read and discarded so the child never blocks on a full pipe.
fn drain(r: &mut impl Read, dst: &mut Vec<u8>, truncated: &mut bool, cap: usize) -> io::Result<bool> {
    let mut buf = [0u8; 16 * 1024];
    // Bounded so a very chatty process cannot starve the timeout check.
    for _ in 0..64 {
        match r.read(&mut buf) {
            Ok(0) => return Ok(false),
            Ok(n) => {
                let room = cap.saturating_sub(dst.len());
                if n > room {
                    *truncated = true;
                }
                dst.extend_from_slice(&buf[..n.min(room)]);
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(true),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

/// Execute `exe` with `argv` (argv[0] is passed as the program name).
pub fn run(exe: &Path, argv: &[String], timeout: Duration, cap: usize) -> io::Result<ExecOutcome> {
    let mut cmd = Command::new(exe);
    cmd.arg0(&argv[0])
        .args(&argv[1..])
        .env_clear()
        .env("PATH", SAFE_PATH)
        .env("LANG", "C.UTF-8")
        .env("HOME", "/root")
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // New session = new process group, so a timeout can kill everything it started.
    // SAFETY: setsid is async-signal-safe.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let mut child = cmd.spawn()?;
    let pgid = child.id() as i32;
    let mut out = child.stdout.take().expect("stdout is piped");
    let mut err = child.stderr.take().expect("stderr is piped");
    set_nonblocking(out.as_raw_fd())?;
    set_nonblocking(err.as_raw_fd())?;

    let mut res = ExecOutcome::default();
    let start = Instant::now();
    let (mut out_open, mut err_open) = (true, true);
    let mut status = None;
    let mut grace_until: Option<Instant> = None;

    loop {
        if status.is_none() {
            if let Some(st) = child.try_wait()? {
                status = Some(st);
                grace_until = Some(Instant::now() + GRACE);
            } else if start.elapsed() >= timeout {
                res.timed_out = true;
                kill_group(pgid);
                status = Some(child.wait()?);
                grace_until = Some(Instant::now() + GRACE);
            }
        }
        if status.is_some() && !out_open && !err_open {
            break;
        }
        if grace_until.is_some_and(|g| Instant::now() >= g) {
            // Something in the background still holds the pipes: kill it.
            kill_group(pgid);
            break;
        }

        let mut pfds: Vec<libc::pollfd> = Vec::with_capacity(2);
        for (open, fd) in [(out_open, out.as_raw_fd()), (err_open, err.as_raw_fd())] {
            if open {
                pfds.push(libc::pollfd { fd, events: libc::POLLIN, revents: 0 });
            }
        }
        if pfds.is_empty() {
            std::thread::sleep(Duration::from_millis(20));
        } else {
            // SAFETY: valid pollfd array; 50 ms timeout.
            unsafe { libc::poll(pfds.as_mut_ptr(), pfds.len() as libc::nfds_t, 50) };
        }
        if out_open {
            out_open = drain(&mut out, &mut res.stdout, &mut res.stdout_truncated, cap)?;
        }
        if err_open {
            err_open = drain(&mut err, &mut res.stderr, &mut res.stderr_truncated, cap)?;
        }
    }

    if let Some(st) = status {
        res.exit_code = st.code();
        res.signal = st.signal();
    }
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sv(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    fn fd_count() -> usize {
        std::fs::read_dir("/proc/self/fd").unwrap().count()
    }

    #[test]
    fn runs_without_shell() {
        let r = run(Path::new("/usr/bin/echo"), &sv(&["echo", "a;", "$(id)", "*"]), Duration::from_secs(5), 1024).unwrap();
        assert_eq!(r.exit_code, Some(0));
        assert_eq!(String::from_utf8_lossy(&r.stdout), "a; $(id) *\n");
    }

    #[test]
    fn clean_environment_and_cwd() {
        // SAFETY: test-only, single env var.
        unsafe { std::env::set_var("ROOTGATE_SECRET_TEST", "leak") };
        let r = run(Path::new("/usr/bin/env"), &sv(&["env"]), Duration::from_secs(5), 4096).unwrap();
        let env = String::from_utf8_lossy(&r.stdout);
        assert!(!env.contains("ROOTGATE_SECRET_TEST"));
        assert!(env.contains(&format!("PATH={SAFE_PATH}")));
        let r = run(Path::new("/usr/bin/pwd"), &sv(&["pwd"]), Duration::from_secs(5), 64).unwrap();
        assert_eq!(String::from_utf8_lossy(&r.stdout), "/\n");
    }

    #[test]
    fn exit_codes_and_stderr() {
        let r = run(Path::new("/usr/bin/ls"), &sv(&["ls", "/nope-404"]), Duration::from_secs(5), 4096).unwrap();
        assert_ne!(r.exit_code, Some(0));
        assert!(!r.stderr.is_empty());
    }

    #[test]
    fn timeout_kills() {
        let t = Instant::now();
        let r = run(Path::new("/usr/bin/sleep"), &sv(&["sleep", "30"]), Duration::from_millis(500), 64).unwrap();
        assert!(r.timed_out);
        assert_eq!(r.signal, Some(libc::SIGKILL));
        assert!(t.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn output_is_capped() {
        let r = run(Path::new("/usr/bin/head"), &sv(&["head", "-c", "5000000", "/dev/zero"]), Duration::from_secs(10), 1000).unwrap();
        assert_eq!(r.stdout.len(), 1000);
        assert!(r.stdout_truncated);
        assert_eq!(r.exit_code, Some(0));
    }

    #[test]
    fn background_children_cannot_hang_us() {
        let t = Instant::now();
        let r = run(Path::new("/usr/bin/sh"), &sv(&["sh", "-c", "sleep 30 & echo started"]), Duration::from_secs(20), 64).unwrap();
        assert_eq!(String::from_utf8_lossy(&r.stdout), "started\n");
        assert!(t.elapsed() < Duration::from_secs(6), "took {:?}", t.elapsed());
    }

    #[test]
    fn no_fd_leaks() {
        // Warm up, then compare.
        let _ = run(Path::new("/usr/bin/true"), &sv(&["true"]), Duration::from_secs(5), 64).unwrap();
        let before = fd_count();
        for _ in 0..50 {
            let _ = run(Path::new("/usr/bin/echo"), &sv(&["echo", "x"]), Duration::from_secs(5), 64).unwrap();
        }
        // Other tests run in parallel threads and may hold fds briefly, so allow slack.
        assert!(fd_count() <= before + 8, "fds before {before}, after {}", fd_count());
    }
}
