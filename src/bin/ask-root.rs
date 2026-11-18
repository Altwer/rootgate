//! ask-root — request a root command and wait for approval on the phone.
//!
//!   ask-root --why "reason shown on the phone" [--socket PATH] -- command [args...]
//!
//! Exit status: the command's own exit code; 128+N if killed by signal N;
//! 124 on timeout; 100 denied; 101 expired; 102 any other error.

use rootgate::net::{read_line_bounded, send_json};
use rootgate::proto::{ClientMsg, ToClient};
use std::io::{BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::exit;

const DEFAULT_SOCKET: &str = "/run/rootgate/rootgate.sock";
/// Results carry up to 2 x 1 MiB of output, JSON-escaped (worst case ~6x).
const MAX_RESULT_LINE: usize = 16 * 1024 * 1024;

fn usage() -> ! {
    eprintln!("usage: ask-root --why \"reason\" [--socket PATH] -- command [args...]");
    exit(102);
}

fn fail(msg: impl AsRef<str>) -> ! {
    eprintln!("ask-root: {}", msg.as_ref());
    exit(102);
}

/// Turn a command name into an absolute path the way a shell would (first match in
/// PATH), so the phone shows exactly which file will run.
fn resolve(cmd: &str) -> Option<String> {
    if cmd.contains('/') {
        return std::fs::canonicalize(cmd).ok().map(|p| p.to_string_lossy().into_owned());
    }
    let path = std::env::var("PATH").unwrap_or_default();
    path.split(':')
        .filter(|d| d.starts_with('/'))
        .map(|d| Path::new(d).join(cmd))
        .find(|p| {
            std::fs::metadata(p).map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0).unwrap_or(false)
        })
        .map(|p: PathBuf| p.to_string_lossy().into_owned())
}

fn main() {
    let mut args = std::env::args().skip(1);
    let mut why: Option<String> = None;
    let mut socket = std::env::var("ROOTGATE_SOCKET").unwrap_or_else(|_| DEFAULT_SOCKET.into());
    let mut argv: Vec<String> = Vec::new();
    while let Some(a) = args.next() {
        match a.as_str() {
            "--why" => why = Some(args.next().unwrap_or_else(|| usage())),
            "--socket" => socket = args.next().unwrap_or_else(|| usage()),
            "--" => {
                argv = args.by_ref().collect();
                break;
            }
            _ => usage(),
        }
    }
    let Some(why) = why else { usage() };
    if argv.is_empty() {
        usage();
    }
    argv[0] = resolve(&argv[0]).unwrap_or_else(|| fail(format!("command not found: {}", argv[0])));

    let stream = UnixStream::connect(&socket)
        .unwrap_or_else(|e| fail(format!("cannot reach rootgated at {socket}: {e}")));
    let mut w = stream.try_clone().unwrap_or_else(|e| fail(e.to_string()));
    send_json(&mut w, &ClientMsg::Submit { argv: argv.clone(), why }).unwrap_or_else(|e| fail(e.to_string()));

    let mut reader = BufReader::new(stream);
    loop {
        let line = match read_line_bounded(&mut reader, MAX_RESULT_LINE) {
            Ok(Some(l)) => l,
            Ok(None) => fail("daemon closed the connection"),
            Err(e) => fail(e.to_string()),
        };
        let msg: ToClient = serde_json::from_str(&line).unwrap_or_else(|e| fail(format!("bad reply: {e}")));
        match msg {
            ToClient::Pending { code, expires, .. } => {
                let left = expires.saturating_sub(rootgate::now_unix());
                eprintln!("ask-root: waiting for approval on your phone, code {code} (expires in {left}s)");
                eprintln!("ask-root: {}", serde_json::to_string(&argv).unwrap_or_default());
            }
            ToClient::Result { exit_code, signal, timed_out, stdout, stderr, stdout_truncated, stderr_truncated } => {
                let _ = std::io::stdout().write_all(stdout.as_bytes());
                let _ = std::io::stderr().write_all(stderr.as_bytes());
                if stdout_truncated || stderr_truncated {
                    eprintln!("ask-root: output was truncated");
                }
                if timed_out {
                    eprintln!("ask-root: command timed out and was killed");
                    exit(124);
                }
                if let Some(c) = exit_code {
                    exit(c);
                }
                exit(128 + signal.unwrap_or(0));
            }
            ToClient::Denied { .. } => {
                eprintln!("ask-root: denied on the phone");
                exit(100);
            }
            ToClient::Expired { .. } => {
                eprintln!("ask-root: request expired without a decision");
                exit(101);
            }
            ToClient::Error { message } => fail(message),
        }
    }
}
