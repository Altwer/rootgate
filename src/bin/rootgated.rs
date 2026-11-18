//! rootgated — the root daemon. Usage: rootgated [config.json]

use rootgate::daemon::{self, Config, DEFAULT_CONFIG};
use std::path::PathBuf;

fn main() {
    // As root, refuse to run from a binary a normal user could have replaced
    // (e.g. straight out of ~/Desktop/rootgate/target).
    if unsafe { libc::geteuid() } == 0 {
        let exe = std::fs::read_link("/proc/self/exe").unwrap_or_default();
        if let Err(e) = rootgate::trust::resolve_trusted_exe(&exe.to_string_lossy()) {
            eprintln!("rootgated: refusing to run as root from an untrusted binary: {e}");
            eprintln!("rootgated: install it with: sudo install -o root -g root -m 0755 target/release/rootgated /usr/local/sbin/");
            std::process::exit(2);
        }
    }
    let path = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG));
    let cfg = match Config::load(&path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("rootgated: config: {e}");
            std::process::exit(2);
        }
    };
    if !cfg.require_trusted_exe {
        eprintln!("rootgated: WARNING require_trusted_exe is off; approved binaries could be swapped");
    }
    match daemon::start(cfg) {
        Ok(h) => h.wait(),
        Err(e) => {
            eprintln!("rootgated: {e}");
            std::process::exit(1);
        }
    }
}
