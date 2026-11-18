//! rootgated — the root daemon. Usage: rootgated [config.json]

use rootgate::daemon::{self, Config, DEFAULT_CONFIG};
use std::path::PathBuf;

fn main() {
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
