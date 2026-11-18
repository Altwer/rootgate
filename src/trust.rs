//! Make sure the program that gets approved is the program that runs.
//!
//! If argv[0] (or any directory or symlink on the way to it) could be changed by a
//! non-root user, that user could swap the binary after the phone approved it.
//! So every directory traversed, every symlink followed and the final file must be
//! owned by root and not writable by group or others.

use std::collections::VecDeque;
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

const MAX_SYMLINK_HOPS: u32 = 32;

fn root_only(meta: &fs::Metadata, what: &Path) -> Result<(), String> {
    if meta.uid() != 0 {
        return Err(format!("{} is not owned by root", what.display()));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(format!("{} is writable by group or others", what.display()));
    }
    Ok(())
}

fn push_components(q: &mut VecDeque<OsString>, p: &Path) {
    for c in p.components() {
        match c {
            Component::Normal(n) => q.push_back(n.to_os_string()),
            Component::ParentDir => q.push_back("..".into()),
            Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
        }
    }
}

/// Resolve `path` step by step and check each step is root-controlled.
/// Returns the fully resolved path of the executable.
pub fn resolve_trusted_exe(path: &str) -> Result<PathBuf, String> {
    resolve_trusted(path, true)
}

/// Same walk for any regular file (no exec bit needed): scripts, packages, configs.
pub fn resolve_trusted_file(path: &str) -> Result<PathBuf, String> {
    resolve_trusted(path, false)
}

fn resolve_trusted(path: &str, need_exec: bool) -> Result<PathBuf, String> {
    let p = Path::new(path);
    if !p.is_absolute() {
        return Err("path must be absolute".into());
    }
    let mut queue = VecDeque::new();
    push_components(&mut queue, p);

    // `cur` is always a fully resolved, already-checked directory.
    let mut cur = PathBuf::from("/");
    root_only(&fs::metadata(&cur).map_err(|e| format!("/: {e}"))?, &cur)?;
    let mut hops = 0;

    while let Some(name) = queue.pop_front() {
        if name == ".." {
            cur.pop();
            continue;
        }
        let next = cur.join(&name);
        let lmeta = fs::symlink_metadata(&next).map_err(|e| format!("{}: {e}", next.display()))?;

        if lmeta.file_type().is_symlink() {
            hops += 1;
            if hops > MAX_SYMLINK_HOPS {
                return Err("too many symlinks".into());
            }
            // Its directory is checked, so only root can replace the link itself;
            // still require root ownership for clarity.
            if lmeta.uid() != 0 {
                return Err(format!("symlink {} is not owned by root", next.display()));
            }
            let target = fs::read_link(&next).map_err(|e| format!("{}: {e}", next.display()))?;
            let mut newq = VecDeque::new();
            push_components(&mut newq, &target);
            if target.is_absolute() {
                cur = PathBuf::from("/");
            }
            newq.extend(queue.drain(..));
            queue = newq;
            continue;
        }

        root_only(&lmeta, &next)?;
        if queue.is_empty() {
            if !lmeta.file_type().is_file() {
                return Err(format!("{} is not a regular file", next.display()));
            }
            if need_exec && lmeta.mode() & 0o111 == 0 {
                return Err(format!("{} is not executable", next.display()));
            }
            return Ok(next);
        }
        if !lmeta.file_type().is_dir() {
            return Err(format!("{} is not a directory", next.display()));
        }
        cur = next;
    }
    Err(format!("{path} resolves to a directory"))
}

/// Programs whose job is to run *other* code given in their arguments. Approving
/// them means approving whatever that code is, so the phone gets a red warning.
const LAUNCHERS: &[&str] = &[
    "sh", "bash", "dash", "zsh", "fish", "ksh", "csh", "tcsh", "busybox", "env", "sudo", "su",
    "pkexec", "doas", "runuser", "setpriv", "nohup", "nice", "ionice", "timeout", "chroot",
    "flock", "setsid", "stdbuf", "unshare", "nsenter", "systemd-run", "find", "xargs",
    "parallel", "watch", "script", "expect", "python", "python2", "python3", "perl", "ruby",
    "node", "nodejs", "php", "lua", "tclsh", "awk", "gawk", "mawk", "sed", "make", "dpkg",
    "apt", "apt-get", "snap", "flatpak", "docker", "podman", "crontab", "at", "tmux", "screen",
    "ssh", "rsync", "git", "vim", "vi", "nvim", "nano", "less", "more", "man",
];

/// Human-readable warnings for the phone. Never blocks: the user decides.
pub fn warnings(argv: &[String]) -> Vec<String> {
    let mut w = Vec::new();
    let name = argv[0].rsplit('/').next().unwrap_or("");
    let base = name.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    if LAUNCHERS.contains(&name) || LAUNCHERS.contains(&base) {
        w.push(format!(
            "{name} can run other programs or code given in its arguments. Read every argument: that is what you are approving."
        ));
    }
    for (i, a) in argv.iter().enumerate().skip(1) {
        // Commands run with cwd "/", so relative paths resolve from there.
        let candidate = if a.starts_with('/') {
            a.clone()
        } else if a.contains('/') && !a.contains("://") {
            format!("/{a}")
        } else {
            continue;
        };
        let p = Path::new(&candidate);
        if !p.exists() {
            continue;
        }
        if p.is_dir() {
            if let Err(e) = check_dir_chain(p) {
                w.push(format!("argv[{i}] is a folder a normal user can change ({e})."));
            }
        } else if let Err(e) = resolve_trusted_file(&candidate) {
            w.push(format!(
                "argv[{i}] is a file a normal user can change ({e}). Its contents can differ from what you reviewed."
            ));
        }
    }
    w
}

fn check_dir_chain(p: &Path) -> Result<(), String> {
    let real = fs::canonicalize(p).map_err(|e| e.to_string())?;
    let mut cur = Some(real.as_path());
    while let Some(d) = cur {
        root_only(&fs::metadata(d).map_err(|e| e.to_string())?, d)?;
        cur = d.parent();
    }
    Ok(())
}

/// Check a config file the daemon trusts (it lists the approver keys).
pub fn check_root_owned_file(path: &Path) -> Result<(), String> {
    let meta = fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    root_only(&meta, path)?;
    let mut dir = path.parent();
    while let Some(d) = dir {
        let m = fs::metadata(d).map_err(|e| format!("{}: {e}", d.display()))?;
        root_only(&m, d)?;
        dir = d.parent();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn system_binaries_are_trusted() {
        // On Ubuntu 26.04 /usr/bin/env is a symlink chain into uutils coreutils,
        // and /bin is a symlink to usr/bin: both must resolve to the real file.
        let p = resolve_trusted_exe("/usr/bin/env").unwrap();
        assert_eq!(p, std::fs::canonicalize("/usr/bin/env").unwrap());
        assert_eq!(resolve_trusted_exe("/bin/env").unwrap(), p);
        assert!(resolve_trusted_exe("/usr/sbin/ufw").is_ok());
    }

    #[test]
    fn user_files_are_rejected() {
        let dir = std::env::temp_dir().join(format!("rootgate-trust-{}", crate::hex(&crate::random_bytes::<6>())));
        fs::create_dir(&dir).unwrap();
        let f = dir.join("evil");
        fs::write(&f, "#!/bin/sh\necho pwned\n").unwrap();
        fs::set_permissions(&f, fs::Permissions::from_mode(0o755)).unwrap();
        let err = resolve_trusted_exe(f.to_str().unwrap()).unwrap_err();
        assert!(err.contains("not owned by root") || err.contains("writable"), "{err}");

        // A user-owned symlink to a trusted binary is rejected too.
        let l = dir.join("link");
        std::os::unix::fs::symlink("/usr/bin/env", &l).unwrap();
        assert!(resolve_trusted_exe(l.to_str().unwrap()).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn non_files_are_rejected() {
        assert!(resolve_trusted_exe("/usr/bin").is_err());
        assert!(resolve_trusted_exe("/usr/bin/definitely-not-here-123").is_err());
        assert!(resolve_trusted_exe("/etc/hostname").is_err()); // not executable
        assert!(resolve_trusted_exe("relative").is_err());
    }

    #[test]
    fn warnings_flag_launchers_and_user_files() {
        let v = |x: &[&str]| x.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(warnings(&v(&["/usr/sbin/ufw", "status"])).is_empty());
        assert!(warnings(&v(&["/usr/bin/id", "-u"])).is_empty());
        assert_eq!(warnings(&v(&["/usr/bin/sh", "-c", "id"])).len(), 1);
        assert_eq!(warnings(&v(&["/usr/bin/python3.12", "-c", "1"])).len(), 1);
        assert_eq!(warnings(&v(&["/usr/bin/env", "id"])).len(), 1);
        // A root-owned file argument is fine.
        assert!(warnings(&v(&["/usr/bin/cat", "/etc/hostname"])).is_empty());
        // A user-owned script/file is flagged.
        let dir = std::env::temp_dir().join(format!("rootgate-warn-{}", crate::hex(&crate::random_bytes::<4>())));
        fs::create_dir(&dir).unwrap();
        let f = dir.join("x.sh");
        fs::write(&f, "id").unwrap();
        let w = warnings(&v(&["/usr/bin/cat", f.to_str().unwrap()]));
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(w[0].contains("argv[1]"));
        // A user-owned folder too (e.g. install target dir).
        assert_eq!(warnings(&v(&["/usr/bin/ls", dir.to_str().unwrap()])).len(), 1);
        // /tmp is world-writable.
        assert_eq!(warnings(&v(&["/usr/bin/ls", "/tmp"])).len(), 1);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn world_writable_dirs_are_rejected() {
        // /tmp is root-owned but world-writable (sticky): must fail.
        assert!(resolve_trusted_exe("/tmp/x").is_err());
    }
}
