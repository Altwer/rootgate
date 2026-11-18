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
            if lmeta.mode() & 0o111 == 0 {
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
    fn world_writable_dirs_are_rejected() {
        // /tmp is root-owned but world-writable (sticky): must fail.
        assert!(resolve_trusted_exe("/tmp/x").is_err());
    }
}
