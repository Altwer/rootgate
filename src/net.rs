//! Small socket helpers: bounded line reads, peer credentials, hang-up detection.

use std::ffi::CStr;
use std::io::{self, BufRead, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;

/// Read one `\n`-terminated line of at most `max` bytes (newline excluded).
/// Ok(None) on clean EOF. A longer line is an error, so a peer cannot make us
/// buffer unbounded data.
pub fn read_line_bounded<R: BufRead>(r: &mut R, max: usize) -> io::Result<Option<String>> {
    let mut buf = Vec::new();
    let n = r.by_ref().take(max as u64 + 1).read_until(b'\n', &mut buf)?;
    if n == 0 {
        return Ok(None);
    }
    if buf.last() == Some(&b'\n') {
        buf.pop();
    } else if buf.len() > max {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
    } else {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "connection closed mid-line"));
    }
    String::from_utf8(buf)
        .map(Some)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "line is not UTF-8"))
}

/// Serialize `msg` as one JSON line.
pub fn send_json<W: Write, T: serde::Serialize>(w: &mut W, msg: &T) -> io::Result<()> {
    let mut line = serde_json::to_vec(msg).map_err(io::Error::other)?;
    line.push(b'\n');
    w.write_all(&line)?;
    w.flush()
}

/// uid and pid of the process on the other end of a Unix socket (kernel-verified).
pub fn peer_cred(s: &UnixStream) -> io::Result<(u32, i32)> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: valid fd, pointer and length for SO_PEERCRED.
    let rc = unsafe {
        libc::getsockopt(
            s.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((cred.uid, cred.pid))
}

/// True if the peer has closed its end (or the socket errored).
pub fn peer_hung_up<F: AsRawFd>(s: &F) -> bool {
    let mut pfd = libc::pollfd {
        fd: s.as_raw_fd(),
        events: libc::POLLRDHUP,
        revents: 0,
    };
    // SAFETY: one valid pollfd, zero timeout.
    let rc = unsafe { libc::poll(&mut pfd, 1, 0) };
    rc > 0 && (pfd.revents & (libc::POLLRDHUP | libc::POLLHUP | libc::POLLERR | libc::POLLNVAL)) != 0
}

/// Only accept traffic that arrived on interface `dev` (SO_BINDTODEVICE).
/// Packets for the listening address that come in over any other interface
/// (e.g. Wi-Fi with an overlapping 100.64.0.0/10 address) never reach us.
pub fn bind_to_device<F: AsRawFd>(s: &F, dev: &str) -> io::Result<()> {
    if dev.is_empty() || dev.len() >= libc::IFNAMSIZ || dev.contains('\0') {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad interface name"));
    }
    // SAFETY: valid fd; the name pointer/length describe a live byte slice.
    let rc = unsafe {
        libc::setsockopt(
            s.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            dev.as_ptr().cast(),
            dev.len() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Login name for a uid, or "uid<N>".
pub fn username(uid: u32) -> String {
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 4096];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: buffers are valid for the call; result is checked before use.
    let rc = unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result) };
    if rc == 0 && !result.is_null() && !pwd.pw_name.is_null() {
        unsafe { CStr::from_ptr(pwd.pw_name) }.to_string_lossy().into_owned()
    } else {
        format!("uid{uid}")
    }
}

pub fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn bounded_lines() {
        let mut r = Cursor::new(b"hello\nworld\n".to_vec());
        assert_eq!(read_line_bounded(&mut r, 10).unwrap().as_deref(), Some("hello"));
        assert_eq!(read_line_bounded(&mut r, 10).unwrap().as_deref(), Some("world"));
        assert_eq!(read_line_bounded(&mut r, 10).unwrap(), None);

        let mut long = Cursor::new(vec![b'a'; 100]);
        assert!(read_line_bounded(&mut long, 10).is_err());

        let mut exact = Cursor::new(b"0123456789\n".to_vec());
        assert_eq!(read_line_bounded(&mut exact, 10).unwrap().as_deref(), Some("0123456789"));

        let mut partial = Cursor::new(b"no newline".to_vec());
        assert!(read_line_bounded(&mut partial, 100).is_err());

        let mut bad = Cursor::new(vec![0xff, 0xfe, b'\n']);
        assert!(read_line_bounded(&mut bad, 10).is_err());
    }

    #[test]
    fn peer_cred_and_hangup() {
        let (a, b) = UnixStream::pair().unwrap();
        let (uid, pid) = peer_cred(&a).unwrap();
        assert_eq!(uid, unsafe { libc::getuid() });
        assert_eq!(pid, std::process::id() as i32);
        assert!(!peer_hung_up(&a));
        drop(b);
        assert!(peer_hung_up(&a));
    }

    #[test]
    fn names() {
        assert_eq!(username(0), "root");
        assert!(!hostname().is_empty());
    }
}
