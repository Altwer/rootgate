# rootgate

Run root commands only after you approve them on your phone.

You (or an AI agent) ask for a command with `ask-root`. Your phone shows the exact
command and why it's needed. You approve it with your fingerprint, and only then does
it run as root.

## Usage

```
ask-root --why "check the firewall" -- /usr/sbin/ufw status
```

- The terminal and the phone show the same 6-character code; check that they match.
- The command must be a full path (`/usr/sbin/ufw`, not `ufw`).
- Requests expire after 2 minutes.
- Exit codes: the command's own, or `100` denied, `101` expired, `102` error, `124` timeout.

## Install

You need Rust, Tailscale on the computer and the phone, and the rootgate Android app
(in `android/`).

1. Build:
   ```
   cargo build --release
   ```
2. Install the app on your phone and copy its public key.
3. Install the service (pass the phone's key and its Tailscale IP):
   ```
   sudo ./install.sh "<phone public key>" <phone tailscale ip>
   ```
4. Open the app and trust the computer if the fingerprint matches:
   ```
   journalctl -u rootgated | grep fingerprint
   ```

Done. Try `ask-root --why test -- /usr/bin/id`.

For the protocol, security details and the release build of the app, see
[docs/DETAILS.md](docs/DETAILS.md).

## License

MIT, see [LICENSE](LICENSE).
