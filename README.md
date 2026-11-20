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

You need Linux, Android and Tailscale on both. The easiest way is a
[release](../../releases): a Linux archive for your CPU (`x86_64` or `aarch64`) and the
APK. Unpack the archive and run the steps below inside it, skipping the build.
Building from source needs Rust and the Android SDK.

1. Fill in your settings. Everything machine-specific (IPs, phone key, user id) lives
   in one file, `rootgate.env`, which git ignores:
   ```
   cp rootgate.env.example rootgate.env
   ```
   | Setting        | What it is                                   | Where to find it    |
   |----------------|----------------------------------------------|---------------------|
   | `COMPUTER_IP`  | this computer's Tailscale IP (optional)      | `tailscale ip -4`   |
   | `PHONE_IP`     | the phone's Tailscale IP                     | Tailscale app       |
   | `PHONE_PUBKEY` | the phone's approval key                     | rootgate app        |
   | `ALLOWED_UID`  | the user allowed to run `ask-root` (optional)| `id -u`             |

   Fill in `COMPUTER_IP` before building the app so it is pre-filled there; get
   `PHONE_PUBKEY` from the app after installing it.
2. (From source only) Build the daemon, and the app from `android/` (see [docs/DETAILS.md](docs/DETAILS.md)
   for a release build), and install the app on your phone:
   ```
   cargo build --release
   ```
3. Install the service:
   ```
   sudo ./install.sh
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
