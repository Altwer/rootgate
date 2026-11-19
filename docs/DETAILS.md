# rootgate: details

Run root commands only after you approve them on your phone.

```
ask-root (you / Claude) --unix socket--> rootgated (root) --TCP over Tailscale--> phone app
                                              ^                                      |
                                              +---- signed approval (P-256) ---------+
```

- The phone shows the **exact argv** (no shell, nothing hidden) plus the requester's "why".
- You approve with a key in the Android Keystore (fingerprint/PIN). The phone signs the
  request; your password never travels anywhere.
- Each approval is single-use (random id + nonce) and expires after 2 minutes.
- Only uid 1000 can submit, only your phone's Tailscale IP can connect as approver,
  and only enrolled keys can approve.

**The "why" is written by whoever asks. Treat it as a hint. The command is what you approve.**

## Use

```
ask-root --why "open RDP for lab PC 192.0.2.10" -- ufw allow from 192.0.2.10 to any port 3389 proto tcp
```

The terminal and the phone both show a 6-character code; they must match.
Exit status: the command's own, 124 timeout, 100 denied, 101 expired, 102 error.

## What the daemon refuses

- argv[0] that isn't an absolute path, or that (or any directory/symlink on the way to it)
  is not root-owned or is group/world-writable. Otherwise a user could swap the binary
  after you approved it. Re-checked right before running.
- Control characters, zero-width and bidi-override characters in arguments (they can make
  a command look different from what it is). The "why" may contain newlines, nothing else.
- More than 64 args / 16 KiB total, a "why" over 500 characters, more than 8 pending requests.

Commands run with a clean environment (`PATH`, `LANG`, `HOME` only), cwd `/`, no stdin
(use `-y` style flags), 10-minute timeout, output capped at 1 MiB per stream. Anything
left running in the background after the command exits is killed after 2 seconds.

## Install (after the phone app exists)

```
cargo build --release
sudo install -o root -g root -m 0755 target/release/rootgated /usr/local/sbin/
sudo install -o root -g root -m 0755 target/release/ask-root  /usr/local/bin/
sudo install -d -o root -g root -m 0755 /etc/rootgate
sudo install -o root -g root -m 0600 config.example.json /etc/rootgate/config.json
sudoedit /etc/rootgate/config.json          # paste the phone's public key
sudo install -o root -g root -m 0644 rootgated.service /etc/systemd/system/
sudo ufw allow in on tailscale0 from <phone-tailscale-ip> to any port 789 proto tcp comment rootgate   # second layer next to bind_device
sudo systemctl daemon-reload && sudo systemctl enable --now rootgated
journalctl -u rootgated -f
```

The daemon refuses to start as root if the config (or a directory above it) is not
root-owned and locked down, because the config decides which phone keys are trusted.

Never put a `rootgate-dev-approver` key into the real config: anything running as your
user could read that file and approve commands.

## Testing without the phone

```
cargo test                                             # 35 tests
cargo test --release --test leaks -- --ignored --nocapture   # 500-request leak check
target/release/rootgate-dev-approver keygen /tmp/dev.key     # terminal stand-in phone
```

## Protocol (for the Android app)

Newline-delimited JSON over TCP to `<computer-tailscale-ip>:789`. Lines are at most 64 KiB.

The phone speaks first, every connection:
- `{"type":"hello","challenge":"<32 random bytes, base64>"}`

Daemon -> phone:
- `{"type":"hello","host":"...","proto":2,"daemon_key":"<SPKI b64>","sig":"<b64 DER>"}`:
  `sig` is the daemon identity key over `"ROOTGATE-HELLO-V2\n" || str challenge || str host || str daemon_key`.
  The app pins `daemon_key` on first contact (after you compare fingerprints) and refuses a different one.
- every pending request:
  `{"type":"request","request":{id,nonce,created,expires,uid,user,host,argv,why},"code":"7RL78B","warnings":[...],"dsig":"..."}`;
  `dsig` = daemon key over `"ROOTGATE-DREQ-V2\n" || u32 len || canonical bytes || u32 count || str warning...`
- `{"type":"cancel","id":"...","reason":"approved|denied|expired|requester disconnected"}`
- `{"type":"error","id":"..."|null,"message":"..."}`
- `{"type":"ping"}` every 30 s. Answer `{"type":"pong"}` or you are dropped after 95 s of silence.

Phone -> daemon:
- `{"type":"decision","id":"...","approve":true,"sig":"<base64 DER>"}`
- `{"type":"decision","id":"...","approve":false,"sig":null}`

**What to sign:** build these bytes from the fields you display (big-endian, `str` =
u32 byte length + UTF-8 bytes), then `Signature.getInstance("SHA256withECDSA")` with the
Keystore key:

```
"ROOTGATE-V1\n"
str id, str nonce, u64 created, u64 expires, u32 uid, str user, str host,
u32 argc, str argv[0] ... str argv[argc-1], str why
```

`code` = first 30 bits of SHA-256(those bytes), 6 chars, 5 bits each from
`ABCDEFGHJKLMNPQRSTUVWXYZ23456789`. The app should recompute it and refuse on mismatch.

Known-answer test: id `00112233445566778899aabbccddeeff`, nonce `bm9uY2U=`, created 1000,
expires 1120, uid 1000, user `alice`, host `laptop`, argv `["/usr/sbin/ufw","status"]`,
why `check firewall` gives 148 bytes with SHA-256
`01456f2b5905c964399d2d52ad5a40db00347009233e83e0a32630de68170037`.

Enrolment: generate an EC P-256 key in the Android Keystore with
`setUserAuthenticationRequired(true)` and paste `Base64(publicKey.getEncoded())`
into `approver_pubkeys`.

## Network hardening (tested in `tests/net_attack.rs` and live)

- `bind_device: "tailscale0"` pins the listener to the Tailscale interface in the kernel.
  Needed when another network (e.g. some Wi-Fi) hands out 100.64.0.0/10 addresses (same range as
  Tailscale), or when Tailscale's own filtering is off (`--netfilter-mode=off`). Live check:
  connections via Wi-Fi and localhost are refused; the listener shows as
  `<computer-tailscale-ip>%tailscale0:789`.
- Unknown source IPs get closed immediately with zero bytes sent and no thread spawned
  (300-connection flood test).
- Max 4 phone connections; a phone that stops answering pings is dropped after 95 s;
  a phone that stops reading is dropped instead of stalling the daemon.
- Lines over 64 KiB, garbage, random bytes, 50 000-deep JSON nesting: connection closed,
  daemon keeps working (verified after every attack).
- A local process spoofing the phone's source IP (IP_FREEBIND) cannot connect, and even if
  it could, it could only deny or see requests, never approve without the phone key.

Run: `cargo test --release --test net_attack` (~50 s, tests run one at a time).

## Daemon identity (protocol v2)

`rootgated` creates `/etc/rootgate/daemon.key` (root, 0600) on first start and logs its
fingerprint: `journalctl -u rootgated | grep fingerprint`. The app shows the fingerprint on
first contact; tap Trust only if they match. Afterwards a different key (a copied daemon,
anything else answering on that address) is shown as a possible impostor and the app stops
connecting. The daemon listens on port 789: below 1024, so nothing running as a normal user
can take over the port while the daemon is down.

## Release build of the app (do not use the debug build for real approvals)

A debug build lets any program on a USB-connected computer inject code into the app. The
app refuses to approve while it is a debug build or while USB/wireless debugging is on.

```
cd android && ./gradlew assembleRelease            # unsigned, aligned APK
keytool -genkeypair -keystore ~/rootgate-release.jks -alias rootgate \
        -keyalg EC -groupname secp256r1 -validity 10000   # once; choose a password
~/Android/Sdk/build-tools/35.0.0/apksigner sign --ks ~/rootgate-release.jks \
        --out ~/rootgate-release.apk app/build/outputs/apk/release/app-release-unsigned.apk
```

Keep the keystore password in your head or password manager, never in a file: with the
keystore and password, someone could build a malicious "update" that keeps the approval key.

## Known limits

- **Agents and malware running as your own user.** You are in the `sudo` group, so anything
  running as your user can wait for you to type your sudo password (e.g. a fake `sudo` in
  fish config). rootgate cannot protect against that. Run AI agents and other untrusted
  automation as a separate user without sudo and put only that uid in `allowed_uids`.
- **Build artifacts live in your home folder.** Anything running as your user can modify
  `install.sh` or `target/release/*` before you run them with sudo. Check `git status` /
  `git diff` before installing.

- Deny is not signed: anything at the phone's Tailscale IP can deny (harmless) but not approve.
- Transport privacy relies on Tailscale (WireGuard). Approvals are authenticated by the
  signature regardless.
- A script's interpreter loads its own files at run time. Those live in root-owned system
  paths, but rootgate only checks the script itself.
