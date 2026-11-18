# rootgate

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
sudo ufw allow in on tailscale0 from <phone-tailscale-ip> to any port 7878 proto tcp comment rootgate   # second layer next to bind_device
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

Newline-delimited JSON over TCP to `<computer-tailscale-ip>:7878`. Lines are at most 64 KiB.

Daemon -> phone:
- `{"type":"hello","host":"...","proto":1}` on connect, then every pending request
- `{"type":"request","request":{id,nonce,created,expires,uid,user,host,argv,why},"code":"7RL78B"}`
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
  `<computer-tailscale-ip>%tailscale0:7878`.
- Unknown source IPs get closed immediately with zero bytes sent and no thread spawned
  (300-connection flood test).
- Max 4 phone connections; a phone that stops answering pings is dropped after 95 s;
  a phone that stops reading is dropped instead of stalling the daemon.
- Lines over 64 KiB, garbage, random bytes, 50 000-deep JSON nesting: connection closed,
  daemon keeps working (verified after every attack).
- A local process spoofing the phone's source IP (IP_FREEBIND) cannot connect, and even if
  it could, it could only deny or see requests, never approve without the phone key.

Run: `cargo test --release --test net_attack` (~50 s, tests run one at a time).

## Known limits

- Deny is not signed: anything at the phone's Tailscale IP can deny (harmless) but not approve.
- Transport privacy relies on Tailscale (WireGuard). Approvals are authenticated by the
  signature regardless.
- A script's interpreter loads its own files at run time. Those live in root-owned system
  paths, but rootgate only checks the script itself.
