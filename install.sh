#!/bin/bash
# Install rootgate as a root service.
#   cp rootgate.env.example rootgate.env   # fill in your values
#   cargo build --release
#   sudo ./install.sh
# Values can also be given as arguments, which override rootgate.env:
#   sudo ./install.sh [--new-config] ["<phone public key>" <phone tailscale ip> [uid]]
# Safe to re-run: binaries and unit are replaced, an existing config is kept
# unless you pass --new-config as the first argument.
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "run with sudo"; exit 1; }
cd "$(dirname "$0")"

# rootgate.env is read as plain KEY=value lines, never executed.
PHONE_PUBKEY="" PHONE_IP="" COMPUTER_IP="" ALLOWED_UID=""
if [[ -f rootgate.env ]]; then
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%%#*}"
    [[ "$line" =~ ^[[:space:]]*([A-Z_]+)[[:space:]]*=[[:space:]]*\"?([^\"[:space:]]*)\"?[[:space:]]*$ ]] || continue
    case "${BASH_REMATCH[1]}" in
      PHONE_PUBKEY|PHONE_IP|COMPUTER_IP|ALLOWED_UID) printf -v "${BASH_REMATCH[1]}" '%s' "${BASH_REMATCH[2]}" ;;
    esac
  done < rootgate.env
fi

NEW_CONFIG=0
if [[ "${1:-}" == "--new-config" ]]; then NEW_CONFIG=1; shift; fi
PUBKEY="${1:-$PHONE_PUBKEY}"
PHONE_IP="${2:-$PHONE_IP}"
ALLOW_UID="${3:-${ALLOWED_UID:-${SUDO_UID:-1000}}}"
[[ -n "$PUBKEY" && -n "$PHONE_IP" ]] || { echo "set PHONE_PUBKEY and PHONE_IP in rootgate.env (see rootgate.env.example)"; exit 1; }

[[ -x target/release/rootgated && -x target/release/ask-root ]] || { echo "build first: cargo build --release"; exit 1; }
[[ "$PUBKEY" =~ ^[A-Za-z0-9+/=]{80,200}$ ]] || { echo "that does not look like a base64 public key"; exit 1; }
[[ "$PHONE_IP" =~ ^100\.([0-9]{1,3}\.){2}[0-9]{1,3}$ ]] || { echo "phone ip must be a Tailscale 100.x.y.z address"; exit 1; }
[[ "$ALLOW_UID" =~ ^[0-9]+$ ]] || { echo "ALLOWED_UID must be a number"; exit 1; }
LISTEN_IP="${COMPUTER_IP:-$(tailscale ip -4 | head -1)}"
[[ "$LISTEN_IP" =~ ^100\.([0-9]{1,3}\.){2}[0-9]{1,3}$ ]] || { echo "computer ip must be a Tailscale 100.x.y.z address; is tailscale up?"; exit 1; }

echo "== binaries"
install -o root -g root -m 0755 target/release/rootgated /usr/local/sbin/rootgated
install -o root -g root -m 0755 target/release/ask-root /usr/local/bin/ask-root

echo "== config"
install -d -o root -g root -m 0755 /etc/rootgate
if [[ ! -e /etc/rootgate/config.json || $NEW_CONFIG -eq 1 ]]; then
  umask 077
  cat > /etc/rootgate/config.json <<EOF
{
  "socket_path": "/run/rootgate/rootgate.sock",
  "listen": "$LISTEN_IP:789",
  "bind_device": "tailscale0",
  "approver_ips": ["$PHONE_IP"],
  "approver_pubkeys": ["$PUBKEY"],
  "allowed_uids": [$ALLOW_UID],
  "request_ttl_secs": 120,
  "exec_timeout_secs": 600
}
EOF
  chown root:root /etc/rootgate/config.json
  chmod 0600 /etc/rootgate/config.json
  echo "wrote /etc/rootgate/config.json (listen $LISTEN_IP:789, phone $PHONE_IP, uid $ALLOW_UID)"
else
  echo "kept existing /etc/rootgate/config.json (use --new-config to replace)"
fi

echo "== systemd"
install -o root -g root -m 0644 rootgated.service /etc/systemd/system/rootgated.service
systemctl daemon-reload
systemctl enable rootgated >/dev/null 2>&1
systemctl restart rootgated

echo "== firewall"
if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
  # Old unprivileged port from v1, if present.
  ufw delete allow in on tailscale0 from "$PHONE_IP" to any port 7878 proto tcp >/dev/null 2>&1 || true
  ufw allow in on tailscale0 from "$PHONE_IP" to any port 789 proto tcp comment rootgate >/dev/null
  echo "ufw: allowed 789/tcp from $PHONE_IP on tailscale0 only"
else
  echo "ufw not active; relying on bind_device + IP allowlist + signatures"
fi

sleep 1
systemctl --no-pager --lines=5 status rootgated || true
echo
echo "Daemon identity (compare with the fingerprint the phone shows before tapping Trust):"
journalctl -u rootgated -n 50 --no-pager -o cat | grep "identity fingerprint" | tail -1
echo
echo "Done. Try:  ask-root --why \"test\" -- id -u"
