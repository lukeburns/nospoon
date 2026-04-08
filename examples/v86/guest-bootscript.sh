#!/bin/sh
# v86 mesh guest — run once after fresh FreeBSD boot, then save a snapshot.
# Sets up passwordless root SSH so any mesh peer can connect.
set -e

# --- sshd config ---
SSHD_CONF=/etc/ssh/sshd_config

# Idempotent: rewrite only the lines we care about
for kv in \
  "PermitRootLogin yes" \
  "PasswordAuthentication yes" \
  "PermitEmptyPasswords yes" \
  "PubkeyAuthentication no" \
  "ChallengeResponseAuthentication no" \
  "UseDNS no" \
  "LogLevel INFO"
do
  key="${kv%% *}"
  if grep -q "^${key} " "$SSHD_CONF" 2>/dev/null; then
    sed -i '' "s|^${key} .*|${kv}|" "$SSHD_CONF"
  elif grep -q "^#${key} " "$SSHD_CONF" 2>/dev/null; then
    sed -i '' "s|^#${key} .*|${kv}|" "$SSHD_CONF"
  else
    echo "$kv" >> "$SSHD_CONF"
  fi
done

# --- host keys (generate if missing) ---
for t in rsa ecdsa ed25519; do
  f="/etc/ssh/ssh_host_${t}_key"
  [ -f "$f" ] || ssh-keygen -t "$t" -f "$f" -N "" -q
done

# --- root: no password, suppress login banner ---
pw usermod root -w none 2>/dev/null || true
touch /root/.hushlogin

# --- start sshd (daemon mode) ---
killall sshd 2>/dev/null || true
sleep 1
/usr/sbin/sshd

# --- DNS resolver (bridge intercepts UDP:53 in-process) ---
# The actual IP doesn't matter — the bridge handles it — but
# it must differ from this host's own address.
echo "nameserver 10.0.2.254" > /etc/resolv.conf

echo ""
echo "=== v86 mesh guest ready ==="
echo "  sshd listening on port 22 (open root, no password)"
echo "  DNS: nameserver 10.0.2.254 (bridge-scoped)"
echo "  save a browser snapshot so this persists across reloads"
echo ""
