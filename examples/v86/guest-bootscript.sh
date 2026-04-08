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

# --- DNS resolver ---
# The bridge intercepts UDP:53 in-process.  resolv.conf is written at
# snapshot-restore time by the JS setup code (which knows the actual
# bound subnet).  On a cold boot the NIC isn't configured yet so there
# is nothing useful to put here — the snapshot will carry the right value.

echo ""
echo "=== v86 mesh guest ready ==="
echo "  sshd listening on port 22 (open root, no password)"
echo "  DNS: configured at snapshot-restore (bridge-scoped .254)"
echo "  save a browser snapshot so this persists across reloads"
echo ""
