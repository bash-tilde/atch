#!/bin/sh
# Integration test for atch remote bootstrap (spec items 5 & 6) against a real
# sshd on localhost. Exercises the no-credentials design end-to-end: first
# contact over the user's own ssh, dedicated-key install with a restricted
# forced-command line, checksum-free binary staging, host-key pinning, and the
# --relay dispatch.
#
# Must run as root in a throwaway container (it starts sshd and writes /root).
# Usage: sh tests/ssh-test.sh <path-to-atch-binary>

ATCH="${1:-./build/atch}"

PASS=0; FAIL=0; T=0
ok()   { T=$((T+1)); PASS=$((PASS+1)); printf "ok %d - %s\n" "$T" "$1"; }
fail() { T=$((T+1)); FAIL=$((FAIL+1)); printf "not ok %d - %s\n" "$T" "$1"
         [ -n "$2" ] && printf "  # %s\n" "$2"; }
have() { case "$2" in *"$1"*) ok "$3" ;; *) fail "$3" "missing '$1' in: $2" ;; esac; }

printf "TAP version 13\n"

# ── set up openssh + sshd on localhost ───────────────────────────────────────
command -v sshd >/dev/null 2>&1 || apk add --no-cache openssh >/dev/null 2>&1
ssh-keygen -A >/dev/null 2>&1
mkdir -p /run/sshd /var/empty
cat > /etc/ssh/sshd_config <<'EOF'
Port 22
PermitRootLogin prohibit-password
PubkeyAuthentication yes
PasswordAuthentication no
UsePAM no
AuthorizedKeysFile .ssh/authorized_keys
EOF
/usr/sbin/sshd
# wait for the listener
i=0; while [ $i -lt 40 ]; do
    (echo > /dev/tcp/127.0.0.1/22) 2>/dev/null && break
    nc -z 127.0.0.1 22 2>/dev/null && break
    sleep 0.1; i=$((i+1))
done

# "User's own ssh" first-contact path: a default identity already trusted.
mkdir -p /root/.ssh; chmod 700 /root/.ssh
[ -f /root/.ssh/id_ed25519 ] || ssh-keygen -q -t ed25519 -N '' -f /root/.ssh/id_ed25519
cat /root/.ssh/id_ed25519.pub > /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys

# Make sure our config dir starts clean.
rm -rf /root/.config/atch /root/.cache/atch

# --- 1. bootstrap via `remote <host> <session>` (attach cannot complete headless) ---
# The final attach needs a tty; we only care that bootstrap's side effects land.
timeout 20 "$ATCH" remote localhost demo </dev/null >/tmp/boot.out 2>&1 || true
BOOT=$(cat /tmp/boot.out)

have "bootstrapping localhost" "$BOOT" "bootstrap: announces bootstrap"

# dedicated key generated
if [ -f /root/.config/atch/id_ed25519 ] && [ -f /root/.config/atch/id_ed25519.pub ]; then
    ok "bootstrap: dedicated identity key generated"
else
    fail "bootstrap: dedicated identity key generated"
fi

# restricted forced-command line installed for our key
AK=$(cat /root/.ssh/authorized_keys)
have "restrict,pty,command=" "$AK" "bootstrap: restricted authorized_keys line"
have "/.cache/atch/atch --relay" "$AK" "bootstrap: forced-command points at relay"
BLOB=$(awk '{print $2}' /root/.config/atch/id_ed25519.pub)
have "$BLOB" "$AK" "bootstrap: dedicated pubkey installed"

# binary staged
if [ -x /root/.cache/atch/atch ]; then
    ok "bootstrap: binary staged executable"
else
    fail "bootstrap: binary staged executable"
fi

# host key pinned in atch's private known_hosts
if ssh-keygen -F localhost -f /root/.config/atch/known_hosts >/dev/null 2>&1; then
    ok "bootstrap: host key pinned (TOFU)"
else
    fail "bootstrap: host key pinned (TOFU)"
fi

# registry records name -> host with a SHA256 fingerprint + key path
REG=$(cat /root/.config/atch/registry 2>/dev/null)
have "demo localhost SHA256:" "$REG" "bootstrap: registry entry with fingerprint"
have "id_ed25519" "$REG" "bootstrap: registry records identity key path"

# ── 2. idempotent re-bootstrap doesn't duplicate the authorized_keys line ─────
timeout 20 "$ATCH" remote localhost demo </dev/null >/dev/null 2>&1 || true
NLINES=$(grep -c -- "--relay" /root/.ssh/authorized_keys)
if [ "$NLINES" = "1" ]; then
    ok "re-bootstrap: authorized_keys line not duplicated"
else
    fail "re-bootstrap: authorized_keys line not duplicated" "found $NLINES"
fi

# ── 3. the relay actually dispatches a non-interactive command ────────────────
# Connect with the dedicated key + pinned host key; the forced command runs
# `atch --relay`, SSH_ORIGINAL_COMMAND="list" -> remote `atch list`.
RELAY=$(ssh -i /root/.config/atch/id_ed25519 -o IdentitiesOnly=yes \
            -o UserKnownHostsFile=/root/.config/atch/known_hosts \
            -o StrictHostKeyChecking=yes localhost list 2>&1)
RC=$?
if [ "$RC" = "0" ]; then ok "relay: list dispatched (exit 0)"; else fail "relay: list dispatched (exit 0)" "exit $RC: $RELAY"; fi
have "session" "$RELAY" "relay: produced atch list output"

# relay refuses re-entrancy
RR=$(ssh -i /root/.config/atch/id_ed25519 -o IdentitiesOnly=yes \
         -o UserKnownHostsFile=/root/.config/atch/known_hosts \
         -o StrictHostKeyChecking=yes localhost -- --relay 2>&1)
have "refuses" "$RR" "relay: refuses nested --relay"

# ── 4. host-key change is refused (item 6) ────────────────────────────────────
# Tamper the pinned fingerprint in the registry; bootstrap must refuse.
sed -i 's#demo localhost SHA256:[^ ]*#demo localhost SHA256:AAAAtampered#' \
    /root/.config/atch/registry
CHG=$(timeout 20 "$ATCH" remote localhost demo </dev/null 2>&1 || true)
have "HOST KEY CHANGED" "$CHG" "pinning: refuses a changed host key"

# ── 5. bare-name resolves to the remote via the registry ──────────────────────
# Distinguish routing by behaviour (socket location is meaningless when the
# "remote" is localhost): an unregistered name takes the LOCAL path and, with no
# tty, fails the terminal check; a registered name takes the REMOTE/ssh path and
# never hits that local check.
"$ATCH" remote rm demo >/dev/null 2>&1
"$ATCH" remote add demo localhost >/dev/null 2>&1

# Unregistered name → local path (no remote "connecting to ... on" line).
LOCALCTL=$(timeout 15 "$ATCH" nosuch-local </dev/null 2>&1 || true)
case "$LOCALCTL" in
    *"connecting to"*) fail "bare-name: unregistered name stays local" "routed remote: $LOCALCTL" ;;
    *) ok "bare-name: unregistered name stays local" ;;
esac

# Registered name → remote path (announces the host before the tty check).
BARE=$(timeout 15 "$ATCH" demo </dev/null 2>&1 || true)
have "connecting to 'demo' on localhost" "$BARE" "bare-name: registered name routed remote"

printf "\n1..%d\n" "$T"
printf "# %d passed, %d failed\n" "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
