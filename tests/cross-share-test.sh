#!/bin/sh
# Cross-user sharing test (spec items 2 & 3): proves SO_PEERCRED authorization
# and the read-only keystroke drop with REAL distinct uids — the part the main
# suite leaves to a manual recipe because it can't be done as a single user.
#
# Strategy: the owner shares a `cat` session; helper `guestpoke` connects to the
# guest listener as each test user (su), so the master reads that user's
# SO_PEERCRED and writes an audit line. A granted read-write user's pushed bytes
# echo back through cat into the session log; a read-only user's are dropped.
#
# Must run as root in a throwaway container (creates users). The owner is root.
# Usage: sh tests/cross-share-test.sh <path-to-atch-binary>

ATCH="${1:-./build/atch}"

PASS=0; FAIL=0; T=0
ok()   { T=$((T+1)); PASS=$((PASS+1)); printf "ok %d - %s\n" "$T" "$1"; }
fail() { T=$((T+1)); FAIL=$((FAIL+1)); printf "not ok %d - %s\n" "$T" "$1"
         [ -n "$2" ] && printf "  # %s\n" "$2"; }
has()    { case "$2" in *"$1"*) ok "$3" ;;   *) fail "$3" "missing '$1'" ;; esac; }
hasnot() { case "$2" in *"$1"*) fail "$3" "found '$1'" ;; *) ok "$3" ;; esac; }

printf "TAP version 13\n"

LOG=/root/.cache/atch/demo.log
GS=/tmp/.atch-guest.0.demo           # owner is root (uid 0)
rm -rf /root/.cache/atch; mkdir -p /root/.cache/atch

# ── build the connector helper with the same gcc that built atch ─────────────
gcc -O2 -o /tmp/guestpoke "$(dirname "$0")/guestpoke.c" || { echo "Bail out! gcc failed"; exit 1; }

# ── test users: alice (granted RO), carol (granted RW), dave (group), bob (no) ─
addgroup atchteam 2>/dev/null
for u in alice carol dave bob; do adduser -D -s /bin/sh "$u" 2>/dev/null; done
adduser dave atchteam 2>/dev/null
A=$(id -u alice); C=$(id -u carol); D=$(id -u dave); B=$(id -u bob)

# helper: connect to the guest socket as a user, optional push string
poke() { su "$1" -c "/tmp/guestpoke '$GS' ${2:+'$2'}" >/dev/null 2>&1; }
# helper: connect and send one raw control packet (type len), e.g. MSG_REDRAW 4 / REDRAW_WINCH 3
poke_pkt() { su "$1" -c "/tmp/guestpoke '$GS' --pkt $2 $3" >/dev/null 2>&1; }

# ── owner starts a shared session ─────────────────────────────────────────────
# Background `cat` echoes pushed input into the log; a short-sleep foreground
# loop keeps the shell responsive so the SIGWINCH trap actually runs (POSIX
# defers traps while a foreground utility like `cat` is blocked) — the trap
# echoes a marker so we can observe whether a guest's MSG_REDRAW(WINCH) reached
# the program.
"$ATCH" start demo sh -c 'trap "echo GOTWINCH" 28; cat & while :; do sleep 0.2; done'
i=0; while [ $i -lt 20 ] && [ ! -S /root/.cache/atch/demo ]; do sleep 0.1; i=$((i+1)); done

# alice read-only (default), carol read-write, @atchteam read-only; bob excluded
"$ATCH" share demo --to "alice,carol:rw,@atchteam" -m 0 >/tmp/share.out 2>&1
SH=$(cat /tmp/share.out)
has "shared to 3 target" "$SH" "share: three targets armed"
i=0; while [ $i -lt 20 ] && [ ! -S "$GS" ]; do sleep 0.1; i=$((i+1)); done
if [ -S "$GS" ]; then ok "share: guest listener present"; else fail "share: guest listener present"; fi

# ── staged guest binary: a guest with no atch can exec it by absolute path ────
# Now a RANDOM, exclusively-created /tmp name (defeats symlink/TOCTOU). The exact
# path is unguessable, so we read it from the share output.
STAGED=$(printf '%s\n' "$SH" | grep -oE '/tmp/\.atch-bin\.[0-9]+\.[A-Za-z0-9]+' | head -1)
if [ -n "$STAGED" ] && [ -x "$STAGED" ]; then
    ok "stage: guest binary staged at a random /tmp path ($STAGED)"
else
    fail "stage: guest binary staged at a random /tmp path" "got '$STAGED'"
fi
# a different, unprivileged user can actually execute the staged copy
if [ -n "$STAGED" ] && su bob -c "$STAGED --version" >/dev/null 2>&1; then
    ok "stage: ungranted-but-binless user can exec the staged copy"
else
    fail "stage: ungranted user can exec the staged copy"
fi

# ── 1. SO_PEERCRED accept/reject (observed via the master's audit log) ────────
poke alice;  poke carol;  poke dave;  poke bob
sleep 0.3
AUD=$(cat "$LOG" 2>/dev/null)

has "guest uid=$A joined read-only"  "$AUD" "auth: granted user accepted read-only"
has "guest uid=$C joined read-write" "$AUD" "auth: per-target :rw accepted read-write"
has "guest uid=$D joined"            "$AUD" "auth: supplementary-group member accepted"
has "guest uid=$B rejected"          "$AUD" "auth: ungranted user rejected"

# ── 2. read-only keystroke drop vs read-write passthrough ─────────────────────
# carol (RW) pushes a marker → cat echoes it into the log; alice (RO) pushes a
# different marker → master drops it, so it never reaches the session.
poke carol "RWPASSe"
poke alice "RODROPe"
sleep 0.5
SESS=$(cat "$LOG" 2>/dev/null)
has    "RWPASS" "$SESS" "read-write guest: keystrokes reach the session"
hasnot "RODROP" "$SESS" "read-only guest: keystrokes are dropped"

# ── 2b. read-only guests cannot redraw/resize/signal the shared pty (H2) ──────
# MSG_REDRAW(4) with REDRAW_WINCH(3) makes the master SIGWINCH the program. The
# trap echoes GOTWINCH. A read-only guest must NOT trigger it; a read-write one
# may. Do read-only first and confirm no marker, then read-write and confirm it.
poke_pkt alice 4 3
sleep 0.5
hasnot "GOTWINCH" "$(cat "$LOG" 2>/dev/null)" "read-only guest: MSG_REDRAW/WINCH dropped"
poke_pkt carol 4 3
sleep 0.5
has    "GOTWINCH" "$(cat "$LOG" 2>/dev/null)" "read-write guest: MSG_REDRAW/WINCH delivered"

# ── 3. unshare drops the listener + staged binary; a former guest can't connect ─
"$ATCH" unshare demo >/dev/null 2>&1
i=0; while [ $i -lt 20 ] && [ -S "$GS" ]; do sleep 0.1; i=$((i+1)); done
if [ ! -S "$GS" ]; then ok "unshare: guest listener gone"; else fail "unshare: guest listener gone"; fi
if [ -n "$STAGED" ] && [ ! -e "$STAGED" ]; then ok "unshare: staged guest binary removed"; else fail "unshare: staged guest binary removed" "$STAGED still present"; fi
poke alice
RC_AFTER=$(su alice -c "/tmp/guestpoke '$GS'" 2>&1; echo $?)
case "$RC_AFTER" in *3) ok "unshare: connect refused after revoke" ;; *) fail "unshare: connect refused after revoke" "$RC_AFTER" ;; esac

"$ATCH" kill demo >/dev/null 2>&1

printf "\n1..%d\n" "$T"
printf "# %d passed, %d failed\n" "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
