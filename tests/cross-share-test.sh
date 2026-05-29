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

# ── owner starts a shared `cat` session ──────────────────────────────────────
"$ATCH" start demo cat
i=0; while [ $i -lt 20 ] && [ ! -S /root/.cache/atch/demo ]; do sleep 0.1; i=$((i+1)); done

# alice read-only (default), carol read-write, @atchteam read-only; bob excluded
"$ATCH" share demo --to "alice,carol:rw,@atchteam" -m 0 >/tmp/share.out 2>&1
SH=$(cat /tmp/share.out)
has "shared to 3 target" "$SH" "share: three targets armed"
i=0; while [ $i -lt 20 ] && [ ! -S "$GS" ]; do sleep 0.1; i=$((i+1)); done
if [ -S "$GS" ]; then ok "share: guest listener present"; else fail "share: guest listener present"; fi

# ── staged guest binary: a guest with no atch can exec it by absolute path ────
# Owner is root here, so it lands at /run/atch/atch (the /run path); a non-root
# owner would get /tmp/.atch-bin.<uid>.
STAGED=/run/atch/atch
if [ -x "$STAGED" ]; then ok "stage: guest binary present at $STAGED"; else fail "stage: guest binary present" "$STAGED missing"; fi
has "$STAGED join demo" "$SH" "stage: share output prints the binless-guest command"
# a different, unprivileged user can actually execute the staged copy
if su bob -c "$STAGED --version" >/dev/null 2>&1; then
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

# ── 3. unshare drops the listener; a former guest can no longer connect ───────
"$ATCH" unshare demo >/dev/null 2>&1
i=0; while [ $i -lt 20 ] && [ -S "$GS" ]; do sleep 0.1; i=$((i+1)); done
if [ ! -S "$GS" ]; then ok "unshare: guest listener gone"; else fail "unshare: guest listener gone"; fi
poke alice
RC_AFTER=$(su alice -c "/tmp/guestpoke '$GS'" 2>&1; echo $?)
case "$RC_AFTER" in *3) ok "unshare: connect refused after revoke" ;; *) fail "unshare: connect refused after revoke" "$RC_AFTER" ;; esac

"$ATCH" kill demo >/dev/null 2>&1

printf "\n1..%d\n" "$T"
printf "# %d passed, %d failed\n" "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
