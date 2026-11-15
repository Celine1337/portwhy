#!/usr/bin/env bash
# Self-contained test suite for portwhy.
# Part 1 drives a synthetic /proc tree (PORTWHY_PROC) for deterministic
# parsing/enrichment assertions. Part 2 starts OUR OWN tiny python3 TCP
# listener on an ephemeral port, verifies live forensics, then kills ONLY
# that listener. No other processes are touched.
set -uo pipefail
cd "$(dirname "$0")"
export TC="$HOME/.local/toolchains"
export PATH="$TC/go/go/bin:$TC/lua/bin:$TC/node/bin:$HOME/.local/bin:$PATH"
./build.sh >/dev/null || { echo "FAIL: build failed"; exit 1; }
PW="./bin/portwhy"
TMP="$(mktemp -d)"
LPID=""
cleanup(){ [ -n "$LPID" ] && kill "$LPID" 2>/dev/null; rm -rf "$TMP"; }
trap cleanup EXIT
pass=0; fail=0
ok(){ pass=$((pass+1)); echo "ok $pass - $1"; }
bad(){ fail=$((fail+1)); echo "FAIL: $1"; }
# check name expected_exit expected_substring actual_exit actual_out
check(){
  local name="$1" want_rc="$2" want="$3" rc="$4" out="$5"
  if [ "$rc" != "$want_rc" ]; then bad "$name (exit $rc, want $want_rc)"; return; fi
  if [ -n "$want" ] && ! printf '%s' "$out" | grep -qF -- "$want"; then
    bad "$name (output missing '$want')"; return
  fi
  ok "$name"
}
check_absent(){
  local name="$1" unwanted="$2" out="$3"
  if printf '%s' "$out" | grep -qF -- "$unwanted"; then
    bad "$name (output unexpectedly contains '$unwanted')"; return
  fi
  ok "$name"
}

# ---------- Part 1: synthetic /proc fixture ----------
P="$TMP/proc"
mkdir -p "$P/net" "$P/4242/fd" "$P/4200" "$P/1" "$P/4343/fd"
cat > "$P/net/tcp" <<'EOF'
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 111 1 0000000000000000 100 0 0 10 0
   1: 0100007F:1F91 0100007F:A1B2 01 00000000:00000000 00:00000000 00000000  1000        0 999 1 0000000000000000 100 0 0 10 0
   2: 00000000:1B9E 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 555 1 0000000000000000 100 0 0 10 0
EOF
cat > "$P/net/tcp6" <<'EOF'
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:238C 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 222 1 0000000000000000 100 0 0 10 0
EOF
printf 'testd\n' > "$P/4242/comm"
printf 'testd\0--flag\0' > "$P/4242/cmdline"
printf 'Name:\ttestd\nState:\tS (sleeping)\nPPid:\t4200\n' > "$P/4242/status"
printf '0::/system.slice/demo.service\n' > "$P/4242/cgroup"
ln -s 'socket:[111]' "$P/4242/fd/3"
printf 'bash\n' > "$P/4200/comm"
printf 'Name:\tbash\nPPid:\t1\n' > "$P/4200/status"
printf 'systemd\n' > "$P/1/comm"
printf 'Name:\tsystemd\nPPid:\t0\n' > "$P/1/status"
printf 'v6d\n' > "$P/4343/comm"
printf 'v6d\0' > "$P/4343/cmdline"
printf 'Name:\tv6d\nPPid:\t1\n' > "$P/4343/status"
printf '0::/system.slice/other.service\n' > "$P/4343/cgroup"
ln -s 'socket:[222]' "$P/4343/fd/7"

export PORTWHY_PROC="$P"
out=$($PW 8080); rc=$?
check "fixture: 8080 owned by pid 4242" 0 "tcp 127.0.0.1:8080  pid=4242 comm=testd" "$rc" "$out"
check "fixture: cmdline NULs joined" 0 "cmdline: testd --flag" "$rc" "$out"
check "fixture: PPid ancestry walk" 0 "ancestry: 4200(bash) <- 1(systemd)" "$rc" "$out"
check "fixture: cgroup + systemd unit" 0 "unit: demo.service" "$rc" "$out"
printf '%s' "$out" | grep -qF "cgroup: 0::/system.slice/demo.service" && ok "fixture: cgroup line" || bad "fixture: cgroup line"

out=$($PW 9100); rc=$?
check "fixture: tcp6 ::1 decoded" 0 "tcp6 ::1:9100  pid=4343 comm=v6d" "$rc" "$out"
check "fixture: tcp6 unit" 0 "unit: other.service" "$rc" "$out"

out=$($PW); rc=$?
check "fixture: unowned listener shows pid=?" 0 "0.0.0.0:7070  pid=? comm=?" "$rc" "$out"
check_absent "fixture: ESTABLISHED socket filtered out" ":8081" "$out"

$PW 8080 --json > "$TMP/one.json"; rc=$?
if [ "$rc" = 0 ] && python3 - "$TMP/one.json" <<'PYEOF'
import json, sys
d = json.load(open(sys.argv[1]))
assert isinstance(d, list) and len(d) == 1, d
l = d[0]
assert l["proto"] == "tcp" and l["address"] == "127.0.0.1"
assert l["port"] == 8080 and l["pid"] == 4242 and l["inode"] == 111
assert l["comm"] == "testd" and l["cmdline"] == "testd --flag"
assert l["unit"] == "demo.service"
assert l["ancestry"][0] == {"pid": 4200, "comm": "bash"}
assert l["ancestry"][1]["pid"] == 1
PYEOF
then ok "fixture: --json structure"; else bad "fixture: --json structure (rc=$rc)"; fi

out=$($PW 65000 --json); rc=$?
check "fixture: empty JSON is [] not null" 0 "[]" "$rc" "$out"
out=$($PW 65000); rc=$?
check "fixture: free port message" 0 "no listener on port 65000" "$rc" "$out"

out=$($PW abc 2>/dev/null); rc=$?
check "usage: non-numeric port exits 2" 2 "" "$rc" "$out"
out=$($PW 0 2>/dev/null); rc=$?
check "usage: port 0 exits 2" 2 "" "$rc" "$out"
out=$($PW 70000 2>/dev/null); rc=$?
check "usage: port 70000 exits 2" 2 "" "$rc" "$out"
out=$($PW --bogus 2>/dev/null); rc=$?
check "usage: unknown flag exits 2" 2 "" "$rc" "$out"
out=$($PW 80 443 2>/dev/null); rc=$?
check "usage: two ports exit 2" 2 "" "$rc" "$out"
out=$($PW --help); rc=$?
check "usage: --help exits 0" 0 "usage: portwhy" "$rc" "$out"
out=$(PORTWHY_PROC="$TMP/empty" $PW 2>/dev/null); rc=$?
check "io: unreadable proc root exits 2" 2 "" "$rc" "$out"
unset PORTWHY_PROC

# ---------- Part 2: live listener (our own process only) ----------
cat > "$TMP/listener.py" <<'PYEOF'
import socket, time
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 0))
s.listen(1)
print(s.getsockname()[1], flush=True)
time.sleep(300)
PYEOF
python3 "$TMP/listener.py" > "$TMP/port.txt" 2>/dev/null &
LPID=$!
LPORT=""
for _ in $(seq 1 50); do
  LPORT="$(cat "$TMP/port.txt" 2>/dev/null)"
  [ -n "$LPORT" ] && break
  sleep 0.1
done
if [ -z "$LPORT" ]; then
  bad "live: listener did not report a port"
else
  out=$($PW "$LPORT"); rc=$?
  check "live: reports our listener pid" 0 "pid=$LPID" "$rc" "$out"
  printf '%s' "$out" | grep -qF "127.0.0.1:$LPORT" && ok "live: reports ephemeral port" || bad "live: reports ephemeral port"
  $PW "$LPORT" --json > "$TMP/live.json"; rc=$?
  if [ "$rc" = 0 ] && python3 - "$TMP/live.json" "$LPID" "$LPORT" <<'PYEOF'
import json, sys
d = json.load(open(sys.argv[1]))
assert len(d) == 1, d
l = d[0]
assert l["pid"] == int(sys.argv[2]) and l["port"] == int(sys.argv[3])
assert l["proto"] == "tcp" and l["address"] == "127.0.0.1"
assert l["comm"] and l["cmdline"]
PYEOF
  then ok "live: --json pid/port match"; else bad "live: --json pid/port match (rc=$rc)"; fi
  kill "$LPID" 2>/dev/null; wait "$LPID" 2>/dev/null; LPID=""
  sleep 0.2
  out=$($PW "$LPORT"); rc=$?
  check "live: port free again after kill" 0 "no listener on port $LPORT" "$rc" "$out"
fi

echo "----------------------------------------"
echo "portwhy: $pass passed, $fail failed"
[ "$fail" -eq 0 ] && echo "ALL CHECKS PASSED" || exit 1