#!/bin/sh
set -Cue

# SSH-mode smoke test with no network: one TLS banner server and one plain banner
# server on loopback, driven through the real binary. The Go tests cover the gates;
# this checks the wiring - flags, the listener, stdio, exit codes, the report.
#
#   go build -o bin/sclient ./cmd/sclient
#   sh tests/ssh-local-smoke.sh

g_bin=./bin/sclient
g_demo=./agents/tmp/ssh-demo
g_tls=4430
g_plain=2200
g_demo_pid=
g_failures=0

# A loopback connect is sub-millisecond, so poll in 20ms steps rather than
# sleeping blind.
fn_wait_up() {
	port=$1
	n=0
	while [ "$n" -lt 25 ]; do
		if nc -z 127.0.0.1 "$port" >/dev/null 2>&1; then
			return 0
		fi
		sleep 0.02
		n=$((n + 1))
	done
	printf 'FAIL: nothing listening on %s\n' "$port"
	return 1
}

fn_check() {
	name=$1
	want=$2
	file=$3
	if grep -q "$want" "$file"; then
		printf 'ok   %s\n' "$name"
		return
	fi
	g_failures=$((g_failures + 1))
	printf 'FAIL %s (want %s)\n' "$name" "$want"
	sed -n '1,20p' "$file"
}

# fn_once is fn_check when the line must appear exactly N times.
fn_once() {
	name=$1
	want=$2
	pattern=$3
	file=$4
	count=$(grep -c "$pattern" "$file" || true)
	if [ "$count" -eq "$want" ]; then
		printf 'ok   %s\n' "$name"
		return
	fi
	g_failures=$((g_failures + 1))
	printf 'FAIL %s: %s appeared %s time(s), want %s\n' "$name" "$pattern" "$count" "$want"
	sed -n '1,20p' "$file"
}

fn_roundtrip() {
	name=$1
	port=$2
	reply=$(printf 'SSH-2.0-SmokeClient_1.0\r\nhello\r\nBYE\r\n' | timeout 0.3 nc 127.0.0.1 "$port")
	case "$reply" in
		*GOODBYE*)
			printf 'ok   %s relay (%s bytes)\n' "$name" "${#reply}"
			;;
		*)
			g_failures=$((g_failures + 1))
			printf 'FAIL %s relay: %s\n' "$name" "$reply"
			;;
	esac
}

# Every flag comes before the positional addresses; flag.Parse stops at the first
# non-flag argument.
fn_case() {
	name=$1
	port=$2
	shift 2
	"$g_bin" --stderr "agents/tmp/smoke-$name.log" --tcp-timeout 0.1 "$@" &
	job=$!
	g_jobs="$g_jobs $job"
	if fn_wait_up "$port"; then
		fn_roundtrip "$name" "$port"
	fi
	kill "$job" 2>/dev/null || true
}

fn_start_demo() {
	if [ -n "$g_demo_pid" ]; then
		kill "$g_demo_pid" 2>/dev/null || true
	fi
	# >| because set -C forbids clobbering an existing file.
	"$g_demo" -tls "$g_tls" -plain "$g_plain" -tls-alpn "$1" -tls-host "$2" -plain-host "$3" -tls-delay "${4:-0}" \
		>| agents/tmp/ssh-demo.log 2>&1 &
	g_demo_pid=$!
	g_jobs="$g_jobs $g_demo_pid"
	fn_wait_up "$g_tls"
	fn_wait_up "$g_plain"
}

g_jobs=
fn_cleanup() {
	for job in $g_jobs; do
		kill "$job" 2>/dev/null || true
	done
}
trap fn_cleanup EXIT INT TERM

if [ ! -x "$g_bin" ]; then
	printf 'build the binary first: go build -o bin/sclient ./cmd/sclient\n'
	exit 1
fi
go build -o "$g_demo" ./tests/demo
rm -f agents/tmp/smoke-*.log agents/tmp/null.log

if nc -z 127.0.0.1 "$g_tls" >/dev/null 2>&1 || nc -z 127.0.0.1 "$g_plain" >/dev/null 2>&1; then
	printf 'FAIL: port %s or %s is already in use; stop the leftover demo server\n' "$g_tls" "$g_plain"
	exit 1
fi

# A: both ports answer and TLS negotiates "ssh" - the TLS candidate wins. The plain
# banner declares nothing, so it proves nothing and TLS keeps its chance.
fn_start_demo ssh demo.local ""
fn_case A 3000 --ssh-port "$g_plain" --insecure --servername demo.local -v 127.0.0.1:"$g_tls" 127.0.0.1:3000
fn_check "A chosen tls" "chosen: tls" agents/tmp/smoke-A.log

# B: the plain banner declares the name being dialled, which is proof on its own,
# so the TLS handshake is cut short instead of running to its deadline. The TLS
# side is slowed down so the cancellation is not a loopback race.
fn_start_demo "" demo.local demo.local 200ms
fn_case B 3001 --ssh-port "$g_plain" --insecure --servername demo.local -v 127.0.0.1:"$g_tls" 127.0.0.1:3001
fn_check "B declared plain wins" "chosen: ssh 127.0.0.1:2200" agents/tmp/smoke-B.log
fn_check "B tls cut short" "tls 127.0.0.1:4430: canceled" agents/tmp/smoke-B.log

# C: TLS offers no ALPN - the gate refuses it and the plain port is used.
fn_start_demo "" "" ""
fn_case C 3002 --ssh-port "$g_plain" --insecure --servername demo.local -v 127.0.0.1:"$g_tls" 127.0.0.1:3002
fn_check "C alpn gate" "negotiated ALPN (none) in" agents/tmp/smoke-C.log

# D: stdio mode through a pipe: the payload is stdout, diagnostics are the log.
fn_start_demo ssh demo.local ""
printf 'SSH-2.0-SmokeClient_1.0\r\nhello\r\nBYE\r\n' |
	timeout 0.3 "$g_bin" --stderr agents/tmp/smoke-D.log --ssh-port "$g_plain" --insecure \
		--servername demo.local 127.0.0.1:"$g_tls" - >| agents/tmp/smoke-D.out
fn_check "D stdio chose tls" "stdin => 127.0.0.1:4430" agents/tmp/smoke-D.log
fn_check "D stdio relayed" "GOODBYE" agents/tmp/smoke-D.out

# E: nothing on either port. Each connection names every candidate and why it lost.
kill "$g_demo_pid" 2>/dev/null || true
g_demo_pid=
"$g_bin" --stderr agents/tmp/smoke-E.log --ssh-port "$g_plain" --insecure --servername demo.local \
	127.0.0.1:"$g_tls" 127.0.0.1:3006 >| agents/tmp/null.log 2>&1 &
job=$!
g_jobs="$g_jobs $job"
fn_wait_up 3006
printf 'SSH-2.0-SmokeClient_1.0\r\nBYE\r\n' | timeout 0.3 nc 127.0.0.1 3006 >/dev/null 2>&1 || true
kill "$job" 2>/dev/null || true
fn_check "E no usable server" "sclient: 127.0.0.1: no usable server" agents/tmp/smoke-E.log
fn_check "E close line names the ports" 'Connection closed by "127.0.0.1" ports' agents/tmp/smoke-E.log

# F: a named --ssh-port 0 is a usage error (2), not "off".
if "$g_bin" --ssh-port 0 127.0.0.1:"$g_tls" 127.0.0.1:3007 >/dev/null 2>&1; then
	g_failures=$((g_failures + 1))
	printf 'FAIL F: --ssh-port 0 should exit 2\n'
else
	printf 'ok   F usage error (exit 2)\n'
fi

# G: a name that does not resolve is one failure, named once, before either dial.
if printf 'SSH-2.0-SmokeClient_1.0\r\nBYE\r\n' |
	timeout 3 "$g_bin" --stderr agents/tmp/smoke-G.log --ssh-port "$g_plain" \
		--insecure --servername does-not-exist.invalid does-not-exist.invalid:443 - >/dev/null 2>&1; then
	g_failures=$((g_failures + 1))
	printf 'FAIL G: an unresolvable name should exit 1\n'
else
	printf 'ok   G unresolvable name (exit 1)\n'
fi
fn_once "G lookup named once" 1 "no such host" agents/tmp/smoke-G.log
fn_check "G close line has no host" 'Connection closed by "NO SUCH HOST" port \[0\]' agents/tmp/smoke-G.log

if [ "$g_failures" -gt 0 ]; then
	printf '%s check(s) failed\n' "$g_failures"
	exit 1
fi
printf 'all local ssh-mode checks passed\n'
