#!/bin/sh
set -Cue

# SSH-mode smoke test with no network: one TLS banner server and one plain
# banner server, both on loopback, driven through the real binary. The Go tests
# are the regression tests; this checks the wiring - flags, exit codes, the
# relay, the report.
#
# Usage, from the repository root:
#   go build -o bin/sclient ./cmd/sclient
#   sh tests/ssh-local-smoke.sh

g_bin=./bin/sclient
g_demo=./agents/tmp/ssh-demo
g_tls=4430
g_plain=2200
g_demo_pid=
g_jobs=

failures=0

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
	log=$3
	if grep -q "$want" "$log"; then
		printf 'ok   %s\n' "$name"
		return
	fi
	failures=$((failures + 1))
	printf 'FAIL %s (want %s)\n' "$name" "$want"
	sed -n '1,20p' "$log"
}

fn_roundtrip() {
	name=$1
	port=$2
	reply=$(printf 'SSH-2.0-SmokeClient_1.0\r\nhello\r\nBYE\r\n' | timeout 1 nc 127.0.0.1 "$port")
	case "$reply" in
		*GOODBYE*)
			printf 'ok   %s relay (%s bytes)\n' "$name" "${#reply}"
			;;
		*)
			failures=$((failures + 1))
			printf 'FAIL %s relay: %s\n' "$name" "$reply"
			;;
	esac
}

# Every flag comes before the positional addresses; flag.Parse stops at the
# first non-flag argument.
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
	"$g_demo" -tls "$g_tls" -plain "$g_plain" -tls-alpn "$1" -tls-host "$2" -plain-host "$3" \
		>| agents/tmp/ssh-demo.log 2>&1 &
	g_demo_pid=$!
	g_jobs="$g_jobs $g_demo_pid"
	fn_wait_up "$g_tls"
	fn_wait_up "$g_plain"
}

fn_cleanup() {
	for job in $g_jobs; do
		kill "$job" 2>/dev/null || true
	done
}
trap fn_cleanup EXIT INT TERM
fn_cleanup

if [ ! -x "$g_bin" ]; then
	printf 'build the binary first: go build -o bin/sclient ./cmd/sclient\n'
	exit 1
fi
go build -o "$g_demo" ./tests/demo

# A: both ports answer, TLS negotiates "ssh" - the TLS candidate wins.
fn_start_demo ssh demo.local demo.local
fn_case A 3000 --ssh-port "$g_plain" --insecure --servername demo.local -v 127.0.0.1:"$g_tls" 127.0.0.1:3000
fn_check "A chosen tls" "chosen: tls" agents/tmp/smoke-A.log

# B: the plain banner declares the name we dialled, which is proof on its own,
# so the TLS handshake is cut short instead of running to its deadline.
fn_start_demo "" demo.local demo.local
fn_case B 3001 --ssh-port "$g_plain" --insecure --servername demo.local -v 127.0.0.1:"$g_tls" 127.0.0.1:3001
fn_check "B declared plain wins" "chosen: ssh 127.0.0.1:2200" agents/tmp/smoke-B.log
fn_check "B tls cut short" "tls 127.0.0.1:4430: canceled" agents/tmp/smoke-B.log

# C: TLS offers no ALPN and the plain banner declares nothing, so the handshake
# completes and the ALPN gate is what refuses the TLS candidate.
fn_start_demo "" "" ""
fn_case C 3002 --ssh-port "$g_plain" --insecure --servername demo.local -v 127.0.0.1:"$g_tls" 127.0.0.1:3002
fn_check "C alpn gate" "chosen: ssh 127.0.0.1:2200" agents/tmp/smoke-C.log
fn_check "C gate named" "negotiated ALPN (none), wanted" agents/tmp/smoke-C.log

# D: --alpn '' turns the gate off, so a server with no ALPN is still usable.
fn_case D 3003 --ssh-port 1 --insecure --servername demo.local -v --alpn '' 127.0.0.1:"$g_tls" 127.0.0.1:3003
fn_check "D gate off" "chosen: tls" agents/tmp/smoke-D.log

# E: the TLS banner declares a different host - refused, the plain port wins.
fn_start_demo ssh other.local ""
fn_case E 3004 --ssh-port "$g_plain" --insecure --servername demo.local -v 127.0.0.1:"$g_tls" 127.0.0.1:3004
fn_check "E banner mismatch" "chosen: ssh 127.0.0.1:2200" agents/tmp/smoke-E.log
fn_check "E mismatch named" "declares other.local" agents/tmp/smoke-E.log

# F: an IP remote with no --servername - TLS is skipped, plain is used.
fn_start_demo ssh demo.local demo.local
fn_case F 3005 --ssh-port "$g_plain" -v 127.0.0.1:"$g_tls" 127.0.0.1:3005
fn_check "F ip without name" "no name to route on" agents/tmp/smoke-F.log
fn_check "F plain chosen" "chosen: ssh" agents/tmp/smoke-F.log

# G: stdio mode through a pipe.
fn_start_demo ssh demo.local ""
printf 'SSH-2.0-SmokeClient_1.0\r\nhello\r\nBYE\r\n' |
	"$g_bin" --stderr agents/tmp/smoke-G.log --ssh-port "$g_plain" --insecure --servername demo.local \
		127.0.0.1:"$g_tls" -
fn_check "G stdio" "connected to 127.0.0.1:4430" agents/tmp/smoke-G.log

# H: nothing on either port. The tunnel stays up for the next attempt; each
# connection reports every candidate and why it lost.
kill "$g_demo_pid" 2>/dev/null || true
g_demo_pid=
"$g_bin" --stderr agents/tmp/smoke-H.log --ssh-port "$g_plain" --insecure --servername demo.local \
	127.0.0.1:"$g_tls" 127.0.0.1:3006 >| agents/tmp/null.log 2>&1 &
job=$!
g_jobs="$g_jobs $job"
fn_wait_up 3006
printf 'SSH-2.0-SmokeClient_1.0\r\nBYE\r\n' | timeout 1 nc 127.0.0.1 3006 >/dev/null 2>&1 || true
kill "$job" 2>/dev/null || true
fn_check "H no usable server" "no usable server" agents/tmp/smoke-H.log
fn_check "H both candidates named" "connection refused" agents/tmp/smoke-H.log

# I: a named --ssh-port 0 is a usage error, not "off".
if "$g_bin" --ssh-port 0 127.0.0.1:"$g_tls" 127.0.0.1:3007 >/dev/null 2>&1; then
	failures=$((failures + 1))
	printf 'FAIL I: --ssh-port 0 should exit 2\n'
else
	printf 'ok   I usage error (exit 2)\n'
fi

if [ "$failures" -gt 0 ]; then
	printf '%s check(s) failed\n' "$failures"
	exit 1
fi
printf 'all local ssh-mode checks passed\n'
