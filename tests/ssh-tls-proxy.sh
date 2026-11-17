#!/bin/sh
set -Cue

# ssh-tls-proxy smoke test with no network: one TLS banner server and one plain
# banner server, both on loopback, driven through the real binary in stdio mode
# - the way ssh uses a ProxyCommand. The Go tests are the regression tests; this
# checks the wiring: flags, exit codes, the relay, the report.
#
# Usage, from the repository root:
#   go build -o bin/ssh-tls-proxy ./cmd/ssh-tls-proxy
#   sh tests/ssh-tls-proxy.sh

g_bin=./bin/ssh-tls-proxy
g_demo=./agents/tmp/ssh-demo
g_tls=4430
g_plain=2200
g_demo_pid=
g_failures=0

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

fn_start_demo() {
	if [ -n "$g_demo_pid" ]; then
		kill "$g_demo_pid" 2>/dev/null || true
	fi
	# >| because set -C forbids clobbering an existing file.
	"$g_demo" -tls "$g_tls" -plain "$g_plain" -tls-alpn "$1" -tls-host "$2" -plain-host "$3" \
		>| agents/tmp/ssh-demo.log 2>&1 &
	g_demo_pid=$!
	fn_wait_up "$g_tls"
	fn_wait_up "$g_plain"
}

# fn_session writes the client's banner and a BYE, captures stdout (the payload)
# and the diagnostics separately.
fn_session() {
	name=$1
	shift
	printf 'SSH-2.0-SmokeClient_1.0\r\nBYE\r\n' |
		timeout 1 "$g_bin" --stderr "agents/tmp/proxy-$name.log" --tcp-timeout 0.1 "$@" \
		>| "agents/tmp/proxy-$name.out"
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
	printf 'FAIL %s (want %s in %s)\n' "$name" "$want" "$file"
	sed -n '1,20p' "$file"
}

if [ ! -x "$g_bin" ]; then
	printf 'build the binary first: go build -o bin/ssh-tls-proxy ./cmd/ssh-tls-proxy\n'
	exit 1
fi
go build -o "$g_demo" ./tests/demo

if nc -z 127.0.0.1 "$g_tls" >/dev/null 2>&1 || nc -z 127.0.0.1 "$g_plain" >/dev/null 2>&1; then
	printf 'FAIL: port %s or %s is already in use; stop the leftover demo server\n' "$g_tls" "$g_plain"
	exit 1
fi

# A: both ports answer, TLS negotiates "ssh" - the TLS candidate wins, and the
# client sees the winner's banner followed by the server's GOODBYE. The plain
# banner declares nothing, so it proves nothing and TLS keeps its chance.
fn_start_demo ssh demo.local ""
fn_session A --ssh-port "$g_plain" --insecure --servername demo.local -v 127.0.0.1:"$g_tls"
fn_check "A chosen tls" "chosen: tls" agents/tmp/proxy-A.log
fn_check "A relayed" "GOODBYE" agents/tmp/proxy-A.out

# B: the plain banner declares the name being dialled, which is proof on its
# own, so the TLS handshake is cut short instead of running to its deadline.
fn_start_demo "" demo.local demo.local
fn_session B --ssh-port "$g_plain" --insecure --servername demo.local -v 127.0.0.1:"$g_tls"
fn_check "B chosen plain" "chosen: ssh" agents/tmp/proxy-B.log
fn_check "B tls cut short" "tls 127.0.0.1:4430: canceled" agents/tmp/proxy-B.log

# C: TLS offers no ALPN and the plain banner declares nothing - the ALPN gate
# refuses the TLS candidate, the plain port is used.
fn_start_demo "" "" ""
fn_session C --ssh-port "$g_plain" --insecure --servername demo.local -v 127.0.0.1:"$g_tls"
fn_check "C alpn gate" "negotiated ALPN (none), wanted" agents/tmp/proxy-C.log
fn_check "C chosen plain" "chosen: ssh" agents/tmp/proxy-C.log

# D: --alpn '' turns the gate off, so a server with no ALPN is still usable.
fn_session D --ssh-port 1 --insecure --servername demo.local -v --alpn '' 127.0.0.1:"$g_tls"
fn_check "D gate off" "chosen: tls" agents/tmp/proxy-D.log

# E: the TLS banner declares a different host - refused, the plain port wins.
fn_start_demo ssh other.local ""
fn_session E --ssh-port "$g_plain" --insecure --servername demo.local -v 127.0.0.1:"$g_tls"
fn_check "E banner mismatch" "declares other.local" agents/tmp/proxy-E.log
fn_check "E chosen plain" "chosen: ssh" agents/tmp/proxy-E.log

# F: an IP remote with no --servername - TLS is skipped, plain is used.
fn_start_demo ssh demo.local demo.local
fn_session F --ssh-port "$g_plain" -v 127.0.0.1:"$g_tls"
fn_check "F ip without name" "no name to route on" agents/tmp/proxy-F.log
fn_check "F plain chosen" "chosen: ssh" agents/tmp/proxy-F.log

# G: --listen puts SSH clients on a local port instead of stdin and stdout.
fn_start_demo ssh demo.local demo.local
"$g_bin" --stderr agents/tmp/proxy-G.log --ssh-port "$g_plain" --insecure --servername demo.local \
	--listen 127.0.0.1:3010 127.0.0.1:"$g_tls" &
job=$!
fn_wait_up 3010
reply=$(printf 'SSH-2.0-SmokeClient_1.0\r\nBYE\r\n' | timeout 1 nc 127.0.0.1 3010)
kill "$job" 2>/dev/null || true
case "$reply" in
	*GOODBYE*)
		printf 'ok   G listen relay\n'
		;;
	*)
		g_failures=$((g_failures + 1))
		printf 'FAIL G listen relay: %s\n' "$reply"
		;;
esac

# H: nothing on either port - every candidate is named and the exit code is 1.
kill "$g_demo_pid" 2>/dev/null || true
g_demo_pid=
if fn_session H --ssh-port "$g_plain" --insecure --servername demo.local 127.0.0.1:"$g_tls"; then
	g_failures=$((g_failures + 1))
	printf 'FAIL H: no usable server should exit 1\n'
else
	printf 'ok   H no usable server (exit 1)\n'
fi
fn_check "H both candidates named" "no usable server" agents/tmp/proxy-H.log

# I: a bad port is a usage error (exit 2), not a runtime failure.
if "$g_bin" --ssh-port 0 127.0.0.1:443 >/dev/null 2>&1; then
	g_failures=$((g_failures + 1))
	printf 'FAIL I: --ssh-port 0 should exit 2\n'
else
	printf 'ok   I usage error (exit 2)\n'
fi

# J: -V prints the version and exits 0.
if "$g_bin" -V >/dev/null 2>&1; then
	printf 'ok   J version\n'
else
	g_failures=$((g_failures + 1))
	printf 'FAIL J: -V should exit 0\n'
fi

if [ "$g_failures" -gt 0 ]; then
	printf '%s check(s) failed\n' "$g_failures"
	exit 1
fi
printf 'all ssh-tls-proxy checks passed\n'
