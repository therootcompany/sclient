#!/bin/sh
set -Cue

# ssh-tls-proxy smoke test, no network: one TLS banner server and one plain banner
# server on loopback, driven through the real binary in stdio mode - the shape a
# ssh ProxyCommand uses. The Go tests cover the gates; this checks the wiring:
# flags, exit codes, the relay, the report.
#
#   go build -o bin/ssh-tls-proxy ./cmd/ssh-tls-proxy
#   sh tests/ssh-tls-proxy.sh

g_bin=./bin/ssh-tls-proxy
g_demo=./agents/tmp/ssh-demo
g_tls=4440
g_plain=2240
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
rm -f agents/tmp/proxy-*.log agents/tmp/proxy-*.out

if nc -z 127.0.0.1 "$g_tls" >/dev/null 2>&1 || nc -z 127.0.0.1 "$g_plain" >/dev/null 2>&1; then
	printf 'FAIL: port %s or %s is already in use; stop the leftover demo server\n' "$g_tls" "$g_plain"
	exit 1
fi

# A: both ports answer; TLS is preferred and the client's payload round trips.
fn_start_demo ssh demo.local ""
printf 'SSH-2.0-SmokeClient_1.0\r\nBYE\r\n' |
	timeout 0.3 "$g_bin" --stderr agents/tmp/proxy-A.log --ssh-port "$g_plain" \
		--insecure --servername demo.local -v 127.0.0.1:"$g_tls" \
		>| agents/tmp/proxy-A.out
fn_check "A chosen tls" "chosen: tls" agents/tmp/proxy-A.log
fn_check "A relayed" "GOODBYE" agents/tmp/proxy-A.out

# B: --listen puts SSH clients on a local port instead of stdin and stdout.
"$g_bin" --stderr agents/tmp/proxy-B.log --ssh-port "$g_plain" --insecure --servername demo.local \
	--listen 127.0.0.1:3010 127.0.0.1:"$g_tls" &
job=$!
fn_wait_up 3010
reply=$(printf 'SSH-2.0-SmokeClient_1.0\r\nBYE\r\n' | timeout 0.3 nc 127.0.0.1 3010)
kill "$job" 2>/dev/null || true
case "$reply" in
	*GOODBYE*)
		printf 'ok   B listen relay\n'
		;;
	*)
		g_failures=$((g_failures + 1))
		printf 'FAIL B listen relay: %s\n' "$reply"
		;;
esac

# C: nothing on either port - every candidate is named and the exit code is 1.
kill "$g_demo_pid" 2>/dev/null || true
g_demo_pid=
if printf 'SSH-2.0-SmokeClient_1.0\r\nBYE\r\n' |
	timeout 0.3 "$g_bin" --stderr agents/tmp/proxy-C.log --ssh-port "$g_plain" \
		--insecure --servername demo.local 127.0.0.1:"$g_tls" >/dev/null 2>&1; then
	g_failures=$((g_failures + 1))
	printf 'FAIL C: no usable server should exit 1\n'
else
	printf 'ok   C no usable server (exit 1)\n'
fi
fn_check "C both candidates named" "ssh-tls-proxy: 127.0.0.1: no usable server" agents/tmp/proxy-C.log
fn_check "C close line names the ports" 'Connection closed by "127.0.0.1" ports' agents/tmp/proxy-C.log

# D: a bad port is a usage error (2), -V is a version and exit 0.
if "$g_bin" --ssh-port 0 127.0.0.1:443 >/dev/null 2>&1; then
	g_failures=$((g_failures + 1))
	printf 'FAIL D: --ssh-port 0 should exit 2\n'
else
	printf 'ok   D usage error (exit 2)\n'
fi

if "$g_bin" -V >/dev/null 2>&1; then
	printf 'ok   E version\n'
else
	g_failures=$((g_failures + 1))
	printf 'FAIL E: -V should exit 0\n'
fi

if [ "$g_failures" -gt 0 ]; then
	printf '%s check(s) failed\n' "$g_failures"
	exit 1
fi
printf 'all ssh-tls-proxy checks passed\n'
