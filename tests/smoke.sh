#!/bin/sh
set -Cue

# Live smoke test: pipe, stdin, and listener mode against a real TLS remote.
# Not a regression test - the regression tests are in Go. This one checks the
# things only a real TLS server can: SNI, ALPN, real keep-alive behaviour.
#
# Usage, from the repository root: tests/smoke.sh [remote]

g_bin=./bin/sclient
g_port=3000
g_remote=example.com

if test -n "${1:-}"; then
	g_remote=$1
fi

fn_pipe() (
	b_response=$("$g_bin" "$g_remote:443" < tests/get.bin)
	case "$b_response" in
		*HTTP/1.*)
			printf 'pipe: %s bytes\n' "${#b_response}"
			;;
		*)
			printf 'pipe: no reply from %s\n' "$g_remote" >&2
			exit 1
			;;
	esac
)

fn_stdin() (
	b_response=$("$g_bin" "$g_remote:443" - < tests/get.bin)
	case "$b_response" in
		*HTTP/1.*)
			printf 'stdin: %s bytes\n' "${#b_response}"
			;;
		*)
			printf 'stdin: no reply from %s\n' "$g_remote" >&2
			exit 1
			;;
	esac
)

fn_listener() (
	b_pid=
	b_attempt=0

	"$g_bin" "$g_remote:443" "localhost:$g_port" > /dev/null 2>&1 &
	b_pid=$!

	while test "$b_attempt" -lt 10; do
		if nc -z localhost "$g_port"; then
			break
		fi
		b_attempt=$((b_attempt + 1))
		sleep 1
	done
	if test "$b_attempt" -ge 10; then
		printf 'listener: port %s never came up\n' "$g_port" >&2
		exit 1
	fi

	b_response=$(nc localhost "$g_port" < tests/get.bin)
	kill "$b_pid" 2> /dev/null

	case "$b_response" in
		*HTTP/1.*)
			printf 'listener: %s bytes\n' "${#b_response}"
			;;
		*)
			printf 'listener: no reply from %s\n' "$g_remote" >&2
			exit 1
			;;
	esac
)

go build -o "$g_bin" ./cmd/sclient
fn_pipe
fn_stdin
fn_listener
