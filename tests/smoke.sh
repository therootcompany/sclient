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

fn_timeout() (
	# 192.0.2.1 (RFC 5180) is unroutable, so the connect waits for a deadline and
	# the command exits 1 on the failed dial.
	b_start=$(date +%s)
	if "$g_bin" --tcp-timeout 1 192.0.2.1:443 - < /dev/null > /dev/null 2>&1; then
		printf 'timeout: a dead remote should exit 1\n' >&2
		exit 1
	fi
	b_elapsed=$(( $(date +%s) - b_start ))
	if test "$b_elapsed" -ge 3; then
		printf 'timeout: --tcp-timeout 1 took %ss, want under 3s\n' "$b_elapsed" >&2
		exit 1
	fi
	printf 'timeout: --tcp-timeout 1 cut the connect off in %ss\n' "$b_elapsed"

	# No flag: the 5s default must still bound the dial.
	b_start=$(date +%s)
	if "$g_bin" 192.0.2.1:443 - < /dev/null > /dev/null 2>&1; then
		printf 'timeout: a dead remote should exit 1\n' >&2
		exit 1
	fi
	b_elapsed=$(( $(date +%s) - b_start ))
	if test "$b_elapsed" -lt 4 || test "$b_elapsed" -ge 10; then
		printf 'timeout: the default took %ss, want about 5s\n' "$b_elapsed" >&2
		exit 1
	fi
	printf 'timeout: the default held at %ss\n' "$b_elapsed"
)

fn_help() (
	b_help=$("$g_bin" --help)
	case "$b_help" in
		*-V*)
			printf 'help: -V is in the flag list\n'
			;;
		*)
			printf 'help: -V is not in the flag list\n' >&2
			exit 1
			;;
	esac

	b_version=$("$g_bin" -V)
	case "$b_version" in
		*sclient*Copyright*)
			printf 'version: %s\n' "$b_version"
			;;
		*)
			printf 'version: -V printed no version or copyright\n' >&2
			exit 1
			;;
	esac

	# -V is answered before anything is dialled or bound, wherever it sits.
	b_anywhere=$("$g_bin" -k --version)
	case "$b_anywhere" in
		*"sclient v"*)
			printf 'version: -V after another flag prints and exits\n'
			;;
		*)
			printf 'version: -V after another flag printed nothing\n' >&2
			exit 1
			;;
	esac

	# -h is the flag package's own: no declaration, usage on stderr, exit 0.
	b_h=$("$g_bin" -h 2>&1)
	case "$b_h" in
		*USAGE*)
			printf 'help: -h works without a declaration\n'
			;;
		*)
			printf 'help: -h printed no usage\n' >&2
			exit 1
			;;
	esac
)

go build -o "$g_bin" ./cmd/sclient
fn_help
fn_pipe
fn_stdin
fn_listener
fn_timeout
