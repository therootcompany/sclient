#!/bin/sh
set -Cue

# Live SSH-mode smoke test: a version exchange only - connect, read the version
# string, hang up. No auth, no state changes.
#
# Which port wins is what is being checked, so each role has an expectation:
#
#   ~/.config/agents/tls-routers.tsv       a router's own ssh answers on :22;
#                                          its TLS side offers no ssh ALPN
#                                          -> expect ssh
#   ~/.config/agents/tls-router-guests.tsv a guest name reaches its server only
#                                          through :443 + SNI + ALPN ssh; :22 on
#                                          that name is the router's own ssh, a
#                                          different server -> expect tls
#   ~/.config/agents/plain-hosts.tsv       :443 is ordinary HTTPS, :22 is ssh,
#                                          no router in between -> expect ssh
#
# Usage, from the repository root:
#   go build -o ./bin/sclient ./cmd/sclient
#   sh tests/ssh-smoke.sh [routers|guests|plain|all]

g_bin=./bin/sclient
g_local=3000
g_routers=~/.config/agents/tls-routers.tsv
g_guests=~/.config/agents/tls-router-guests.tsv
g_plain=~/.config/agents/plain-hosts.tsv

# Real networks: a few hundred milliseconds to connect, or give up.
g_tcp_timeout=0.5

g_failures=0

# fn_probe runs one SSH-mode session and prints the candidate that was chosen.
fn_probe() (
	a_role=$1
	a_host=$2
	a_expect=$3

	b_log=./agents/tmp/ssh-smoke-$a_role-$a_host.log
	b_out=./agents/tmp/ssh-smoke-$a_role-$a_host.out

	if test -d ./agents/tmp; then
		:
	else
		mkdir -p ./agents/tmp
	fi

	"$g_bin" --verbose --ssh-port 22 --servername "$a_host" --tcp-timeout "$g_tcp_timeout" \
		--stderr "$b_log" "$a_host":443 localhost:"$g_local" >| "$b_out" 2>&1 &
	b_pid=$!

	# Ready when the version exchange succeeds - a bare connect would leave an
	# empty local session. Poll in 20ms steps.
	b_reply=
	b_try=0
	while test "$b_try" -lt 25; do
		b_reply=$(printf 'SSH-2.0-SmokeProbe_1.0\r\n' | nc -w 1 localhost "$g_local" 2> /dev/null || true)
		if test -n "$b_reply"; then
			break
		fi
		b_try=$((b_try + 1))
		sleep 0.02
	done

	kill "$b_pid" 2> /dev/null || true

	b_chosen=$(grep -m 1 'chosen:' "$b_log" || grep -m 1 'no usable server' "$b_log" || printf 'nothing reported')

	case "$b_chosen" in
		*"chosen: $a_expect"*)
			printf 'ok   %s %s: %s\n' "$a_role" "$a_host" "$b_chosen"
			exit 0
			;;
		*)
			printf 'FAIL %s %s: %s (want %s)\n' "$a_role" "$a_host" "$b_chosen" "$a_expect"
			exit 1
			;;
	esac

	grep -E 'version string:|dial:' "$b_log" | head -4 || true
)

# fn_probe_list walks one deployment list, counting the probes that disagree with
# the expectation for that role. It is not a subshell: the count has to survive it.
fn_probe_list() {
	a_role=$1
	a_file=$2
	a_expect=$3

	if test -r "$a_file"; then
		while read -r b_host _; do
			case "$b_host" in
				'' | host)
					continue
					;;
			esac
			if fn_probe "$a_role" "$b_host" "$a_expect"; then
				:
			else
				g_failures=$((g_failures + 1))
			fi
		done < "$a_file"
	else
		printf 'skip %s: no %s\n' "$a_role" "$a_file"
	fi
}

if test -x "$g_bin"; then
	:
else
	printf 'build the binary first: go build -o bin/sclient ./cmd/sclient\n'
	exit 1
fi

g_which=${1:-all}

if test "$g_which" = routers || test "$g_which" = all; then
	fn_probe_list router "$g_routers" ssh
fi

if test "$g_which" = guests || test "$g_which" = all; then
	fn_probe_list guest "$g_guests" tls
fi

if test "$g_which" = plain || test "$g_which" = all; then
	fn_probe_list plain "$g_plain" ssh
fi

if test "$g_failures" -gt 0; then
	printf '%s probe(s) did not behave as expected\n' "$g_failures"
	exit 1
fi

printf 'all live ssh probes behaved as expected\n'
