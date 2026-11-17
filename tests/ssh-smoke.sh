#!/bin/sh
set -Cue

# Live SSH-mode smoke test. It probes the fleet with a banner exchange only:
# connect, read the identification string, hang up. No auth, no state changes.
#
# Host names are never written here. They come from the deployment notes:
#   ~/.config/agents/tls-routers.tsv       a router's own ssh is on :22, its TLS
#                                          front offers no ssh ALPN  -> expect :22
#   ~/.config/agents/tls-router-guests.tsv a guest name reaches its server only
#                                          through :443 + SNI + ALPN ssh; :22 on
#                                          that name is the router's own ssh
#                                          (a different server)   -> expect :443
#   ~/.config/agents/plain-hosts.tsv       :443 is ordinary HTTPS, :22 is ssh,
#                                          no router in between     -> expect :22
#
# Usage: sh tests/ssh-smoke.sh [routers|guests|plain|all]

g_bin=./bin/sclient
g_local=3000
g_routers=~/.config/agents/tls-routers.tsv
g_guests=~/.config/agents/tls-router-guests.tsv
g_plain=~/.config/agents/plain-hosts.tsv

# Real networks: connect in a few hundred milliseconds, or give up.
g_tcp_timeout=0.5

failures=0

fn_probe() {
	role=$1
	host=$2
	expect=$3

	log=./agents/tmp/live-$role-$host.log
	"$g_bin" --stderr "$log" --ssh-port 22 --servername "$host" --verbose \
		--tcp-timeout "$g_tcp_timeout" "$host":443 localhost:"$g_local" \
		>| agents/tmp/live-out.log 2>&1 &
	job=$!

	# Ready when the banner exchange succeeds; a bare connect would leave an
	# empty local session. Retry in 20ms steps.
	reply=
	for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25; do
		reply=$(printf 'SSH-2.0-SmokeProbe_1.0\r\n' | timeout 0.3 nc localhost "$g_local" 2>/dev/null || true)
		if test -n "$reply"; then
			break
		fi
		sleep 0.02
	done
	kill "$job" 2>/dev/null || true

	chosen=$(grep -m 1 'chosen:' "$log" || grep -m 1 'no usable server' "$log" || echo 'nothing reported')
	case "$chosen" in
		*"chosen: $expect"*)
			printf 'ok   %s %s: %s\n' "$role" "$host" "$chosen"
			;;
		*)
			failures=$((failures + 1))
			printf 'FAIL %s %s: %s (want %s)\n' "$role" "$host" "$chosen" "$expect"
			;;
	esac
	grep -E 'banner:|dial:' "$log" | head -4 || true
}

if [ ! -x "$g_bin" ]; then
	printf 'build the binary first: go build -o bin/sclient ./cmd/sclient\n'
	exit 1
fi

which=${1:-all}

if [ "$which" = routers ] || [ "$which" = all ]; then
	if [ -r "$g_routers" ]; then
		while read -r host _; do
			case "$host" in '' | host) continue ;; esac
			fn_probe router "$host" ssh
		done < "$g_routers"
	fi
fi

if [ "$which" = guests ] || [ "$which" = all ]; then
	if [ -r "$g_guests" ]; then
		while read -r host _; do
			case "$host" in '' | host) continue ;; esac
			fn_probe guest "$host" tls
		done < "$g_guests"
	fi
fi

if [ "$which" = plain ] || [ "$which" = all ]; then
	if [ -r "$g_plain" ]; then
		while read -r host _; do
			case "$host" in '' | host) continue ;; esac
			fn_probe plain "$host" ssh
		done < "$g_plain"
	fi
fi

if [ "$failures" -gt 0 ]; then
	printf '%s probe(s) did not behave as expected\n' "$failures"
	exit 1
fi
printf 'all live ssh probes behaved as expected\n'
