#!/bin/sh
# e2e for ssh-tls-proxy through the real ssh client.
# Cases 1-3 are offline; case 4 probes public services (owner-approved to
# be named here) and needs network.
set -u

cd "$(dirname "$0")/.."
go build -o ./bin/ssh-tls-proxy ./cmd/ssh-tls-proxy || exit 1

fail=0
note() { printf 'FAIL: %s\n' "$*"; fail=1; }

SSH_OPTS="-T -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
# 192.0.2.1 is TEST-NET-1: guaranteed dead.

# 1a. standalone against a dead host: report on stderr, exit 255
# (ssh discards a ProxyCommand's stderr unless ControlPath is none)
out=$(printf 'SSH-2.0-e2e\r\n' | timeout 10 ./bin/ssh-tls-proxy --tcp-timeout 1 192.0.2.1 2>&1)
code=$?
[ "$code" = 255 ] || note "standalone: exit=$code, want 255"
case "$out" in
  *"no usable server"*) ;;
  *) note "standalone: missing 'no usable server': $out" ;;
esac

# 1b. via ssh: exit 255 (ssh prints its own message)
out=$(ssh $SSH_OPTS \
  -o "ProxyCommand=./bin/ssh-tls-proxy --tcp-timeout 1 192.0.2.1" \
  192.0.2.1 true 2>&1)
code=$?
[ "$code" = 255 ] || note "via ssh: exit=$code, want 255"

# 1c. ControlPersist nulls a ProxyCommand's stderr. With a pty the report
# must still reach the terminal through /dev/tty (Stderr()'s repair). Skipped
# when `script` is unavailable (no pty to allocate).
if command -v script >/dev/null 2>&1; then
  out=$(script -q /dev/null sh -c \
    'ssh -T -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ControlPath=./agents/tmp/e2e-ctl -o ControlPersist=10s -o "ProxyCommand=./bin/ssh-tls-proxy --tcp-timeout 1 192.0.2.1" 192.0.2.1 true' 2>&1)
  case "$out" in
    *"no usable server"*) ;;
    *) note "ControlPersist: report did not reach the tty: $out" ;;
  esac
  rm -f ./agents/tmp/e2e-ctl
fi

# 2. version + usage
./bin/ssh-tls-proxy -V | grep -q ssh-tls-proxy || note "-V does not print the name"
./bin/ssh-tls-proxy help | grep -q 'ProxyCommand' || note "help lacks the ssh_config example"

# 3. usage error exits 2
./bin/ssh-tls-proxy </dev/null >/dev/null 2>&1
[ $? = 2 ] || note "missing <host>: want exit 2"

# 4. Live-host probes (real network required): public services, named
# directly by owner-approved exception (2026-11-14). Probe hygiene:
# banner exchange + one auth attempt, no state changes —
# StrictHostKeyChecking=no + UserKnownHostsFile=/dev/null (in
# SSH_OPTS) write nothing, and -o ControlPath=none both keeps the
# proxy's selection line on stderr and prevents session sockets.
LIVE_OPTS="$SSH_OPTS -o ControlPath=none"

# 4a. example.com: TLS front without the ALPN, blackholed 22.
# Fast-fail: the transport-up grace must end the probe well before
# the connect clock (regression guard for the grace fast-fail).
s=$(date +%s)
out=$(ssh $LIVE_OPTS \
  -o "ProxyCommand=./bin/ssh-tls-proxy --tcp-timeout 3 --alpn ssh --ssh-port 22 example.com" \
  example.com true 2>&1)
code=$?
dt=$(( $(date +%s) - s ))
[ "$code" = 255 ] || note "live dead host: exit=$code, want 255"
case "$out" in
  *"no usable server"*) ;;
  *) note "live dead host: missing 'no usable server': $out" ;;
esac
[ "$dt" -lt 2 ] || note "live dead host: took ${dt}s, want < 2s (fast-fail grace)"

# 4b. github.com: plain ssh on :22, HTTPS (no ALPN ssh) on :443.
# The plain path must be chosen.
out=$(ssh $LIVE_OPTS \
  -o "ProxyCommand=./bin/ssh-tls-proxy --tcp-timeout 3 --alpn ssh --ssh-port 22 github.com" \
  github.com true 2>&1)
case "$out" in
  *"using ssh (github.com:22)"*) ;;
  *) note "live github: plain path not chosen: $out" ;;
esac

# 4c. a fleet router (vms.slc1): :22 is the router's own ssh, :443 is
# the TLS front without ALPN ssh. The plain path must be chosen. (Auth
# may fail; the selection line is the assertion.)
out=$(ssh $LIVE_OPTS \
  -o "ProxyCommand=./bin/ssh-tls-proxy --tcp-timeout 3 --alpn ssh --ssh-port 22 vms.slc1.bnna.net" \
  vms.slc1.bnna.net true 2>&1)
case "$out" in
  *"using ssh (vms.slc1.bnna.net:22)"*) ;;
  *) note "live router: plain path not chosen: $out" ;;
esac

# 4d/4e. Public router-guest services: :443 + SNI + ALPN ssh reaches
# the intended guest server; :22 is the router's ssh and also answers.
# Both live: the TLS-terminated path must win.
for GUEST in ip.bnna.net pw.bnna.net; do
  out=$(ssh $LIVE_OPTS \
    -o "ProxyCommand=./bin/ssh-tls-proxy --tcp-timeout 3 --alpn ssh --ssh-port 22 $GUEST" \
    "$GUEST" true 2>&1)
  case "$out" in
    *"using tls ($GUEST:443)"*) ;;
    *) note "live guest $GUEST: tls path not chosen: $out" ;;
  esac
done

[ "$fail" = 0 ] && printf 'e2e ok\n'
exit "$fail"
