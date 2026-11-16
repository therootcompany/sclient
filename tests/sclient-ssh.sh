#!/bin/sh
# e2e for sclient's SSH mode (--ssh-port) through the real ssh client.
# Cases 1-3 are offline (TEST-NET-1 is guaranteed dead). Cases 4-5 are live
# probes of public services (owner-approved to be named here): run with LIVE=1.
set -u

cd "$(dirname "$0")/.."
go build -o ./bin/sclient ./cmd/sclient || exit 1

fail=0
note() { printf 'FAIL: %s\n' "$*"; fail=1; }

SSH_OPTS="-T -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ControlPath=none"
SSH_PORT=22

# 1a. standalone against a dead host: informative stderr, exit 255
out=$(printf 'SSH-2.0-e2e\r\n' | timeout 10 ./bin/sclient --ssh-port "$SSH_PORT" --timeout 1 192.0.2.1 2>&1)
code=$?
[ "$code" = 255 ] || note "standalone: exit=$code, want 255"
case "$out" in
  *"no usable server"*) ;;
  *) note "standalone: missing 'no usable server': $out" ;;
esac

# 1b. --ssh is shorthand for --ssh-port 22: same mode, same probe of :22
out=$(printf 'SSH-2.0-e2e\r\n' | timeout 10 ./bin/sclient --ssh -v --timeout 1 192.0.2.1 2>&1)
code=$?
[ "$code" = 255 ] || note "--ssh alone: exit=$code, want 255"
case "$out" in
  *"192.0.2.1:22"*) ;;
  *) note "--ssh alone did not probe port 22: $out" ;;
esac

# 1c. -v/--verbose prints every candidate and its banner
out=$(printf 'SSH-2.0-e2e\r\n' | timeout 10 ./bin/sclient --verbose --ssh-port "$SSH_PORT" --timeout 1 192.0.2.1 2>&1)
case "$out" in
  *"dial: ssh"*) ;;
  *) note "verbose: no 'dial: ssh' line: $out" ;;
esac
case "$out" in
  *"dial: tls"*) ;;
  *) note "verbose: no 'dial: tls' line: $out" ;;
esac

# 1d. --timeout 0 is the default clock, not "forever": a dead host still
# fails, and it fails bounded (well under 10s).
start=$(date +%s)
out=$(printf 'SSH-2.0-e2e\r\n' | timeout 20 ./bin/sclient --ssh-port "$SSH_PORT" --timeout 0 192.0.2.1 2>&1)
code=$?
elapsed=$(( $(date +%s) - start ))
[ "$code" = 255 ] || note "timeout 0: exit=$code, want 255"
[ "$elapsed" -le 8 ] || note "timeout 0: took ${elapsed}s, want the 3s clock"

# 2. version + usage
./bin/sclient -V | grep -q sclient || note "-V does not print the name"
./bin/sclient --ssh-port 22 </dev/null 2>&1 | grep -q -- '--ssh-port' || note "usage lacks the --ssh-port example"

# 3. usage errors exit 2
./bin/sclient --ssh-port "$SSH_PORT" example.com:notaport - >/dev/null 2>&1
[ $? = 2 ] || note "bad remote port: want exit 2"
./bin/sclient --ssh-port -1 example.com >/dev/null 2>&1
[ $? = 2 ] || note "negative --ssh-port: want exit 2"
./bin/sclient --ssh-port 0 example.com >/dev/null 2>&1
[ $? = 2 ] || note "explicit --ssh-port 0: want exit 2 (0 is the sentinel, not a port)"

# 4. Live SSH mode: a router guest reached through 443 + ALPN. The selection
# line is the assertion; auth success is not required, so key rotation will
# not break the suite.
if [ "${LIVE:-0}" = 1 ]; then
  out=$(ssh $SSH_OPTS \
    -o "ProxyCommand=./bin/sclient --ssh-port $SSH_PORT --timeout 3 pw.bnna.net" \
    pw.bnna.net true 2>&1)
  case "$out" in
    *"using tls"*) ;;
    *) note "4: no TLS selection line: $out" ;;
  esac

  # 5. Plain mode + the SSH banner sniff: no --ssh-port, still reaches sshd
  # over 443 because the client announced itself as SSH.
  out=$(ssh $SSH_OPTS \
    -o "ProxyCommand=./bin/sclient pw.bnna.net -" \
    pw.bnna.net true 2>&1)
  case "$out" in
    *"publickey"*) ;;
    *) note "5: plain+sniff did not reach sshd: $out" ;;
  esac
fi

if [ "$fail" = 0 ]; then
  printf 'sclient --ssh-port e2e ok\n'
else
  exit 1
fi
