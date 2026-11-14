#!/bin/sh
# e2e: sclient --ssh through the real ssh client.
# Cases 1-3 are offline (TEST-NET-1 is guaranteed dead; no keys are
# presented because the proxy dies before auth) and run in any
# environment. Case 4 is a live probe of a public service (owner
# approved to be named here, 2026-11-14) and needs real network plus a
# usable ssh identity: run with LIVE=1.
set -u

cd "$(dirname "$0")/.."
go build -o ./bin/sclient ./cmd/sclient || exit 1

fail=0
note() { printf 'FAIL: %s\n' "$*"; fail=1; }

SSH_OPTS="-T -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ControlPath=none"

# 1a. standalone against a dead host: informative stderr, exit 255
out=$(printf 'SSH-2.0-e2e\r\n' | timeout 10 ./bin/sclient --ssh --timeout 1 192.0.2.1 2>&1)
code=$?
[ "$code" = 255 ] || note "standalone: exit=$code, want 255"
case "$out" in
  *"no usable server"*) ;;
  *) note "standalone: missing 'no usable server': $out" ;;
esac

# 1b. via ssh ProxyCommand: exit 255 (ssh prints its own message)
out=$(ssh $SSH_OPTS \
  -o "ProxyCommand=./bin/sclient --ssh --timeout 1 192.0.2.1" \
  192.0.2.1 true 2>&1)
code=$?
[ "$code" = 255 ] || note "via ssh: exit=$code, want 255"

# 2. version + usage
./bin/sclient -V | grep -q sclient || note "-V does not print the name"
./bin/sclient --ssh </dev/null 2>&1 | grep -q -- '--ssh' || note "usage lacks the --ssh example"

# 3. usage errors exit 2
./bin/sclient --ssh example.com:notaport - >/dev/null 2>&1
[ $? = 2 ] || note "bad port: want exit 2"

# 4. Live: a router guest reached through 443 + ALPN. The selection
# line is the assertion; auth success is not required, so key rotation
# will not break the suite.
if [ "${LIVE:-0}" = 1 ]; then
  out=$(ssh $SSH_OPTS \
    -o "ProxyCommand=./bin/sclient --ssh --timeout 3 pw.bnna.net" \
    pw.bnna.net true 2>&1)
  case "$out" in
    *"using tls"*) ;;
    *) note "4: no TLS selection line: $out" ;;
  esac
fi

if [ "$fail" = 0 ]; then
  printf 'sclient --ssh e2e ok\n'
else
  exit 1
fi
