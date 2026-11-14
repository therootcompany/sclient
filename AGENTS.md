# sclient — agent notes

## Intent (read before touching the proxy logic)

`ssh-tls-proxy` exists because the *same name* can be reachable over two
different transports that may be served by **different backends**: plain
SSH on 22, and TLS-terminated SSH on 443 (SNI + ALPN). Dialing **both at
once is the whole point** — the tool determines which to accept:

- If the 443 connection terminates TLS with the correct hostname
  (and ALPN), answers the SSH banner, it is certainly ssh-over-tls →
  use it.
- If the 443 side terminates TLS with the correct hostname but
  WITHOUT the ALPN, it may still be forwarding to the intended sshd
  (ALPN is a routing hint on the fleet fronts, not a security
  property). Send the banner anyway — there is no loss in trying —
  and use it if it answers; the "TLS negotiated ALPN (none), ..."
  note goes into the failure report if it does not.
- If the 443 side does not, but 22 answers with an SSH banner, it is
  most likely plain ssh → use it.
- Neither answers → no usable server (report to stderr, exit 255).

Do not "simplify" this into trying one port and falling back; the
simultaneous probe with the banner exchange is the feature.

## Test hosts

The parameterized live-test hosts live **only** in:

- `~/.config/agents/tls-routers.tsv` — the TLS router fleet. On a
  router name, :22 is the router's own/intended server ssh; :443 is the
  TLS front (currently no ALPN for the router names).
- `~/.config/agents/tls-router-guests.tsv` — tenant names that resolve
  to a router IP: **only** :443 + SNI + ALPN `ssh` reaches the intended
  guest server. Port 22 on a guest name is the router's ssh — a
  *different server*. Never treat a guest's :22 as the plain equivalent
  of its :443 path.

Rules:

- Read the relevant file before running any test that needs a real
  endpoint.
- Do NOT write these hostnames into source files, tests, plans,
  README, this file, or commit messages. Refer to them by role
  ("a router guest", "one of the fleet's routers").
- Owner exception (2026-11-14): the following are PUBLIC services and
  may be named in tests (tests/ssh-tls-proxy.sh): example.com,
  github.com, vms.slc1.bnna.net, ip.bnna.net, pw.bnna.net.
- Probe hygiene: banner exchange, one auth attempt, no state changes.
  Throwaway `known_hosts` files for probing go in `agents/tmp/` and are
  deleted after use (they hold real host keys).
