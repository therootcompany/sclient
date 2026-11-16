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

## Plain mode: the ALPN sniff (do not remove)

A TLS front routes SSH on ALPN `ssh`, and plain mode offers no ALPN
unless the operator names one. When `--alpn` is *unset*, the tunnel
peeks the local side's first bytes: an RFC 4253 §4.2 identification
string (`SSH-`) means the client is SSH, so `ssh` is offered.

Rules to preserve:
- Detection fills in only an unset `--alpn`. An explicit list is used
  verbatim, an explicit empty one offers nothing.
- The peek must not consume the banner - the relay still sees it.
- The peek is bounded (1s) so a client that says nothing is not
  mistaken for SSH and the tunnel never hangs.

## Identity gates (do not remove)

Two rules decide whether a candidate is usable. Both exist because a
router-fronted name can reach two different servers:

- **ALPN gate.** A non-empty `--alpn` (default `ssh`) is a requirement,
  not a hint: if the TLS handshake completes without negotiating one of
  those protocols, the TLS candidate is closed at the handshake and no
  banner is sent to it. `--alpn ''` (explicit empty) turns the gate off.
  Do not soften this back into "try the banner anyway".
- **Banner host declaration.** RFC 4253 §4.2 lets a server put a comment
  after the version, and the fleet uses it to name itself:
  `SSH-2.0-OpenSSH_9.6 tlsrouter-v0.9.4 host:<name>`. When a banner
  declares hosts via `host:` or `hostname:` and none of them equals the
  name we asked for (`--servername`, default the host), the candidate is
  refused and the mismatch is reported. A banner that declares nothing is
  accepted — the rule is opt-in per server.

The 255 report must list each candidate's outcome, including the banner
it answered with.

## Mode selection: `--ssh-port` is the switch

`--ssh-port <n>` **is** the SSH-mode switch: naming the plain port turns on
the dual-port probe (ALPN defaults to `ssh`, exit 255 when nothing is
usable, `-v` shows every candidate). `--ssh` is shorthand for
`--ssh-port 22` and nothing more; an explicit port always wins. Neither
flag: a single TLS connection.

Documented ssh_config form - the TLS port is written out, never implied:

```
ProxyCommand sclient --ssh-port %p %h:443
```

`--timeout` is always bounded: `0` means "the default" (3s), never
"unlimited". Every dial has a deadline.

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
  may be named in tests (tests/ssh-tls-proxy.sh, tests/sclient-ssh.sh): example.com,
  github.com, vms.slc1.bnna.net, ip.bnna.net, pw.bnna.net.
- Probe hygiene: banner exchange, one auth attempt, no state changes.
  Throwaway `known_hosts` files for probing go in `agents/tmp/` and are
  deleted after use (they hold real host keys).
