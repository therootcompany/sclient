# Agent guidance

## Terminology

Use industry-standard terms. Do not invent jargon for the parts of a connection.

- MUST NOT: call the remote endpoint a "front". Say **server**, **proxy**, or the
  standard term for its role.
- MUST NOT: call the copy loops "pumps". Say **copy**, or name the direction: the
  local-to-remote copy, the remote-to-local copy.
- MUST NOT: call a deadline a "clock". A dial has a **timeout** (`--tcp-timeout`,
  `--tls-timeout`) and a **deadline**; the context that carries it is the deadline
  context. "Connect clock", "handshake clock", and "probe clock" are invented.
- MUST NOT: use "grace" as a noun. It is a **grace period**: "the grace period cuts
  the pending dial", not "the grace cut it off" or "arming the grace".
- If a thing has a standard name in the standard library, an RFC, or the docs
  (deadline, timeout, context cancellation, banner, handshake, ALPN, SNI), use
  that name. A word that appears nowhere in those sources is jargon.

Before writing a noun for a part of a connection, ask: is this the term a
net/http, net.Conn, or RFC document would use? If not, find the term.

Comments: plain English, one or two lines. Say what the code does.

This applies to comments, doc comments, README, commit messages, PR bodies, and
`./agents/` notes.

## Package structure

- `cmd/sclient/`, `cmd/ssh-tls-proxy/` - wiring only: flags, usage text, exit
  codes, the signal context. No protocol logic.
- `internal/cli/` - the argument handling both commands share: the release stamp,
  the `-V`/`--help` pre-parse, address and port parsing, seconds, protocol lists,
  and the usage-error exit. Each command keeps its own flags and usage text.
- `internal/ssh/` - the SSH probe: banner exchange, the ALPN and banner gates, the
  deadlines, the grace period, the report. Shared by both commands.
- `internal/tunnel/` - dial plumbing with no SSH knowledge: `Dial`, `DialTLS`,
  `DialPlain`, `Pipe`, `BufferedConn`, `StdioConn`, `DisplayAddr`, `ElapsedText`.
- `internal/diagnostics/` - where progress lines go when ssh nulls a
  ProxyCommand's stderr.
- `internal/ttyprobe/` - platform-specific terminal and null-fd probes.
- `sclient.go`, `doc.go` - the public library API; the CLI is a thin wrapper.

If a helper is needed by more than one command, it belongs in `internal/`, not in
`cmd/`. Two commands naming their own defaults is fine; two commands re-implementing
the same tty probe, port validator, or version stamp is not.

## Release builds

- MUST NOT: add `ldflags` to `.goreleaser.yml`. GoReleaser injects
  `-X main.version`, `-X main.commit`, and `-X main.date` by default when the main
  package declares `version`, `commit`, and `date` - `cmd/sclient/main.go` does.
  Hand-written ldflags replace that injection and stamp the wrong version.
- The defaults in main.go (`version = "v0.0.0-pre0+0000000"`) are what a plain
  `go build` prints. A GoReleaser build stamps the real tag, commit, and date:

```
$ goreleaser build --snapshot --clean && ./dist/.../sclient -V
sclient 1.5.1-SNAPSHOT-e656990 (e656990) 2026-11-17T10:15:02Z
```

- Anything that "stamps" the version at runtime (`init()`, `debug.ReadBuildInfo`)
  is for `go run` and `go install`, not for released binaries.

## SSH mode (read before touching the probe)

SSH mode (`--ssh-port`, `--ssh`) exists because the **same name** can answer on
two transports served by two different servers: plain SSH on 22, and SSH over TLS
on 443 (SNI + ALPN). Dialing both at once is the whole point - the engine decides
which to accept:

- TLS that handshakes, negotiates the ALPN, and answers the banner is ssh over
  TLS: use it.
- TLS that handshakes but will not negotiate the named ALPN has no ssh route for
  this name: it is closed at the handshake and never sees the banner.
- Otherwise, if 22 answers with an SSH banner, it is plain ssh: use it.
- Neither answers: no usable server, reported to the diagnostics destination. The
  report starts with the command name and ends with ssh's own closing line,
  `sclient: Connection closed by "<host>" ports [22, 443]` (`"NO SUCH HOST" port [0]`
  when the name never resolved).

Do not "simplify" this into trying one port and falling back to the other. The
simultaneous probe plus the banner exchange is the feature.

Two gates decide whether a candidate is usable:

- **ALPN.** A non-empty list (default `ssh`) is a requirement, not a hint. An
  explicit empty list (`--alpn ''`) turns the gate off for servers that do not
  speak ALPN at all.
- **Banner host.** RFC 4253 section 4.2 allows a comment after the version, and
  the fleet uses it to name itself: `SSH-2.0-OpenSSH_9.6 host:<name>`. When a
  banner declares hosts and none matches the name being dialled (`--servername`,
  default the host), the candidate is refused. A banner that declares nothing is
  accepted - the rule is opt-in per server.

`--ssh-port <n>` is the switch: naming the plain port turns on the dual probe.
`--ssh` is shorthand for 22 and nothing more; an explicit port always wins.
Naming `--ssh-port 0` is a usage error (exit 2), not "off". Neither flag: a
single TLS tunnel. The documented ssh_config form writes the TLS port out:

```
ProxyCommand sclient --ssh-port %p %h:443
```

Timeouts: `--tcp-timeout` bounds the connect (default 5s), `--tls-timeout` bounds
the handshake from the connect (unset = auto, 3x that candidate's connect, floor
150ms). Zero means auto, never unlimited - every dial has a deadline. Each side
resolves on its own deadline:

- connect, handshake, and banner each run on their own deadline;
- a blackholed connect is cut by the grace period (150ms after the first transport
  connects);
- a plain banner that *declares* the name we dialled is proof on its own, so the
  TLS handshake is closed instead of running to its deadline;
- a banner declaring a different host is a refusal, immediately;
- the probe is still capped by the connect timeout plus the longest handshake.

In plain mode (no SSH mode) the tunnel sniffs the local side: with no `--alpn`,
an `SSH-` banner in the first bytes means the client is ssh, so `ssh` is offered.
Detection fills in only an unset list; the peek does not consume the banner; the
peek is bounded (100ms) so a silent local connection is not mistaken for ssh.

## Live probes

The host lists live in `~/.config/agents/`:

- `tls-routers.tsv` - a router's own ssh is on 22; its TLS side on 443 does not
  offer the ssh ALPN.
- `tls-router-guests.tsv` - a guest name resolves to a router address. Only
  443 + SNI + ALPN `ssh` reaches the guest's server; 22 on that name is the
  router's ssh, a different server. Never treat a guest's 22 as the plain
  equivalent of its 443 path.
- `plain-hosts.tsv` - servers not behind a router: 443 is ordinary HTTPS, 22 is
  a real ssh server.

`sh tests/ssh-smoke.sh` reads those files and prints which candidate each name
chose. A probe is a banner exchange only: connect, read, hang up. No auth, no
state changes. Throwaway `known_hosts` files go in `agents/tmp/` and are deleted
after use - they hold real host keys.

Environment-specific hostnames, IPs, ports, and paths stay in those config files.
In source, tests, plans, docs, commit messages, and responses, refer to them by
role ("a router guest", "one of the fleet's routers").
