---
name: ssh-tls-proxy
description: Use ssh-tls-proxy, the dual-port ssh ProxyCommand that probes plain SSH and TLS-terminated SSH at once. Use when configuring ssh_config ProxyCommand lines for tenant/guest hosts behind the fleet's TLS fronts, debugging "no usable server" or swallowed diagnostics, building or installing the binary on this Mac, or running its test suites.
---

# ssh-tls-proxy

`cmd/ssh-tls-proxy` in this repo (`git.rootprojects.org/root/sclient.go`,
branch `feat/ssh-tls-proxy`). An ssh `ProxyCommand` that dials a host's
plain-SSH port AND its TLS port (443) **simultaneously**, runs the RFC 4253
§4.2 banner exchange against whichever answer(s) arrive, and splices the
client onto the winner. The simultaneous probe with the banner exchange is
the feature — never simplify to try-one-port-then-fallback (see repo
`AGENTS.md` for intent and test-host rules).

## Install (this Mac)

```sh
cd ~/Projects/golib/sclient
CGO_ENABLED=0 go build -ldflags \
  "-s -w -X main.version=$(git describe --tags --match 'v*' --dirty) \
   -X main.commit=$(git rev-parse --short HEAD) \
   -X main.date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -o ./agents/tmp/ssh-tls-proxy ./cmd/ssh-tls-proxy/
install -m 0755 ./agents/tmp/ssh-tls-proxy /Users/aj/bin/ssh-tls-proxy
/Users/aj/bin/ssh-tls-proxy -V   # exactly one "v", short commit, date
```

`/usr/local/bin` refuses non-sudo copies; `~/bin` is on PATH. The binary
must exist on every machine whose ssh_config uses it.

## ssh_config

```
Host *
    ProxyCommand ssh-tls-proxy --timeout 3 --alpn ssh --ssh-port %p %n:443
```

Flags (values shown are defaults): `--ssh-port 22`, `--tls-port 443`,
`--alpn ssh` (list), `--timeout 3` (float **seconds**, one overall clock
covering dial + handshake + banner + grace), `--servername` (default: host,
SNI/verification name), `-k/--insecure`, `-v/--verbose`, `-s/--silent`,
`-V`/`help`. Env fallbacks `SSHTLSPROXY_SSH_PORT`, `_TLS_PORT`, `_ALPN`,
`_TIMEOUT`, `_SERVERNAME` fill only flags the operator did not set (an
explicit flag always wins over env). Exit codes: 0 session done,
1 client-side failure, 2 usage error, **255 no usable server** (ssh
convention).

## Selection semantics

- TLS candidate: cert verifies against the host, TLS completed, SSH banner
  answered → **wins over plain**, whether or not ALPN matched.
- A TLS front that terminates **without** the ALPN is kept and the banner
  is still sent: on the fleet fronts ALPN is a routing hint, not a security
  property, so an empty-ALPN front is still likely forwarding to the
  intended sshd. If it does not answer, the failure report carries
  `TLS negotiated ALPN (none), required one of [ssh]`.
- Plain candidate: banner answered → used when TLS does not win.
- Neither → diagnostic on stderr, exit 255.

**Tenant/guest topology (critical):** for a guest name, :443 (SNI, TLS)
reaches the intended guest server; :22 is the **TLS router's own sshd — a
different server**. The proxy cannot tell them apart. On the TLS router's
own name, :443 is not a TLS route at all (its ssh route is raw-tunneled to
sshd, so the "TLS" handshake fails with `first record does not look like a
TLS handshake`) and :22 is the real server. Steer with `--ssh-port` when
the :22 answer is not the wanted server.

## Diagnostics visibility

The proxy prints to its inherited stderr. ssh swallows it iff `ControlPath`
(anything but `none`) AND a valued `ControlPersist` are both set (OpenSSH
≥ 8.0, deliberate design — a ControlPersist master is daemon()d off the tty;
`ControlMaster` is irrelevant). This is effectively wontfix and is already
reported upstream; do **not** file an OpenSSH bug. The proxy mirrors its
diagnostic to `/dev/tty` when it detects null stderr and a controlling
terminal exists (unix only). Escape hatches for plain stderr:
`-o ControlPath=none`, `-o ControlPersist=no`, `ssh -v`, or run the proxy
standalone.

Standalone usage for debugging:

```sh
printf 'SSH-2.0-debug\r\n' | ssh-tls-proxy -v --timeout 3 host
```

`-v` shows per-candidate dial, ALPN-note, banner, and choice lines.

## Testing

```sh
cd ~/Projects/golib/sclient
go test -race ./cmd/ssh-tls-proxy/    # unit, loopback; no network
sh tests/ssh-tls-proxy.sh             # e2e through real ssh
```

e2e cases 1-3 are offline (any environment); cases 4a-4e are live probes of
public services (owner-approved to be named in that script — see repo
`AGENTS.md` exception) and need real network. The selection line
(`using tls (...)` / `using ssh (...)`) is the live assertion; auth
success is not required. Live test hosts for the fleet itself live ONLY in
`~/.config/agents/tls-routers.tsv` and `tls-router-guests.tsv` — read them
before any live probe; never copy those hostnames into source, tests,
plans, docs, commits, or replies. Probe hygiene: banner exchange, one auth
attempt, no state changes.

## Known limitations

- `pty-req` is accepted but not emulated (interactive sessions through a
  failing path are out of scope; the success path is a dumb pipe).
- `--prefer ssh|tls` deferred.
- Loopback cannot produce a pending dial, so the blackhole timing case is a
  documented comment stub, verified live instead.

## Further reading

`agents/handoffs/ssh-tls-proxy.md` (gitignored) — the full project
document: design notes, resolved investigations (stderr swallowing, accept
mode removal, tlsrouter ALPN behavior), deployment state, and open items.
