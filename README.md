# sclient

Secure Client for exposing TLS (aka SSL) secured services as plain-text
connections locally.

Also ideal for multiplexing a single port with multiple protocols using SNI.

Unwrap a TLS connection:

```bash
sclient whatever.com:443 localhost:3000

> [listening] whatever.com:443 <= localhost:3000
```

Connect via Telnet

```bash
telnet localhost 3000
```

Connect via netcat (nc)

```bash
nc localhost 3000
```

cURL

```bash
curl http://localhost:3000 -H 'Host: whatever.com'
```

A poor man's (or Windows user's) makeshift replacement for `openssl s_client`,
`stunnel`, or `socat`.

# Table of Contents

- [Install](#install)
- [Usage](#usage)
- [Examples](#examples)
- [SSH mode](#ssh-mode)
- [ssh-tls-proxy](#ssh-tls-proxy)
- [API](#api)
- [Build from source](#build-from-source)
- [Tests](#tests)

# Install

### Mac, Linux

```bash
curl -sS https://webinstall.dev/sclient | bash
```

```bash
curl.exe -A MS https://webinstall.dev/sclient | powershell
```

### Downloads

Check the [Github Releases](https://github.com/therootcompany/sclient/releases)
for

- macOS (x64, Apple Silicon)
- Linux (x64, arm64, armv7)
- Windows (x64, arm64)
- FreeBSD (x64, arm64, armv7)

# Usage

```bash
sclient [flags] <remote> <local>
```

- flags
  - `-s`, `--silent` less verbose logging
  - `-k`, `--insecure` ignore invalid TLS (SSL/HTTPS) certificates
  - `--servername <domain>` spoof SNI (to disable use IP as &lt;remote&gt; and do
    not use this option)
  - `--alpn <protocol-list>` acceptable protocols, ex: `h2,http/1.1` `ssh`
  - `--ssh-port <n>` probe a plain SSH port alongside `<remote>` at once: SSH
    mode. `<remote>` stays the TLS side.
  - `--ssh` shorthand for `--ssh-port 22`.
  - `-v`, `--verbose` show what each dial did (SSH mode: every candidate and the
    banner it answered with)
  - `--stderr <path>` a file or device, ex `sclient.log`, `/dev/tty`, `/dev/null`
  - `--tcp-timeout <seconds>` seconds for the TCP connect, DNS included
    (0 = default, 5s)
  - `--tls-timeout <seconds>` seconds for the TLS handshake, from the connect
    (0 = auto, 3x connection time)
- remote
  - a hostname or an IP
  - port is optional (default is 443)
- local
  - address is optional (default is localhost)
  - must have port (i.e. 3000)

# Examples

Bridge between `telebit.cloud` and local port `3000`.

```bash
sclient telebit.cloud 3000
```

Same as above, but more explicit

```bash
sclient telebit.cloud:443 localhost:3000
```

Ignore a bad TLS/SSL/HTTPS certificate and connect anyway.

```bash
sclient -k badtls.telebit.cloud:443 localhost:3000
```

Connect to an IP. The certificate must have that IP, or name it, or skip
verification.

```bash
sclient 203.0.113.1:443 localhost:3000
sclient --servername telebit.cloud 203.0.113.1:443 localhost:3000
sclient -k 203.0.113.1:443 localhost:3000
```

Reading from stdin

```bash
sclient telebit.cloud:443 -
```

```bash
sclient telebit.cloud:443 - </path/to/file
```

Piping

```bash
printf "GET / HTTP/1.1\r\nHost: telebit.cloud\r\n\r\n" | sclient telebit.cloud:443
```

Testing for security vulnerabilities on the remote:

```bash
sclient --servername "Robert'); DROP TABLE Students;" -k example.com localhost:3000
```

```bash
sclient --servername "../../../.hidden/private.txt" -k example.com localhost:3000
```

# SSH mode

A name can answer on plain `:22` **and** on TLS-terminated `:443` (ALPN `ssh`),
sometimes on different servers. Naming `--ssh-port` dials both at once, runs the
SSH banner exchange (RFC 4253 section 4.2) against whichever answers, prefers the
TLS connection, and relays you onto the winner. Trying one port and falling back
to the other is a different, weaker tool: the probe is simultaneous.

```bash
# as an ssh ProxyCommand: the plain port and the TLS port probed at once
ssh -o ProxyCommand='sclient --ssh-port %p %h:443' example.com

# stunnel-style: a local listener for SSH clients
sclient --ssh-port 22 example.com:443 localhost:3000
```

Write the TLS port out (`%h:443`) rather than leaving it implied: it names the
side being probed and keeps `%p` unambiguously the plain SSH port.

Two gates tell the two servers apart:

- **ALPN** - a named `--alpn` is a requirement, not a hint. A TLS connection that
  negotiates none of it has no ssh route for this name: it is closed at the
  handshake and never sees the banner. `--alpn ''` turns the gate off.
- **Banner host** - a server can name itself in the banner comment, ex:
  `SSH-2.0-OpenSSH_9.6 host:example.com`. If it declares hosts and none matches
  the name you dialled (`--servername`, default the host), the candidate is
  refused. A banner that declares nothing is accepted.

An IP remote is not probed over TLS in SSH mode - an address carries no name to
route on. `--servername` names the server and makes the TLS side fair game.

Plain mode sniffs the local side: with no `--alpn`, an `SSH-` banner on the first
bytes means the client is ssh, so `ssh` is offered. The peek does not consume the
banner.

# ssh-tls-proxy

`ssh-tls-proxy` is the SSH-specific command: the same probe, without the TLS-tunnel
flags. It reads the SSH client on stdin and writes the server back on stdout, which
is what ssh's `ProxyCommand` expects.

```bash
ssh -o ProxyCommand='ssh-tls-proxy --ssh-port %p %h:443' example.com

# stunnel-style: SSH clients connect to a local port instead of stdin/stdout
ssh-tls-proxy --listen localhost:2222 example.com:443
```

Build it from source:

```bash
go build -o ./dist/ssh-tls-proxy ./cmd/ssh-tls-proxy/
```

Exit codes match sclient's: 0 done, 1 failure (including no usable server, after
naming every candidate and why it lost), 2 usage.

# API

See [Go Docs](https://pkg.go.dev/github.com/therootcompany/sclient).

# Build from source

You'll need to install [Go](https://golang.org). See
[webinstall.dev/golang](https://webinstall.dev/golang) for install instructions.

```bash
curl -sS https://webinstall.dev/golang | bash
```

Then you can install and run as per usual.

```bash
git clone https://github.com/therootcompany/sclient.git

pushd sclient
  go build -o ./dist/sclient ./cmd/sclient/
  sudo rsync -av dist/sclient /usr/local/bin/sclient
popd

sclient example.com:443 localhost:3000
```

## Install or Run with Go

```bash
go get github.com/therootcompany/sclient/cmd/sclient
go run github.com/therootcompany/sclient/cmd/sclient example.com:443 localhost:3000
```

# Tests

```bash
go build -o bin/sclient ./cmd/sclient
go build -o bin/ssh-tls-proxy ./cmd/ssh-tls-proxy

sh tests/ssh-local-smoke.sh    # SSH mode against loopback banner servers
sh tests/ssh-tls-proxy.sh      # ssh-tls-proxy against the same servers
sh tests/ssh-smoke.sh all      # live SSH-mode probes against the fleet
./tests/smoke.sh example.com   # live smoke test against a real TLS remote
```

The fleet probes read their host lists from the local deployment notes; the
script itself names no host.
