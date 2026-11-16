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
- [ssh-tls-proxy](#ssh-tls-proxy)
- [sclient --ssh](#sclient---ssh)
- [Build from Source](#build-from-source)

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

- macOS (x64) Apple Silicon
  [coming soon](https://github.com/golang/go/issues/39782)
- Linux (x64, i386, arm64, arm6, arm7)
- Windows 10 (x64, i386)

# Usage

```bash
sclient [flags] <remote> <local>
```

- flags
  - `-s`, `--silent` less verbose logging
  - `-k`, `--insecure` ignore invalid TLS (SSL/HTTPS) certificates
  - `--servername <domain>` spoof SNI (to disable use IP as &lt;remote&gt; and do
    not use this option)
  - `--alpn <protocol-list>`
- remote
  - must have servername (i.e. example.com)
  - port is optional (default is 443)
- local
  - address is optional (default is localhost)
  - must have port (i.e. 3000)

  -alpn string
    	acceptable protocols, ex: 'h2,http/1.1' 'http/1.1' (default) 'ssh' (default "http/1.1")
  -insecure
    	ignore bad TLS/SSL/HTTPS certificates
  -k	alias for --insecure
  -s	alias of --silent
  -servername string
    	specify a servername different from <remote> (to disable SNI use an IP as <remote> and do use this option)
  -silent
    	less verbose output

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

# ssh-tls-proxy

`ssh-tls-proxy` is an [ssh](https://www.openssh.com/) `ProxyCommand` for
hosts that offer SSH over **both** plain TCP (port 22) and TLS-terminated
SSH (port 443, ALPN `ssh`) — e.g. behind a TLS SNI router. It dials both
ports at once, runs the SSH identification-banner exchange against
whichever answer(s) it gets, prefers the TLS-terminated connection, and
splices you onto the winner. You only set `ProxyCommand`:

```bash
Host *
    ProxyCommand ssh-tls-proxy --timeout 3 --alpn ssh --ssh-port %p %h
```

- If the TLS side answers first (or at all, if both do), it wins.
- If only the plain side answers, it is used — the client never notices.
- If neither is usable, the proxy prints which ports failed to its
  stderr and exits 255. Note that since OpenSSH 8.0, when both
  `ControlPath` and a valued `ControlPersist` are set (the common
  `Host *` setup), ssh redirects a ProxyCommand's stderr to /dev/null.
  In that case the proxy detects it and, when the client runs in a
  terminal, also writes the diagnostic to the controlling terminal
  (`/dev/tty`) — still reachable, because the proxy is forked before
  the master detaches into the background. With no terminal at all
  (cron, CI) only ssh's own `Connection closed by UNKNOWN port 65535`
  line shows; the 255 exit status always propagates. Run the proxy
  standalone, or ssh with `-o ControlPath=none` (or `-o
  ControlPersist=no`, or `-v`), for the message on plain stderr.
- **Host keys / which server answers:** behind these routers, 443 (SNI +
  ALPN) and 22 can be served by *different* backends — on a tenant name,
  443 is the intended server while 22 is the router's own ssh. Each
  backend has its own host key, and OpenSSH accepts only one key per
  name, so if the path that wins changes for a name you'll get
  `REMOTE HOST IDENTIFICATION HAS CHANGED` until you re-record the key.
  The proxy cannot tell the backends apart; if the :22 fallback is not
  the server you want for a given name, steer with `--ssh-port` in the
  `ProxyCommand` line.

Flags: `--ssh-port` (default 22), `--tls-port` (default 443), `--alpn`
(default `ssh`), `--timeout` seconds (default 3, one overall budget),
`--servername`, `-k/--insecure`, `-v/--verbose`, `-s/--silent`.
The same values can
come from
`SSHTLSPROXY_*` environment variables when the flag is not set.

```bash
curl -sS https://webinstall.dev/ssh-tls-proxy | bash
```

# sclient --ssh

`sclient --ssh` is the same dual-port probe as `ssh-tls-proxy`, in the
sclient shape: instead of a single TLS connection to `<remote>`, each
connection goes through the `sshtlsproxy` engine — plain port (22) and
TLS port (443, ALPN `ssh`) probed at once, the SSH identification-banner
exchange run against whichever answer(s) arrive, the TLS-terminated
connection preferred, and the winner spliced in.

```bash
# stunnel-style: a local listener for SSH clients
sclient --ssh example.com:443 localhost:3000

# as an ssh ProxyCommand: plain 22 and TLS 443 probed at once
ssh -o ProxyCommand='sclient --ssh --ssh-port %p %n' example.com
```

The local side must be an SSH client: the first line of each connection
must be an `SSH-2.0` banner. `--alpn` defaults to `ssh` in this mode
(`--alpn ''` means "no ALPN requirement"); `--ssh-port` (default 22) is
also available.

Exit codes: 0 done, 1 failure, 2 usage, 255 no usable server. Both
modes accept `host`, `host:port`, or `[ipv6]:port`.

The failure report goes to sclient's stderr — there is no
`/dev/tty` mirror here, because a standalone tool is not an ssh
ProxyCommand with its stderr swallowed.

`--timeout` is seconds until a remote connection is ready to
communicate: the TCP connect and the TLS handshake share one deadline.
Plain mode defaults to 10 (`--timeout 0` means no limit); `--ssh` uses
the engine's probe clock, default 3.

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
git clone https://git.rootprojects.org/root/sclient.go.git

pushd sclient.go
  go build -o dist/sclient cmd/sclient/main.go
  sudo rsync -av dist/sclient /usr/local/bin/sclient
popd

sclient example.com:443 localhost:3000
```

## Install or Run with Go

```bash
go get git.rootprojects.org/root/sclient.go/cmd/sclient
go run git.rootprojects.org/root/sclient.go/cmd/sclient example.com:443 localhost:3000
```

`ssh-tls-proxy` reports its version from the build stamp. goreleaser supplies
`main.version`, `main.commit`, and `main.date`; an ad-hoc build can do the same:

```bash
LDFLAGS="-X main.version=$(git describe --tags --match 'v*' --dirty) -X main.commit=$(git rev-parse --short HEAD) -X main.date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
go build -ldflags "$LDFLAGS" -o dist/ssh-tls-proxy ./cmd/ssh-tls-proxy/
```

A plain `go build` (no ldflags) falls back to the tag and commit hash that Go
embeds itself, so `ssh-tls-proxy -V` is never a placeholder.
