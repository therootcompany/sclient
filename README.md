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
- [API](#api)
- [Build from Source](#build-from-source)
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
  - `version`, `-V`, `--version` print the version, the commit, and the build date
  - `help`, `--help` print the usage and exit
  - `-s`, `--silent` less verbose logging
  - `-v`, `--verbose` name every probe candidate, its banner, and why it lost
    (SSH mode); also turns on progress lines for a session on a pipe
  - `-k`, `--insecure` ignore invalid TLS (SSL/HTTPS) certificates
  - `--servername <domain>` spoof SNI (to disable use IP as &lt;remote&gt; and do
    not use this option)
  - `--alpn <protocol-list>` acceptable protocols, ex: `h2,http/1.1` `ssh`
  - `--ssh`, `--ssh-port <n>` SSH mode: probe the plain SSH port alongside the
    TLS port (`--ssh` is shorthand for 22; naming 0 is a usage error, not "off")
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

One name can answer on two transports: plain SSH on 22, and SSH wrapped in TLS on
443 (SNI plus ALPN). `--ssh-port` dials both at the same time and takes the one
that is the SSH server for that name. Trying one port and falling back to the
other would be a weaker tool - the simultaneous probe is the feature.

```bash
sclient --ssh-port 22 example.com:443 localhost:3000
ssh -o ProxyCommand='sclient --ssh-port %p %h:443' example.com
```

- TLS that negotiates the ALPN you asked for is ssh over TLS: use it.
- TLS that handshakes but will not negotiate that ALPN has no ssh route for this
  name - it is closed at the handshake and never sees the banner.
- Otherwise, if the plain port answers with an SSH banner, it is plain ssh.
- Neither answers: one report, spoken by the command, with every candidate that
  lost indented under it:

  ```
  sclient: example.com: no usable server
    tls 443: banner "SSH-2.0-OpenSSH_9.6 host:other.example.net" excludes "example.com"
    ssh 22: timed out after 1.2s
  ```

  A session piped to ssh (`ProxyCommand`) also gets ssh's own closing line, so the
  "Connection closed by UNKNOWN port 65535" ssh prints has a cause:

  ```
  Connection closed by "example.com" ports [22, 443]
  ```

Progress goes where a human is watching: a forwarded port (`localhost:3000`)
prints `[listening]` and a `[connect]` line naming the port that won. A session on
a pipe - ssh's `ProxyCommand` - has its stderr on the user's terminal, so it says
nothing while it works; the failure report is still printed, and `--verbose` turns
the progress lines on.

A server can name itself in the banner comment (RFC 4253 section 4.2), ex
`SSH-2.0-OpenSSH_9.6 host:example.com`. When a banner declares hosts and none of
them is the name being dialled, that candidate is refused. A banner that declares
nothing is accepted - the rule is opt-in per server.

With no SSH mode, the local side is sniffed: an `SSH-` banner in the first bytes
means the client is ssh, so `ssh` is offered as the ALPN. Stdio has no read
deadline, so it is not sniffed - name the protocol with `--ssh-port` or `--alpn`.

# API

A tunnel is `Probe`, `Listen`, and `Serve`: check the remote, bind the local
port, accept, and relay each connection. Those three never print - the caller
owns the output and the exit codes. The deprecated `DialAndListen` writes its
own progress lines to stderr; `Silent` quiets the progress lines.

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
go test ./...                  # unit and integration tests, no network needed
./tests/smoke.sh example.com   # live smoke test against a real TLS remote
./tests/ssh-smoke.sh           # SSH mode against the fleet, banner exchange only
```
