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
  - -s, --silent less verbose logging
  - -k, --insecure ignore invalid TLS (SSL/HTTPS) certificates
  - --servername <string> spoof SNI (to disable use IP as &lt;remote&gt; and do
    not use this option)
- remote
  - must have servername (i.e. example.com)
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
