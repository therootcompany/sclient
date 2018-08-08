sclient.go
==========

Secure Client for exposing TLS (aka SSL) secured services as plain-text connections locally.

Also ideal for multiplexing a single port with multiple protocols using SNI.

Unwrap a TLS connection:

```bash
$ sclient whatever.com:443 localhost:3000
> [listening] whatever.com:443 <= localhost:3000
```

Connect via Telnet

```bash
$ telnet localhost 3000
```

Connect via netcat (nc)

```bash
$ nc localhost 3000
```

cURL

```bash
$ curl http://localhost:3000 -H 'Host: whatever.com'
```

A poor man's (or Windows user's) makeshift replacement for `openssl s_client`, `stunnel`, or `socat`.

Install
=======

### Downloads

* [Windows 10](https://telebit.cloud/sclient/dist/windows/amd64/sclient.exe)
* [Mac OS X](https://telebit.cloud/sclient/dist/darwin/amd64/sclient)
* [Linux (x64)](https://telebit.cloud/sclient/dist/linux/amd64/sclient)
* [Raspberry Pi (armv7)](https://telebit.cloud/sclient/dist/linux/armv7/sclient)
* more downloads <https://telebit.cloud/sclient/>

### Build from source

For the moment you'll have to install go and compile `sclient` yourself:

* <https://golang.org/doc/install#install>

```bash
git clone https://git.coolaj86.com/coolaj86/sclient.go.git
pushd sclient.go
go build -o dist/sclient sclient*.go
rsync -av dist/sclient /usr/local/bin/sclient
```

```bash
go run sclient*.go example.com:443 localhost:3000
```

Usage
=====

```bash
sclient [flags] <remote> <local>
```

* flags
  * -k, --insecure ignore invalid TLS (SSL/HTTPS) certificates
* remote
  * must have servername (i.e. example.com)
  * port is optional (default is 443)
* local
  * address is optional (default is localhost)
  * must have port (i.e. 3000)

Examples
========

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
