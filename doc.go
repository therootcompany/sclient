/*
Package sclient unwraps TLS.

It makes secure remote connections (such as HTTPS) available locally as plain-text connections -
similar to `stunnel` or `openssl s_client`.

There are a variety of reasons that you might want to do that,
but we created it specifically to be able to upgrade applications with legacy
security protocols - like SSH, OpenVPN, and Postgres - to take
advantage of the features of modern TLS, such as ALPN and SNI
(which makes them routable through almost every type of firewall).

See https://telebit.cloud/sclient for more info.

# Package Basics

In the simplest case you'll just be setting a ServerName and connection info:

	tun := &sclient.Tunnel{
		RemoteAddress: "example.com",
		RemotePort:    443,
		LocalAddress:  "localhost",
		LocalPort:     3000,
	}

	listener, err := tun.Listen()
	if err != nil {
		return err
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go func() { _ = tun.Serve(ctx, conn) }()
	}

Probe dials the remote once and hangs up. Listen binds the local address. Serve
relays one accepted connection; canceling ctx ends the session in flight. The
accept loop, the reporting, and the exit codes belong to the caller. Stdio is
one dial with nothing to bind, so it needs no probe: `StdioConn("-")` is stdin
and stdout as a `net.Conn`.

# Deprecated

`DialAndListen` is the v1.5.1 lifecycle in one call, progress lines on stderr.
`Silent` quiets those lines; it says nothing about what a caller prints.

# Try the CLI

If you'd like to better understand what sclient does, you can try it out with `go run`:

	go get github.com/therootcompany/sclient/cmd/sclient
	go run github.com/therootcompany/sclient/cmd/sclient example.com:443 localhost:3000
	curl http://localhost:3000 -H "Host: example.com"

Pre-built versions for various platforms are also available at
https://telebit.cloud/sclient
*/
package sclient
