package sclient

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/therootcompany/sclient/internal/ssh"
	"github.com/therootcompany/sclient/internal/tunnel"
)

// ErrNoServer means neither port was usable in SSH mode. Each candidate's
// failure is already reported to the diagnostics destination.
var ErrNoServer = ssh.ErrNoServer

// Tunnel specifies which remote encrypted connection to make available as a plain connection locally.
type Tunnel struct {
	RemoteAddress      string
	RemotePort         int
	LocalAddress       string
	LocalPort          int
	InsecureSkipVerify bool
	NextProtos         []string
	ServerName         string
	Silent             bool
	Verbose            bool
	TCPTimeout         time.Duration
	TLSTimeout         time.Duration
	// SSHPort turns on SSH mode: the plain SSH port probed alongside
	// RemoteAddress:RemotePort. Zero is a plain TLS tunnel.
	SSHPort int
}

// serverName is the name the connection is for: ServerName, or the remote
// address when none is given.
func (t *Tunnel) serverName() string {
	if t.ServerName != "" {
		return t.ServerName
	}
	return t.RemoteAddress
}

// dial is everything one dial needs, with the protocols this attempt offers.
func (t *Tunnel) dial(protos []string) tunnel.Dial {
	return tunnel.Dial{
		ServerName:         t.serverName(),
		NextProtos:         protos,
		InsecureSkipVerify: t.InsecureSkipVerify,
		TCPTimeout:         t.TCPTimeout,
		TLSTimeout:         t.TLSTimeout,
	}
}

// DialAndListen runs the tunnel with a context that is never canceled.
func (t *Tunnel) DialAndListen() error {
	return t.DialAndListenContext(context.Background())
}

// DialAndListenContext connects to the remote address, then listens locally; each
// local connection gets its own remote connection. It runs until the tunnel
// finishes, fails, or ctx is canceled.
//
// Canceling ctx closes the listener, ends every open connection, and returns nil.
func (t *Tunnel) DialAndListenContext(ctx context.Context) error {
	if t.SSHPort > 0 {
		return t.serveSSH(ctx)
	}

	remote := net.JoinHostPort(t.RemoteAddress, strconv.Itoa(t.RemotePort))

	// use stdin/stdout: one connection, one dial
	if t.LocalAddress == "-" || t.LocalAddress == "|" {
		t.handleConnection(ctx, remote, tunnel.StdioConn(t.LocalAddress))
		return nil
	}

	// use net.Conn
	// Probe once before binding, so the operator knows early whether the remote is
	// alive; each local connection dials on its own.
	probeConn, err := t.dial(t.NextProtos).DialTLS(ctx, remote, t.NextProtos, nil)

	if err != nil {
		fmt.Fprintf(os.Stderr, "[warn] '%s' may not be accepting connections: %s\n", remote, err)
	} else {
		_ = probeConn.Close()
	}

	local := net.JoinHostPort(t.LocalAddress, strconv.Itoa(t.LocalPort))
	ln, err := net.Listen("tcp", local)
	if err != nil {
		return err
	}
	defer func() { _ = ln.Close() }()

	if !t.Silent {
		_, _ = fmt.Fprintf(os.Stderr, "[listening] %s <= %s\n", remote, local)
	}

	// Canceling ctx closes the listener, so Accept returns. Connections already
	// running end on the same ctx.
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("local listener: %w", err)
		}
		go func() { t.handleConnection(ctx, remote, conn) }()
	}
}

// serveSSH hands the whole SSH-mode session to the ssh package.
func (t *Tunnel) serveSSH(ctx context.Context) error {
	cfg := ssh.Config{
		Host:               t.RemoteAddress,
		ServerName:         t.ServerName,
		SSHPort:            t.SSHPort,
		TLSPort:            t.RemotePort,
		ALPN:               t.NextProtos,
		TCPTimeout:         t.TCPTimeout,
		TLSTimeout:         t.TLSTimeout,
		InsecureSkipVerify: t.InsecureSkipVerify,
		Verbose:            t.Verbose,
		Silent:             t.Silent,
	}

	if t.LocalAddress == "-" || t.LocalAddress == "|" {
		return ssh.Serve(ctx, cfg, tunnel.StdioConn(t.LocalAddress), os.Stderr)
	}

	local := net.JoinHostPort(t.LocalAddress, strconv.Itoa(t.LocalPort))
	return ssh.Listen(ctx, cfg, local, os.Stderr)
}

// reportConnect says what a dial negotiated, when the operator asked for more than
// the bare "connected" line.
func (t *Tunnel) reportConnect(remote string, conn *tls.Conn, elapsed time.Duration) {
	if !t.Verbose {
		return
	}
	protocol := "(none)"
	if p := conn.ConnectionState().NegotiatedProtocol; p != "" {
		protocol = strconv.Quote(p)
	}
	_, _ = fmt.Fprintf(os.Stderr, "[verbose] %s: tls %s, alpn %s, ready in %s\n",
		remote, conn.RemoteAddr(), protocol, tunnel.ElapsedText(elapsed))
}

func (t *Tunnel) handleConnection(ctx context.Context, remote string, conn net.Conn) {
	local := bufio.NewReaderSize(conn, 32*1024)
	protos := ssh.SniffALPN(t.NextProtos, local, conn)

	start := time.Now()
	remoteConn, err := t.dial(protos).DialTLS(ctx, remote, protos, nil)

	if err != nil {
		fmt.Fprintf(os.Stderr, "[error] (remote) %s\n", err)
		_ = conn.Close()
		return
	}

	t.reportConnect(remote, remoteConn, time.Since(start))

	if !t.Silent {
		if conn.RemoteAddr().Network() == "stdio" {
			_, _ = fmt.Fprintf(os.Stderr, "(connected to %s and reading from %s)\n",
				remote, conn.RemoteAddr().String())
		} else {
			_, _ = fmt.Fprintf(os.Stderr, "[connect] %s => %s\n",
				tunnel.DisplayAddr(conn.RemoteAddr()), remote)
		}
	}

	// Pipe copies both directions and closes both when either side ends. Canceling
	// ctx closes both early.
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := tunnel.Pipe(&tunnel.BufferedConn{R: local, Conn: conn}, remoteConn); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "[copy error] %s\n", err)
		}
	}()

	select {
	case <-done:
	case <-ctx.Done():
		_ = conn.Close()
		_ = remoteConn.Close()
		<-done
	}
}
