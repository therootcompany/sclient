package sclient

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"time"
)

// Tunnel specifies which remote encrypted connection to make available as a plain connection locally.
type Tunnel struct {
	RemoteAddress      string
	RemotePort         int
	LocalAddress       string
	LocalPort          int
	InsecureSkipVerify bool
	NextProtos         []string
	ServerName         string
	// Deprecated: Silent only quiets the progress lines of the deprecated
	// DialAndListen. A command decides its own output.
	Silent     bool
	TCPTimeout time.Duration
	TLSTimeout time.Duration
}

func (t *Tunnel) Remote() string {
	return net.JoinHostPort(t.RemoteAddress, strconv.Itoa(t.RemotePort))
}

func (t *Tunnel) Local() string {
	return net.JoinHostPort(t.LocalAddress, strconv.Itoa(t.LocalPort))
}

// tlsConfig is the client config for one dial. The name defaults to the remote
// address. Go sends no SNI for an IP, but still checks it against the cert.
func (t *Tunnel) tlsConfig() *tls.Config {
	serverName := t.ServerName
	if serverName == "" {
		serverName = t.RemoteAddress
	}
	return &tls.Config{
		ServerName:         serverName,
		NextProtos:         t.NextProtos,
		InsecureSkipVerify: t.InsecureSkipVerify,
	}
}

const (
	defaultTCPDeadline   = 5 * time.Second
	minHandshakeDeadline = 150 * time.Millisecond
	handshakeMultiplier  = 3
)

func (t *Tunnel) handshakeDeadline(connect time.Duration) time.Duration {
	if t.TLSTimeout > 0 {
		return t.TLSTimeout
	}
	return max(handshakeMultiplier*connect, minHandshakeDeadline)
}

// dial connects, then handshakes, each under its own deadline.
func (t *Tunnel) dial(ctx context.Context) (*tls.Conn, error) {
	connect := t.TCPTimeout
	if connect <= 0 {
		connect = defaultTCPDeadline
	}
	ctx, cancel := context.WithTimeout(ctx, connect+t.handshakeDeadline(connect))
	defer cancel()

	start := time.Now()
	conn, err := (&net.Dialer{Timeout: connect}).DialContext(ctx, "tcp", t.Remote())
	if err != nil {
		return nil, err
	}

	handshake, cancelHandshake := context.WithTimeout(ctx, t.handshakeDeadline(time.Since(start)))
	defer cancelHandshake()

	remoteConn := tls.Client(conn, t.tlsConfig())
	if err := remoteConn.HandshakeContext(handshake); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return remoteConn, nil
}

// Deprecated: DialAndListen is the v1.5.1 entry point - the lifecycle in one
// call, progress lines included (quieted by the deprecated Silent field).
func (t *Tunnel) DialAndListen() error {
	return t.dialAndListen(context.Background())
}

// dialAndListen is DialAndListen with a context, so the tests can stop a
// listener that would otherwise run forever.
func (t *Tunnel) dialAndListen(ctx context.Context) error {
	if t.LocalAddress == "-" || t.LocalAddress == "|" {
		local := StdioConn(t.LocalAddress)
		if !t.Silent {
			_, _ = fmt.Fprintf(os.Stderr, "(connected to %s and reading from %s)\n",
				t.Remote(), local.RemoteAddr())
		}
		return t.Serve(ctx, local)
	}

	if err := t.Probe(ctx); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "[warn] '%s' may not be accepting connections: %s\n",
			t.Remote(), err)
	}

	ln, err := t.Listen()
	if err != nil {
		return err
	}
	defer func() { _ = ln.Close() }()

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	if !t.Silent {
		_, _ = fmt.Fprintf(os.Stderr, "[listening] %s <= %s\n", t.Remote(), t.Local())
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("local listener: %w", err)
		}
		go func() {
			if !t.Silent {
				_, _ = fmt.Fprintf(os.Stderr, "[connect] %s => %s\n",
					displayAddr(conn.RemoteAddr()), t.Remote())
			}
			_ = t.Serve(ctx, conn)
		}()
	}
}

// Probe dials the remote once and hangs up. An error means the remote is not
// answering; saying so is the caller's job.
func (t *Tunnel) Probe(ctx context.Context) error {
	conn, err := t.dial(ctx)
	if err != nil {
		return err
	}
	return conn.Close()
}

func (t *Tunnel) Listen() (net.Listener, error) {
	return net.Listen("tcp", t.Local())
}

func (t *Tunnel) Serve(ctx context.Context, local net.Conn) error {
	remote, err := t.dial(ctx)
	if err != nil {
		_ = local.Close()
		return fmt.Errorf("remote %s: %w", t.Remote(), err)
	}

	return pipeContext(ctx, local, remote)
}

// StdioConn is stdin and stdout as a local connection, for Serve.
func StdioConn(which string) net.Conn {
	name := "stdin"
	if which == "|" {
		name = "pipe"
	}
	return &stdnet{
		in:   os.Stdin,
		out:  os.Stdout,
		addr: &stdaddr{net.UnixAddr{Name: name, Net: "stdio"}},
	}
}

type stdaddr struct {
	net.UnixAddr
}

type stdnet struct {
	in   *os.File // os.Stdin
	out  *os.File // os.Stdout
	addr *stdaddr
}

func (rw *stdnet) Read(buf []byte) (n int, err error) {
	return rw.in.Read(buf)
}
func (rw *stdnet) Write(buf []byte) (n int, err error) {
	return rw.out.Write(buf)
}
func (rw *stdnet) Close() error {
	return rw.in.Close()
}
func (rw *stdnet) RemoteAddr() net.Addr {
	return rw.addr
}
func (rw *stdnet) LocalAddr() net.Addr {
	return rw.addr
}

// A pipe has no deadlines; the file behind it cannot be timed out.
func (rw *stdnet) SetDeadline(time.Time) error      { return nil }
func (rw *stdnet) SetReadDeadline(time.Time) error  { return nil }
func (rw *stdnet) SetWriteDeadline(time.Time) error { return nil }

// displayAddr prints loopback as localhost.
func displayAddr(addr net.Addr) string {
	host, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return net.JoinHostPort("localhost", port)
	}
	return addr.String()
}

// pipe copies local to remote and remote to local, ending each copy when its
// source is exhausted, then closes both sides.
func pipe(local io.ReadWriteCloser, remote io.ReadWriteCloser) error {
	var (
		wg        sync.WaitGroup
		localErr  error
		remoteErr error
	)

	wg.Go(func() { localErr = pipeToRemote(local, remote) })
	wg.Go(func() { remoteErr = pipeToLocal(remote, local) })
	wg.Wait()

	_ = remote.Close()
	return errors.Join(localErr, remoteErr)
}

// pipeContext is pipe that can be canceled: canceling ctx closes both sides and
// returns the cause, so an open session ends cleanly rather than hanging.
func pipeContext(ctx context.Context, local, remote io.ReadWriteCloser) error {
	done := make(chan struct{})
	var pipeErr error
	go func() {
		defer close(done)
		pipeErr = pipe(local, remote)
	}()

	select {
	case <-done:
		return pipeErr
	case <-ctx.Done():
		_ = local.Close()
		_ = remote.Close()
		<-done
		return ctx.Err()
	}
}

// pipeToRemote copies local to remote, then half-closes the remote so a
// keep-alive server sees EOF without losing its buffered answer.
func pipeToRemote(local io.Reader, remote io.WriteCloser) error {
	_, err := io.Copy(remote, local)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, os.ErrClosed) {
		return err
	}
	if cw, ok := remote.(interface{ CloseWrite() error }); ok {
		if err := cw.CloseWrite(); err != nil && !errors.Is(err, net.ErrClosed) {
			return err
		}
		return nil
	}
	if err := remote.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		return err
	}
	return nil
}

// pipeToLocal copies remote to local, then closes the local side.
func pipeToLocal(remote io.Reader, local io.WriteCloser) error {
	_, err := io.Copy(local, remote)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, os.ErrClosed) {
		return err
	}
	if err := local.Close(); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, os.ErrClosed) {
		return err
	}
	return nil
}
