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
	"strings"
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
	Silent             bool
	TCPTimeout         time.Duration
	TLSTimeout         time.Duration
}

func (t *Tunnel) tlsConfig() *tls.Config {
	serverName := t.ServerName
	if serverName == "" && net.ParseIP(t.RemoteAddress) == nil { // an IP has no name
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
func (t *Tunnel) dial(ctx context.Context, remote string) (*tls.Conn, error) {
	connect := t.TCPTimeout
	if connect <= 0 {
		connect = defaultTCPDeadline
	}
	ctx, cancel := context.WithTimeout(ctx, connect+t.handshakeDeadline(connect))
	defer cancel()

	start := time.Now()
	conn, err := (&net.Dialer{Timeout: connect}).DialContext(ctx, "tcp", remote)
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

// DialAndListen runs the tunnel with a context that is never canceled.
func (t *Tunnel) DialAndListen() error {
	return t.DialAndListenContext(context.Background())
}

// DialAndListenContext connects to the remote address, then listens locally;
// each local connection gets its own remote connection. It runs until the tunnel
// finishes, fails, or ctx is canceled.
//
// Canceling ctx closes the listener, ends every open connection, and returns nil.
func (t *Tunnel) DialAndListenContext(ctx context.Context) error {
	remote := t.RemoteAddress + ":" + strconv.Itoa(t.RemotePort)

	// use stdin/stdout: one connection, one dial
	if t.LocalAddress == "-" || t.LocalAddress == "|" {
		var name string
		network := "stdio"
		if t.LocalAddress == "|" {
			name = "pipe"
		} else {
			name = "stdin"
		}
		stdioConn := &stdnet{os.Stdin, os.Stdout, &stdaddr{net.UnixAddr{Name: name, Net: network}}}
		t.handleConnection(ctx, remote, stdioConn)
		return nil
	}

	// use net.Conn
	// Probe once before binding, so the operator knows early whether the remote is
	// alive; each local connection dials on its own.
	probeConn, err := t.dial(ctx, remote)

	if err != nil {
		fmt.Fprintf(os.Stderr, "[warn] '%s' may not be accepting connections: %s\n", remote, err)
	} else {
		_ = probeConn.Close()
	}

	local := t.LocalAddress + ":" + strconv.Itoa(t.LocalPort)
	ln, err := net.Listen("tcp", local)
	if err != nil {
		return err
	}
	defer func() { _ = ln.Close() }()

	if !t.Silent {
		_, _ = fmt.Fprintf(os.Stderr, "[listening] %s:%d <= %s:%d\n",
			t.RemoteAddress, t.RemotePort, t.LocalAddress, t.LocalPort)
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
		go t.handleConnection(ctx, remote, conn)
	}
}

// I wonder if I can get this to exactly mirror UnixAddr without passing it in
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

// not all of net.Conn, just RWC and RemoteAddr()
type netReadWriteCloser interface {
	io.ReadWriteCloser
	RemoteAddr() net.Addr
}

// pipe relays local <-> remote in both directions, ending each stream when its
// source is exhausted, then hangs up on both.
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

// pipeToRemote copies local to remote, then half-closes the remote so a
// keep-alive server sees EOF without losing its buffered answer.
func pipeToRemote(local io.Reader, remote io.WriteCloser) error {
	_, err := io.Copy(remote, local)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
		return err
	}
	if cw, ok := remote.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return remote.Close()
}

// pipeToLocal copies remote to local, then hangs up on the local side.
func pipeToLocal(remote io.Reader, local io.WriteCloser) error {
	_, err := io.Copy(local, remote)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
		return err
	}
	return local.Close()
}

func (t *Tunnel) handleConnection(ctx context.Context, remote string, conn netReadWriteCloser) {
	remoteConn, err := t.dial(ctx, remote)

	if err != nil {
		fmt.Fprintf(os.Stderr, "[error] (remote) %s\n", err)
		_ = conn.Close()
		return
	}

	if !t.Silent {
		if conn.RemoteAddr().Network() == "stdio" {
			_, _ = fmt.Fprintf(os.Stderr, "(connected to %s:%d and reading from %s)\n",
				t.RemoteAddress, t.RemotePort, conn.RemoteAddr().String())
		} else {
			_, _ = fmt.Fprintf(os.Stderr, "[connect] %s => %s:%d\n",
				strings.Replace(conn.RemoteAddr().String(), "[::1]:", "localhost:", 1), t.RemoteAddress, t.RemotePort)
		}
	}

	// pipe() copies both directions and closes both when either side ends.
	// Canceling ctx closes both early.
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := pipe(conn, remoteConn); err != nil {
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
