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
	Verbose            bool
	// TCPTimeout bounds one TCP connect, DNS included. Zero takes the default.
	TCPTimeout time.Duration
	// TLSTimeout bounds one TLS handshake, measured from the moment the socket
	// connects. Zero - the default - is auto: twice that connect, floored at
	// 150ms. Name it only for a front that issues a certificate on first use.
	TLSTimeout time.Duration
}

// Stdio is the LocalAddress sentinel that means "no local listener": read
// stdin, write stdout.
const Stdio = "-"

// pipeStdio is the undocumented sentinel the 2018 pipe support invented for
// "stdin is not a terminal". It is an alias for Stdio; prefer Stdio.
const pipeStdio = "|"

// stdioNetwork labels the pseudo-connection so the connect line can tell a
// stdio session from a real local client.
const stdioNetwork = "stdio"

// IsStdio reports whether the local side is stdin/stdout rather than a listener.
func IsStdio(addr string) bool {
	return addr == Stdio || addr == pipeStdio
}

// The engine clocks: a connect that is not quick is dead; a handshake gets
// twice the connect that just happened (measured 0.5-1.4x on public fronts).
const (
	defaultTCPTimeout   = 5 * time.Second
	minHandshakeClock   = 150 * time.Millisecond
	handshakeMultiplier = 2
)

// connectClock is the TCP deadline: the operator's clock, or the default.
func (t *Tunnel) connectClock() time.Duration {
	if t.TCPTimeout > 0 {
		return t.TCPTimeout
	}
	return defaultTCPTimeout
}

// handshakeClock bounds one TLS handshake. An explicit --tls-timeout wins;
// zero is auto - twice the connect that just happened, with a floor so a
// sub-millisecond loopback connect does not strangle a real handshake. There
// is no unlimited mode: every dial has a deadline.
func (t *Tunnel) handshakeClock(connect time.Duration) time.Duration {
	if t.TLSTimeout > 0 {
		return t.TLSTimeout
	}
	return max(handshakeMultiplier*connect, minHandshakeClock)
}

// reportConnect says what a dial actually negotiated, when the operator asked
// for more than the bare "connected" line.
func (t *Tunnel) reportConnect(remote string, conn *tls.Conn, elapsed time.Duration) {
	if !t.Verbose {
		return
	}
	protocol := "(none)"
	if p := conn.ConnectionState().NegotiatedProtocol; p != "" {
		protocol = strconv.Quote(p)
	}
	_, _ = fmt.Fprintf(os.Stderr, "[verbose] %s: tls %s, alpn %s, ready in %s\n",
		remote, conn.RemoteAddr(), protocol, elapsed.Round(10*time.Millisecond))
}

// dialTLS connects under the connect clock and handshakes under the handshake
// clock. The returned connection is ready to communicate.
func (t *Tunnel) dialTLS(remote string) (*tls.Conn, error) {
	connect := t.connectClock()
	ctx, cancel := context.WithTimeout(context.Background(), connect+t.handshakeClock(connect))
	defer cancel()
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return nil, fmt.Errorf("remote %q: %w", remote, err)
	}
	d := &net.Dialer{Timeout: connect, KeepAlive: 30 * time.Second}
	start := time.Now()
	conn, err := d.DialContext(ctx, "tcp", remote)
	if err != nil {
		return nil, err
	}
	handshakeCtx, cancelHandshake := context.WithTimeout(ctx, t.handshakeClock(time.Since(start)))
	defer cancelHandshake()
	tc := tls.Client(conn, t.tlsConfig(host))
	if err := tc.HandshakeContext(handshakeCtx); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return tc, nil
}

// tlsConfig builds the client config for one remote. The operator's
// --servername is the name to send as SNI and verify against; when it is
// empty the remote host is used, which is what tls.Dial does when ServerName
// is left unset.
func (t *Tunnel) tlsConfig(host string) *tls.Config {
	serverName := t.ServerName
	if serverName == "" {
		serverName = host
	}
	return &tls.Config{
		ServerName:         serverName,
		NextProtos:         t.NextProtos,
		InsecureSkipVerify: t.InsecureSkipVerify,
	}
}

// DialAndListen will create a test TLS connection to the remote address and then
// begin listening locally. Each local connection will result in a separate remote connection.
func (t *Tunnel) DialAndListen() error {
	remote := net.JoinHostPort(t.RemoteAddress, strconv.Itoa(t.RemotePort))

	// use stdin/stdout: one connection, one dial - no pre-flight probe
	if IsStdio(t.LocalAddress) {
		name := "stdin"
		if t.LocalAddress == pipeStdio {
			name = "pipe"
		}
		conn := &stdnet{
			in:   os.Stdin,
			out:  os.Stdout,
			addr: &stdaddr{net.UnixAddr{Name: name, Net: stdioNetwork}},
		}
		t.handleConnection(remote, conn)
		return nil
	}

	// Probe once before binding, so the operator knows early whether the
	// front is alive; each local connection dials on its own.
	start := time.Now()
	probe, err := t.dialTLS(remote)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "[warn] '%s' may not be accepting connections: %s\n", remote, err)
	} else {
		t.reportConnect(remote, probe, time.Since(start))
		_ = probe.Close()
	}

	// use net.Conn
	local := net.JoinHostPort(t.LocalAddress, strconv.Itoa(t.LocalPort))
	ln, err := net.Listen("tcp", local)
	if err != nil {
		return err
	}
	// The accept loop only exits on an error, so this is the only place the
	// listener is released; without it the port stays bound until the process
	// dies.
	defer ln.Close()

	if !t.Silent {
		_, _ = fmt.Fprintf(os.Stdout, "[listening] %s:%d <= %s:%d\n",
			t.RemoteAddress, t.RemotePort, t.LocalAddress, t.LocalPort)
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			// A failing accept never recovers; report it and stop instead of
			// spinning on the error. main maps it to an exit code.
			return fmt.Errorf("local listener: %w", err)
		}
		go t.handleConnection(remote, conn)
	}
}

// stdaddr gives the stdio pseudo-connection a RemoteAddr that reads as
// "stdin" or "pipe".
type stdaddr struct {
	net.UnixAddr
}

// stdnet wraps the stdin/stdout pair so it behaves like a net.Conn for the
// relay below.
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

// Close ends the input side only: closing stdin gives the local client its
// EOF, which is the session-ending signal. stdout stays open so the remote
// side can still flush its last bytes.
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

// displayAddr renders a local address for humans: any loopback - [::1] or
// 127.0.0.1 alike - reads as localhost.
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

// pipe copies src to dst; io.EOF and a close we initiated end the session,
// they are not errors.
// pipe copies r to w. io.Copy stops when r hits EOF, but the peer only sees the
// end of the stream when w is closed, so pipe closes the writer it is done
// with. A TLS connection is half-closed (close_notify) so whatever the front
// has already buffered can still come back through the open read side.
func pipe(r io.ReadCloser, w io.WriteCloser) error {
	_, err := io.Copy(w, r)

	// Write the EOF. A writer that can half-close keeps its read side open, so
	// the peer's answer still arrives; anything else is closed outright.
	var closeErr error
	if cw, ok := w.(interface{ CloseWrite() error }); ok {
		closeErr = cw.CloseWrite()
	} else {
		closeErr = w.Close()
	}

	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
		return err
	}
	return closeErr
}

func (t *Tunnel) handleConnection(remote string, conn netReadWriteCloser) {
	start := time.Now()
	sclient, err := t.dialTLS(remote)

	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "[error] (remote) %s\n", err)
		_ = conn.Close()
		return
	}
	t.reportConnect(remote, sclient, time.Since(start))

	if !t.Silent {
		if conn.RemoteAddr().Network() == stdioNetwork {
			_, _ = fmt.Fprintf(os.Stdout, "(connected to %s:%d and reading from %s)\n",
				t.RemoteAddress, t.RemotePort, conn.RemoteAddr().String())
		} else {
			_, _ = fmt.Fprintf(os.Stdout, "[connect] %s => %s:%d\n",
				displayAddr(conn.RemoteAddr()), t.RemoteAddress, t.RemotePort)
		}
	}

	// Two pumps. Each pump's source hitting EOF must be echoed to its
	// destination as a real end-of-stream: a keep-alive front otherwise sits on
	// an open connection until it times out (33s on a public front). The TLS
	// side is half-closed, not closed, so whatever the front has already
	// buffered still gets through.
	// local -> remote: when stdin (or the local client) is at EOF the front has
	// to be told, or it waits on the keep-alive connection until it times out.
	go func() {
		if err := pipe(conn, sclient); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "[copy error] (local) %s\n", err)
		}
	}()
	// remote -> local: the front hung up, so hang up on the local side.
	if err := pipe(sclient, conn); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "[copy error] (remote) %s\n", err)
	}
	_ = sclient.Close()
}
