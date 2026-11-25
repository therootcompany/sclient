package sclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/therootcompany/sclient/internal/testserver"
)

const (
	request = "GET / HTTP/1.1\r\nHost: local\r\n\r\n"
	reply   = testserver.Reply

	// A session that never ends is a hung session. The loopback round trip takes
	// about 10ms, so this is a hang detector, not a performance budget.
	noHang = 100 * time.Millisecond

	serveWait = 200 * time.Millisecond
)

func remoteOf(t *testing.T) (string, int, func(), *atomic.Int32) {
	return testserver.TLS(t)
}

// The name defaults to the remote address. Go sends no SNI for an IP.
func TestTLSConfigServerName(t *testing.T) {
	cases := []struct {
		remote     string
		servername string
		want       string
	}{
		{"example.com", "", "example.com"}, // the documented default
		{"example.com", "other.example.net", "other.example.net"},
		{"192.0.2.1", "", "192.0.2.1"},              // the IP is the name
		{"192.0.2.1", "example.com", "example.com"}, // unless it is named
		{"2001:db8::1", "", "2001:db8::1"},          // IPv6 too
		{"", "", ""},
	}
	for _, c := range cases {
		tun := &Tunnel{RemoteAddress: c.remote, ServerName: c.servername}
		if got := tun.tlsConfig(nil).ServerName; got != c.want {
			t.Errorf("tlsConfig(remote %q, servername %q): got %q, want %q",
				c.remote, c.servername, got, c.want)
		}
	}
}

func TestRemoteAndLocal(t *testing.T) {
	tun := &Tunnel{
		RemoteAddress: "example.com", RemotePort: 8443,
		LocalAddress: "localhost", LocalPort: 3000,
	}
	if got, want := tun.Remote(), "example.com:8443"; got != want {
		t.Errorf("Remote(): got %q, want %q", got, want)
	}
	if got, want := tun.Local(), "localhost:3000"; got != want {
		t.Errorf("Local(): got %q, want %q", got, want)
	}
}

// An IP remote is its own name.
func TestDialIPRemoteNamesItself(t *testing.T) {
	host, port, shutdown, _ := remoteOf(t)
	defer shutdown()

	tun := &Tunnel{RemoteAddress: host, RemotePort: port}
	conn, err := tun.dial(context.Background(), nil)
	if err == nil {
		_ = conn.Close()
		t.Fatalf("dial %s: the untrusted certificate was accepted", host)
	} else if strings.Contains(err.Error(), "ServerName or InsecureSkipVerify") {
		t.Errorf("dial %s: the address was not used as the name: %v", host, err)
	} else if !strings.Contains(err.Error(), "unknown authority") {
		t.Errorf("dial %s: want a chain error, got %v", host, err)
	}

	insecure := &Tunnel{RemoteAddress: host, RemotePort: port, InsecureSkipVerify: true}
	conn, err = insecure.dial(context.Background(), nil)
	if err != nil {
		t.Fatalf("dial -k %s: %v", host, err)
	}
	_ = conn.Close()
}

func TestProbe(t *testing.T) {
	host, port, shutdown, conns := remoteOf(t)
	defer shutdown()

	local := testserver.FreePort(t)
	tun := &Tunnel{
		RemoteAddress:      host,
		RemotePort:         port,
		LocalAddress:       "127.0.0.1",
		LocalPort:          local.Port,
		InsecureSkipVerify: true,
	}

	if err := tun.Probe(context.Background()); err != nil {
		t.Errorf("Probe: %v", err)
	}

	// A probe is exactly one dial, and it hangs up.
	if count := conns.Load(); count != 1 {
		t.Errorf("Probe: the remote saw %d connections, want 1", count)
	}

	// Probe binds nothing: the local port is still free.
	ln, err := net.Listen("tcp", tun.Local())
	if err != nil {
		t.Errorf("Probe bound the local address: %v", err)
		return
	}
	_ = ln.Close()

	deadHost, deadPort, shutDownDead := testserver.Blackhole(t)
	defer shutDownDead()

	quiet := &Tunnel{RemoteAddress: deadHost, RemotePort: deadPort, InsecureSkipVerify: true, TLSTimeout: 100 * time.Millisecond}
	if err := quiet.Probe(context.Background()); err == nil {
		t.Errorf("Probe: a server that never handshakes answered nil")
	}
}

func TestServeRelaysOneSession(t *testing.T) {
	host, port, shutdown, conns := remoteOf(t)
	defer shutdown()

	local := testserver.FreePort(t)
	tun := &Tunnel{
		RemoteAddress:      host,
		RemotePort:         port,
		LocalAddress:       "127.0.0.1",
		LocalPort:          local.Port,
		InsecureSkipVerify: true,
	}

	ln, err := tun.Listen()
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	if got, want := ln.Addr().String(), tun.Local(); got != want {
		t.Errorf("Listen: bound %s, want %s", got, want)
		_ = ln.Close()
		return
	}

	done := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- fmt.Errorf("accept: %w", err)
			return
		}
		done <- tun.Serve(context.Background(), conn)
	}()

	client, err := net.Dial("tcp", tun.Local())
	if err != nil {
		t.Fatalf("dial local: %v", err)
	}
	defer client.Close()

	_, _ = client.Write([]byte(request))
	if tcp, ok := client.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(serveWait):
		t.Fatal("Serve: the session never ended")
	}

	got, err := io.ReadAll(client)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != reply {
		t.Errorf("Serve: got %q, want %q", string(got), reply)
	}

	// One session, one dial: Serve does not probe.
	if count := conns.Load(); count != 1 {
		t.Errorf("Serve: the remote saw %d connections, want 1", count)
	}
}

func TestServeStopsOnCancel(t *testing.T) {
	host, port, shutdown, _ := remoteOf(t)
	defer shutdown()

	local := testserver.FreePort(t)
	tun := &Tunnel{
		RemoteAddress:      host,
		RemotePort:         port,
		LocalAddress:       "127.0.0.1",
		LocalPort:          local.Port,
		InsecureSkipVerify: true,
	}

	ln, err := tun.Listen()
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// A keep-alive remote never ends the session on its own, so this is the
	// cancellation test: Serve must come back when ctx does.
	done := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- fmt.Errorf("accept: %w", err)
			return
		}
		done <- tun.Serve(ctx, conn)
	}()

	client, err := testserver.Dial(t, tun.Local())
	if err != nil {
		t.Fatalf("dial local: %v", err)
	}
	defer client.Close()

	_, _ = client.Write([]byte(request)) // no CloseWrite: the session stays open

	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("cancel: Serve returned %v, want context canceled", err)
		}
	case <-time.After(noHang):
		t.Fatal("cancel: the session in flight never ended")
	}

	_ = client.SetReadDeadline(time.Now().Add(noHang))
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Error("cancel: the client side stayed open")
	}
}

// A stdio session canceled by the context ends on the deadline, not on the
// closed files: stdin and stdout are closed by the hang-up, and that is not an
// error.
func TestServeStdioCancel(t *testing.T) {
	_, port, shutdown, _ := remoteOf(t)
	defer shutdown()

	inRead, inWrite, err := os.Pipe()
	if err != nil {
		t.Fatalf("stdio: pipe: %v", err)
	}
	outRead, outWrite, err := os.Pipe()
	if err != nil {
		t.Fatalf("stdio: pipe: %v", err)
	}

	oldIn, oldOut := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = inRead, outWrite
	defer func() { os.Stdin, os.Stdout = oldIn, oldOut }()
	defer func() { _ = inWrite.Close(); _ = outWrite.Close(); _ = outRead.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	tun := &Tunnel{
		RemoteAddress:      "127.0.0.1",
		RemotePort:         port,
		InsecureSkipVerify: true,
	}

	err = tun.Serve(ctx, StdioConn("-"))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("stdio cancel: Serve returned %v, want the deadline", err)
	}
}

func TestServeWithCanceledContext(t *testing.T) {
	host, port, shutdown, _ := remoteOf(t)
	defer shutdown()

	local := testserver.FreePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	tun := &Tunnel{
		RemoteAddress:      host,
		RemotePort:         port,
		LocalAddress:       "127.0.0.1",
		LocalPort:          local.Port,
		InsecureSkipVerify: true,
	}

	ln, err := tun.Listen()
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	conn, err := net.Dial("tcp", tun.Local())
	if err != nil {
		t.Fatalf("dial local: %v", err)
	}
	defer conn.Close()

	done := make(chan error, 1)
	go func() { done <- tun.Serve(ctx, conn) }()

	select {
	case err := <-done:
		if err == nil {
			t.Error("Serve: a canceled context served a session")
		}
	case <-time.After(noHang):
		t.Fatal("Serve: a canceled context did not return")
	}
}

func TestPipeEndsBothStreams(t *testing.T) {
	host, port, shutdown, _ := remoteOf(t)
	defer shutdown()

	remote, err := tls.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)),
		&tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("dial remote: %v", err)
	}
	local := &stubConn{in: bytes.NewBufferString(request), out: &bytes.Buffer{}}

	done := make(chan error, 1)
	go func() { done <- pipe(local, remote) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("pipe: %v", err)
		}
	case <-time.After(noHang):
		t.Fatal("pipe: the TLS server never saw the end of the request")
	}

	if got, want := local.out.String(), reply; got != want {
		t.Errorf("pipe: reply truncated: got %q, want %q", got, want)
	}
	if !local.closed {
		t.Error("pipe: the local side was left open")
	}
}

func TestDialAndListenStdio(t *testing.T) {
	host, port, shutdown, conns := remoteOf(t)
	defer shutdown()

	inRead, inWrite, err := os.Pipe()
	if err != nil {
		t.Fatalf("stdio: pipe: %v", err)
	}
	outRead, outWrite, err := os.Pipe()
	if err != nil {
		t.Fatalf("stdio: pipe: %v", err)
	}

	oldIn := os.Stdin
	oldOut := os.Stdout
	os.Stdin = inRead
	os.Stdout = outWrite
	defer func() {
		os.Stdin = oldIn
		os.Stdout = oldOut
	}()

	_, _ = inWrite.Write([]byte(request))
	_ = inWrite.Close()

	tun := &Tunnel{
		RemoteAddress:      host,
		RemotePort:         port,
		LocalAddress:       "-",
		InsecureSkipVerify: true,
		Silent:             true,
	}

	done := make(chan error, 1)
	go func() { done <- tun.DialAndListen() }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("stdio: %v", err)
		}
	case <-time.After(noHang):
		t.Fatal("stdio: the session never ended")
	}

	_ = outWrite.Close()
	got, err := io.ReadAll(outRead)
	if err != nil {
		t.Fatalf("stdio: read: %v", err)
	}
	if string(got) != reply {
		t.Errorf("stdio: got %q, want %q", string(got), reply)
	}

	// stdio has one connection, one dial: no pre-flight probe.
	if count := conns.Load(); count != 1 {
		t.Errorf("stdio: the remote saw %d connections, want 1", count)
	}
}

func TestDialAndListenListener(t *testing.T) {
	host, port, shutdown, conns := remoteOf(t)
	defer shutdown()

	local := testserver.FreePort(t)

	tun := &Tunnel{
		RemoteAddress:      host,
		RemotePort:         port,
		LocalAddress:       "127.0.0.1",
		LocalPort:          local.Port,
		InsecureSkipVerify: true,
		Silent:             true,
	}

	ctx := t.Context()

	// The listener stays up for the next connection, so the read deadline is
	// what bounds this test.
	go func() { _ = tun.dialAndListen(ctx) }()

	conn, err := testserver.Dial(t, tun.Local())
	if err != nil {
		t.Fatalf("listener: %v", err)
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(noHang))
	_, _ = conn.Write([]byte(request))
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}

	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("listener: no reply from %s: %v", host, err)
	}
	if string(got) != reply {
		t.Errorf("listener: got %q, want %q", string(got), reply)
	}

	// The pre-flight probe, then the client.
	if count := conns.Load(); count != 2 {
		t.Errorf("listener: the remote saw %d connections, want 2", count)
	}
}

// The deprecated listener names the local address the operator gave, not the
// address the socket resolved to.
func TestDialAndListenListeningLine(t *testing.T) {
	host, port, shutdown, _ := remoteOf(t)
	defer shutdown()

	local := testserver.FreePort(t)

	diagRead, diagWrite, err := os.Pipe()
	if err != nil {
		t.Fatalf("stderr: pipe: %v", err)
	}
	oldErr := os.Stderr
	os.Stderr = diagWrite
	defer func() {
		os.Stderr = oldErr
		_ = diagWrite.Close()
	}()

	tun := &Tunnel{
		RemoteAddress:      host,
		RemotePort:         port,
		LocalAddress:       "localhost",
		LocalPort:          local.Port,
		InsecureSkipVerify: true,
	}

	done := make(chan error, 1)
	go func() { done <- tun.dialAndListen(t.Context()) }()

	conn, err := testserver.Dial(t, tun.Local())
	if err != nil {
		t.Fatalf("listener: %v", err)
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(noHang))
	_, _ = conn.Write([]byte(request))
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}
	_, _ = io.ReadAll(conn)

	_ = diagWrite.Close()
	diagnostics, err := io.ReadAll(diagRead)
	if err != nil {
		t.Fatalf("stderr: read: %v", err)
	}

	want := fmt.Sprintf("[listening] %s <= localhost:%d", tun.Remote(), local.Port)
	if !strings.Contains(string(diagnostics), want) {
		t.Errorf("listening line: got %q, want %q", string(diagnostics), want)
	}
}

// stdout is the payload. The reply is all that arrives there; the deprecated
// path puts its progress lines on stderr.
func TestStdioKeepsDiagnosticsOffThePayload(t *testing.T) {
	host, port, shutdown, _ := remoteOf(t)
	defer shutdown()

	inRead, inWrite, err := os.Pipe()
	if err != nil {
		t.Fatalf("stdio: pipe: %v", err)
	}
	payloadRead, payloadWrite, err := os.Pipe()
	if err != nil {
		t.Fatalf("stdio: pipe: %v", err)
	}
	diagRead, diagWrite, err := os.Pipe()
	if err != nil {
		t.Fatalf("stderr: pipe: %v", err)
	}

	oldIn := os.Stdin
	oldOut := os.Stdout
	oldErr := os.Stderr
	os.Stdin = inRead
	os.Stdout = payloadWrite
	os.Stderr = diagWrite
	defer func() {
		os.Stdin = oldIn
		os.Stdout = oldOut
		os.Stderr = oldErr
	}()

	tun := &Tunnel{
		RemoteAddress:      host,
		RemotePort:         port,
		LocalAddress:       "-",
		InsecureSkipVerify: true,
	}

	done := make(chan error, 1)
	go func() { done <- tun.DialAndListen() }()

	_, _ = inWrite.Write([]byte(request))
	_ = inWrite.Close()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("stdio: %v", err)
		}
	case <-time.After(noHang):
		t.Fatal("stdio: the session never ended")
	}

	_ = payloadWrite.Close()
	payload, err := io.ReadAll(payloadRead)
	if err != nil {
		t.Fatalf("stdio: read payload: %v", err)
	}
	if string(payload) != reply {
		t.Errorf("stdio: the payload was polluted: got %q, want %q", string(payload), reply)
	}

	_ = diagWrite.Close()
	diagnostics, err := io.ReadAll(diagRead)
	if err != nil {
		t.Fatalf("stdio: read diagnostics: %v", err)
	}
	if !strings.Contains(string(diagnostics), "(connected to") {
		t.Errorf("stdio: the connect line is not on stderr: got %q", string(diagnostics))
	}
}

// "::1:3000" is not an address; the tunnel has to bracket it.
func TestIPv6LocalAddress(t *testing.T) {
	host, port, shutdown, _ := remoteOf(t)
	defer shutdown()

	probe, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback on this host: %v", err)
	}
	localPort := probe.Addr().(*net.TCPAddr).Port
	_ = probe.Close()
	local := net.JoinHostPort("::1", strconv.Itoa(localPort))

	tun := &Tunnel{
		RemoteAddress:      host,
		RemotePort:         port,
		LocalAddress:       "::1",
		LocalPort:          localPort,
		InsecureSkipVerify: true,
	}

	ln, err := tun.Listen()
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	done := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- fmt.Errorf("accept: %w", err)
			return
		}
		done <- tun.Serve(context.Background(), conn)
	}()

	client, err := testserver.Dial(t, local)
	if err != nil {
		t.Fatalf("ipv6: %v", err)
	}
	defer client.Close()

	_, _ = client.Write([]byte(request))
	if tcp, ok := client.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}

	_ = client.SetReadDeadline(time.Now().Add(serveWait))
	got, err := io.ReadAll(client)
	if err != nil {
		t.Fatalf("ipv6: no reply from %s: %v", host, err)
	}
	if string(got) != reply {
		t.Errorf("ipv6: got %q, want %q", string(got), reply)
	}

	if err := <-done; err != nil {
		t.Errorf("ipv6: Serve: %v", err)
	}
}

// 0 means 3x the connect, floored at 150ms; an explicit timeout wins.
func TestHandshakeDeadline(t *testing.T) {
	cases := []struct {
		tlsTimeout time.Duration
		connect    time.Duration
		want       time.Duration
	}{
		{0, time.Millisecond, minHandshakeDeadline},                   // auto, floored
		{0, 100 * time.Millisecond, 300 * time.Millisecond},           // auto, 3x the connect
		{300 * time.Millisecond, time.Second, 300 * time.Millisecond}, // explicit wins
		{-1, time.Second, 3 * time.Second},                            // nonsense falls back
	}
	for _, c := range cases {
		tun := &Tunnel{TLSTimeout: c.tlsTimeout}
		if got := tun.handshakeDeadline(c.connect); got != c.want {
			t.Errorf("handshakeDeadline(timeout %s, connect %s): got %s, want %s",
				c.tlsTimeout, c.connect, got, c.want)
		}
	}
}

// A server that accepts the connection but never handshakes must time out.
func TestDialHonorsTLSDeadline(t *testing.T) {
	deadHost, deadPort, shutDownDead := testserver.Blackhole(t)
	defer shutDownDead()

	for _, tun := range []*Tunnel{
		{RemoteAddress: deadHost, RemotePort: deadPort, ServerName: "localhost"},                                     // auto: the 150ms floor
		{RemoteAddress: deadHost, RemotePort: deadPort, ServerName: "localhost", TLSTimeout: 100 * time.Millisecond}, // explicit
	} {
		start := time.Now()
		conn, err := tun.dial(context.Background(), nil)
		elapsed := time.Since(start)
		if err == nil {
			_ = conn.Close()
			t.Fatalf("dial(%s): the handshake never timed out", tun.Remote())
		}
		if !errors.Is(err, errHandshakeTimeout) {
			t.Errorf("dial: got %v, want the handshake deadline", err)
		}
		// The handshake deadline fired, not the 5s connect default.
		if elapsed > time.Second {
			t.Errorf("dial: took %s, want well under the %s connect default", elapsed, defaultTCPDeadline)
		}
	}
}

func TestDialHandshakeFailed(t *testing.T) {
	port := testserver.CloseImmediately(t)

	tun := &Tunnel{RemoteAddress: "127.0.0.1", RemotePort: port, InsecureSkipVerify: true}
	_, err := tun.dial(context.Background(), nil)
	if err == nil {
		t.Fatal("dial: the handshake never failed")
	}
	if !errors.Is(err, errHandshakeFailed) {
		t.Errorf("dial: got %v, want the handshake failure", err)
	}
	want := "handshake failed: server closed the connection"
	if got := err.Error(); got != want {
		t.Errorf("dial: got %q, want %q", got, want)
	}
}

func TestDisplayAddr(t *testing.T) {
	cases := []struct {
		addr net.Addr
		want string
	}{
		{&net.TCPAddr{IP: net.IPv6loopback, Port: 3000}, "localhost:3000"},
		{&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 3000}, "localhost:3000"},
		{&net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 3000}, "192.0.2.1:3000"},
	}
	for _, c := range cases {
		if got := displayAddr(c.addr); got != c.want {
			t.Errorf("displayAddr(%s): got %q, want %q", c.addr, got, c.want)
		}
	}
}

type stubConn struct {
	in     *bytes.Buffer
	out    *bytes.Buffer
	closed bool
}

func (c *stubConn) Read(b []byte) (int, error)  { return c.in.Read(b) }
func (c *stubConn) Write(b []byte) (int, error) { return c.out.Write(b) }
func (c *stubConn) Close() error                { c.closed = true; return nil }
