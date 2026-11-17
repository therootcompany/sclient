package sclient

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/therootcompany/sclient/internal/tunnel"
)

const (
	request = "GET / HTTP/1.1\r\nHost: local\r\n\r\n"
	reply   = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nhello from the server\r\n"
	// A session that never ends is a hung session. The loopback round trip takes
	// about 10ms, so this is a hang detector, not a performance budget.
	noHang = 100 * time.Millisecond
	// How long the tunnel is allowed to take to bind its local listener.
	bindWait  = 2 * time.Millisecond
	bindTries = 50
)

// tlsServer starts a TLS server on 127.0.0.1 that reads a request to EOF before
// answering - the behavior the copy loops have to satisfy. It returns the address,
// a shutdown function, and the number of connections it has accepted.
func tlsServer(t *testing.T) (string, func(), *atomic.Int32) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("tls server: key: %v", err)
	}

	notBefore := time.Now().Add(-time.Hour)
	notAfter := time.Now().Add(time.Hour)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{{127, 0, 0, 1}}, // the remote is an IP
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, key.Public(), key)
	if err != nil {
		t.Fatalf("tls server: certificate: %v", err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	})
	if err != nil {
		t.Fatalf("tls server: listen: %v", err)
	}

	conns := &atomic.Int32{}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conns.Add(1)
			go func() {
				defer conn.Close()
				if _, err := io.ReadAll(conn); err != nil {
					return
				}
				_, _ = conn.Write([]byte(reply))
			}()
		}
	}()

	return ln.Addr().String(), func() { _ = ln.Close() }, conns
}

func remoteOf(t *testing.T) (string, int, func(), *atomic.Int32) {
	t.Helper()

	addr, shutdown, conns := tlsServer(t)
	host, portText, err := net.SplitHostPort(addr)
	if err != nil {
		shutdown()
		t.Fatalf("remote: %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		shutdown()
		t.Fatalf("remote: %v", err)
	}
	return host, port, shutdown, conns
}

// The name defaults to the remote address. Go sends no SNI for an IP.
func TestDialServerName(t *testing.T) {
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
		if got := tun.dial(nil).ServerName; got != c.want {
			t.Errorf("dial(remote %q, servername %q): got %q, want %q",
				c.remote, c.servername, got, c.want)
		}
	}
}

// An IP remote is its own name.
func TestDialIPRemoteNamesItself(t *testing.T) {
	host, port, shutdown, _ := remoteOf(t)
	defer shutdown()

	addr := net.JoinHostPort(host, strconv.Itoa(port))

	_, err := (&Tunnel{RemoteAddress: host, RemotePort: port}).dial(nil).DialTLS(context.Background(), addr, nil, nil)
	if err == nil {
		t.Fatalf("dial %s: the untrusted certificate was accepted", host)
	}
	if strings.Contains(err.Error(), "ServerName or InsecureSkipVerify") {
		t.Errorf("dial %s: the address was not used as the name: %v", host, err)
	}
	if !strings.Contains(err.Error(), "unknown authority") {
		t.Errorf("dial %s: want a chain error, got %v", host, err)
	}

	insecure := &Tunnel{RemoteAddress: host, RemotePort: port, InsecureSkipVerify: true}
	conn, err := insecure.dial(nil).DialTLS(context.Background(), addr, nil, nil)
	if err != nil {
		t.Fatalf("dial -k %s: %v", host, err)
	}
	_ = conn.Close()
}

func TestPipeEndsBothStreams(t *testing.T) {
	addr, shutdown, _ := tlsServer(t)
	defer shutdown()

	remote, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("dial remote: %v", err)
	}
	local := &stubConn{in: bytes.NewBufferString(request), out: &bytes.Buffer{}}

	done := make(chan error, 1)
	go func() { done <- tunnel.Pipe(local, remote) }()

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

	local := localPort(t)

	tun := &Tunnel{
		RemoteAddress:      host,
		RemotePort:         port,
		LocalAddress:       "127.0.0.1",
		LocalPort:          local.Port,
		InsecureSkipVerify: true,
		Silent:             true,
	}

	// The listener stays up for the next connection, so the read deadline is what
	// bounds this test.
	go func() { _ = tun.DialAndListen() }()

	var conn net.Conn
	var err error
	for attempt := 0; attempt < bindTries && conn == nil; attempt++ {
		conn, err = net.Dial("tcp", local.String())
		if err != nil {
			time.Sleep(bindWait)
		}
	}
	if conn == nil {
		t.Fatalf("listener: nothing bound %s", local.String())
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
		t.Errorf("listener: got %q, want %q", got, reply)
	}

	// The pre-flight probe, then the client.
	if count := conns.Load(); count != 2 {
		t.Errorf("listener: the remote saw %d connections, want 2", count)
	}
}

// stdout is the payload. The reply is all that arrives there; the progress lines
// go to stderr, where --stderr can send them.
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

// localPort returns a free TCP port on 127.0.0.1.
func localPort(t *testing.T) *net.TCPAddr {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("local port: %v", err)
	}
	addr := ln.Addr().(*net.TCPAddr)
	_ = ln.Close()
	return addr
}

// Canceling ctx stops the tunnel and frees the port.
func TestDialAndListenContextStops(t *testing.T) {
	host, port, shutdown, _ := remoteOf(t)
	defer shutdown()

	local := localPort(t)
	ctx, cancel := context.WithCancel(context.Background())

	tun := &Tunnel{
		RemoteAddress:      host,
		RemotePort:         port,
		LocalAddress:       "127.0.0.1",
		LocalPort:          local.Port,
		InsecureSkipVerify: true,
		Silent:             true,
	}

	done := make(chan error, 1)
	go func() { done <- tun.DialAndListenContext(ctx) }()

	var conn net.Conn
	var err error
	for attempt := 0; attempt < bindTries && conn == nil; attempt++ {
		conn, err = net.Dial("tcp", local.String())
		if err != nil {
			time.Sleep(bindWait)
		}
	}
	if conn == nil {
		cancel()
		t.Fatalf("listener: nothing bound %s", local.String())
	}
	defer conn.Close()

	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("cancel: %v", err)
		}
	case <-time.After(noHang):
		t.Fatal("cancel: the listener never came down")
	}

	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Error("cancel: the session in flight stayed open")
	}

	rebind, err := net.Listen("tcp", local.String())
	if err != nil {
		t.Errorf("cancel: %s is still bound: %v", local.String(), err)
		return
	}
	_ = rebind.Close()
}

// An already-canceled context returns at once and leaves nothing bound.
func TestDialAndListenContextAlreadyCanceled(t *testing.T) {
	host, port, shutdown, _ := remoteOf(t)
	defer shutdown()

	local := localPort(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	tun := &Tunnel{
		RemoteAddress:      host,
		RemotePort:         port,
		LocalAddress:       "127.0.0.1",
		LocalPort:          local.Port,
		InsecureSkipVerify: true,
		Silent:             true,
	}

	done := make(chan error, 1)
	go func() { done <- tun.DialAndListenContext(ctx) }()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("already canceled: %v", err)
		}
	case <-time.After(noHang):
		t.Fatal("already canceled: it did not return")
	}

	rebind, err := net.Listen("tcp", local.String())
	if err != nil {
		t.Errorf("already canceled: %s is bound: %v", local.String(), err)
		return
	}
	_ = rebind.Close()
}

// "::1:3000" is not an address; the tunnel has to bracket it.
func TestIPv6LocalAddress(t *testing.T) {
	host, port, shutdown, _ := remoteOf(t)
	defer shutdown()

	probe, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback on this host: %v", err)
	}
	portNumber := probe.Addr().(*net.TCPAddr).Port
	_ = probe.Close()
	local := net.JoinHostPort("::1", strconv.Itoa(portNumber))

	diagRead, diagWrite, err := os.Pipe()
	if err != nil {
		t.Fatalf("ipv6: stderr: pipe: %v", err)
	}
	oldErr := os.Stderr
	os.Stderr = diagWrite
	defer func() { os.Stderr = oldErr }()

	tun := &Tunnel{
		RemoteAddress:      host,
		RemotePort:         port,
		LocalAddress:       "::1",
		LocalPort:          portNumber,
		InsecureSkipVerify: true,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- tun.DialAndListenContext(ctx) }()

	var conn net.Conn
	for attempt := 0; attempt < bindTries && conn == nil; attempt++ {
		conn, err = net.Dial("tcp", local)
		if err != nil {
			time.Sleep(bindWait)
		}
	}
	if conn == nil {
		t.Fatalf("ipv6: nothing bound %s", local)
	}
	defer conn.Close()

	if err := <-done; err != nil {
		t.Errorf("ipv6: the listener did not stop on cancel: %v", err)
	}
	_ = diagWrite.Close()

	line, err := io.ReadAll(diagRead)
	if err != nil {
		t.Fatalf("ipv6: stderr: read: %v", err)
	}
	want := fmt.Sprintf("[listening] %s <= %s", net.JoinHostPort(host, strconv.Itoa(port)), local)
	if !strings.Contains(string(line), want) {
		t.Errorf("ipv6: the listening line is %q, want %q", string(line), want)
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
