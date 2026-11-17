package sclient

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"math/big"
	"net"
	"os"
	"strconv"
	"testing"
	"time"
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
// answering - the behavior the pumps have to satisfy. It returns the address and
// a function to shut the server down.
func tlsServer(t *testing.T) (string, func()) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("tls server: key: %v", err)
	}

	notBefore, notAfter := time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
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

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				if _, err := io.ReadAll(conn); err != nil {
					return
				}
				_, _ = conn.Write([]byte(reply))
			}()
		}
	}()

	return ln.Addr().String(), func() { _ = ln.Close() }
}

func remoteOf(t *testing.T) (string, int, func()) {
	t.Helper()

	addr, shutdown := tlsServer(t)
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
	return host, port, shutdown
}

func TestPipeEndsBothStreams(t *testing.T) {
	addr, shutdown := tlsServer(t)
	defer shutdown()

	remote, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
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
	host, port, shutdown := remoteOf(t)
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
}

func TestDialAndListenListener(t *testing.T) {
	host, port, shutdown := remoteOf(t)
	defer shutdown()

	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("local port: %v", err)
	}
	localAddr := probe.Addr().(*net.TCPAddr)
	_ = probe.Close()

	tun := &Tunnel{
		RemoteAddress:      host,
		RemotePort:         port,
		LocalAddress:       "127.0.0.1",
		LocalPort:          localAddr.Port,
		InsecureSkipVerify: true,
		Silent:             true,
	}

	// The listener stays up for the next connection, so the read deadline is
	// what bounds this test.
	go func() { _ = tun.DialAndListen() }()

	var conn net.Conn
	for attempt := 0; attempt < bindTries && conn == nil; attempt++ {
		conn, err = net.Dial("tcp", localAddr.String())
		if err != nil {
			time.Sleep(bindWait)
		}
	}
	if conn == nil {
		t.Fatalf("listener: nothing bound %s", localAddr.String())
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
}

// stubConn is the local side: stdin in, stdout out.
type stubConn struct {
	in     *bytes.Buffer
	out    *bytes.Buffer
	closed bool
}

func (c *stubConn) Read(b []byte) (int, error)  { return c.in.Read(b) }
func (c *stubConn) Write(b []byte) (int, error) { return c.out.Write(b) }
func (c *stubConn) Close() error                { c.closed = true; return nil }
