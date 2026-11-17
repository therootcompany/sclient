package sclient

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"net"
	"strconv"
	"testing"
	"time"
)

// halfCloseable stands in for tls.Conn: CloseWrite is EOF to the peer, Close
// is the whole connection.
type halfCloseable struct {
	writeClosed bool
	closed      bool
}

func (h *halfCloseable) Write(b []byte) (int, error) { return len(b), nil }
func (h *halfCloseable) CloseWrite() error           { h.writeClosed = true; return nil }
func (h *halfCloseable) Close() error                { h.closed = true; return nil }

type plainWriter struct {
	closed bool
}

func (p *plainWriter) Write(b []byte) (int, error) { return len(b), nil }
func (p *plainWriter) Close() error                { p.closed = true; return nil }

type brokenReader struct{}

func (brokenReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func (brokenReader) Close() error             { return nil }

// source returns a reader that yields data and then EOF. io.Pipe is unbuffered,
// so the writes have to happen in a goroutine.
func source(data string) (io.ReadCloser, error) {
	r, w := io.Pipe()
	go func() {
		_, err := w.Write([]byte(data))
		_ = w.Close()
		if err != nil {
			panic(err)
		}
	}()
	return r, nil
}

func TestPipeSignalsEOFByClosingTheWriter(t *testing.T) {
	r, err := source("GET / HTTP/1.1\r\nHost: test\r\n\r\n")
	if err != nil {
		t.Fatal(err)
	}
	w := &halfCloseable{}

	if err := pipe(r, w); err != nil {
		t.Fatalf("a clean EOF must not be an error: %v", err)
	}
	if !w.writeClosed {
		t.Error("pipe() must close the writer: io.Copy stops at EOF on the reader and tells the peer nothing")
	}
	if w.closed {
		t.Error("pipe() must half-close a TLS writer, not close it, so the answer can still come back")
	}
}

func TestPipeClosesPlainWriters(t *testing.T) {
	r, err := source("hello")
	if err != nil {
		t.Fatal(err)
	}
	w := &plainWriter{}
	if err := pipe(r, w); err != nil {
		t.Fatal(err)
	}
	if !w.closed {
		t.Error("a writer without CloseWrite must be closed")
	}
}

func TestPipeReportsRealErrors(t *testing.T) {
	if err := pipe(brokenReader{}, &plainWriter{}); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("expected the read error to surface, got %v", err)
	}
}

// testConn is the local side of a stdio session: bytes in, bytes out.
type testConn struct {
	in  io.Reader
	out bytes.Buffer
}

func (c *testConn) Read(b []byte) (int, error)  { return c.in.Read(b) }
func (c *testConn) Write(b []byte) (int, error) { return c.out.Write(b) }
func (c *testConn) Close() error                { return nil }
func (c *testConn) RemoteAddr() net.Addr        { return &stdaddr{net.UnixAddr{Name: "stdin", Net: "stdio"}} }

func testCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, key.Public(), key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// The regression: a piped request ends at EOF. If the local side says nothing,
// the front waits on the keep-alive connection until it times out; if the local
// side closes the connection outright, the front's answer is truncated.
func TestLocalEOFReachesTheFrontWithoutTruncatingTheAnswer(t *testing.T) {
	cert, err := testCert()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	// The front reads until the client half-closes, answers, then hangs up.
	// The read deadline keeps the test from blocking if the EOF never arrives.
	sawEOF := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			sawEOF <- ""
			return
		}
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		req, err := io.ReadAll(c)
		if err != nil {
			sawEOF <- ""
			return
		}
		_, _ = c.Write([]byte("answered\n"))
		_ = c.Close()
		sawEOF <- string(req)
	}()

	tun := &Tunnel{
		RemoteAddress:      "127.0.0.1",
		RemotePort:         port,
		InsecureSkipVerify: true,
		Silent:             true,
	}
	conn := &testConn{in: bytes.NewReader([]byte("GET / HTTP/1.1\r\nHost: test\r\n\r\n"))}

	tun.handleConnection(context.Background(), net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), conn)

	if got := conn.out.String(); got != "answered\n" {
		t.Fatalf("the front's answer was truncated: got %q, want %q", got, "answered\n")
	}
	if got := <-sawEOF; got == "" {
		t.Error("the front never saw EOF: the local side must half-close when its input ends")
	}
}

func TestDialAndListenContextStopsOnCancel(t *testing.T) {
	cert, err := testCert()
	if err != nil {
		t.Fatal(err)
	}
	front, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer front.Close()
	go func() {
		for {
			c, err := front.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	// Reserve a port, release it, and reuse it so we can prove the listener
	// was released when the context was canceled.
	probePort, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probePort.Addr().(*net.TCPAddr).Port
	_ = probePort.Close()

	tun := &Tunnel{
		RemoteAddress: "127.0.0.1",
		RemotePort:    front.Addr().(*net.TCPAddr).Port,
		LocalAddress:  "127.0.0.1",
		LocalPort:     port,
		Silent:        true,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	if err := tun.DialAndListenContext(ctx); err != nil {
		t.Fatalf("a canceled context should stop the tunnel cleanly, got %v", err)
	}

	rebind, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("the listener leaked the port: %v", err)
	}
	_ = rebind.Close()
}

func TestHandshakeClock(t *testing.T) {
	tun := &Tunnel{}
	if got := tun.handshakeClock(80 * time.Millisecond); got != 160*time.Millisecond {
		t.Errorf("auto handshake clock = %v, want twice the connect", got)
	}
	if got := tun.handshakeClock(10 * time.Millisecond); got != minHandshakeClock {
		t.Errorf("a fast connect must still get the %v floor, got %v", minHandshakeClock, got)
	}
	tun.TLSTimeout = 3 * time.Second
	if got := tun.handshakeClock(80 * time.Millisecond); got != 3*time.Second {
		t.Errorf("an explicit timeout must win, got %v", got)
	}
	if got := tun.connectClock(); got != defaultTCPTimeout {
		t.Errorf("connect clock default = %v, want %v", got, defaultTCPTimeout)
	}
	tun.TCPTimeout = 2 * time.Second
	if got := tun.connectClock(); got != 2*time.Second {
		t.Errorf("connect clock = %v, want the operator's 2s", got)
	}
}

func TestDisplayAddr(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"[::1]:3000", "localhost:3000"},
		{"127.0.0.1:3000", "localhost:3000"},
		{"10.0.0.5:3000", "10.0.0.5:3000"},
	}
	for _, c := range cases {
		host, portStr, err := net.SplitHostPort(c.in)
		if err != nil {
			t.Fatal(err)
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			t.Fatal(err)
		}
		if got := displayAddr(&net.TCPAddr{IP: net.ParseIP(host), Port: port}); got != c.want {
			t.Errorf("displayAddr(%s) = %q, want %q", c.in, got, c.want)
		}
	}
}
