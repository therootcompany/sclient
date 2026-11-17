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
	"strconv"
	"testing"
	"time"
)

// testConn is the local side of a stdio session: bytes in, bytes out.
type testConn struct {
	in     io.Reader
	out    bytes.Buffer
	closed bool
}

func (c *testConn) Read(b []byte) (int, error)  { return c.in.Read(b) }
func (c *testConn) Write(b []byte) (int, error) { return c.out.Write(b) }
func (c *testConn) Close() error                { c.closed = true; return nil }
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
// the remote waits on the keep-alive connection until it times out; if the local
// side closes the connection outright, the remote's answer is truncated.
func TestLocalEOFReachesTheRemoteWithoutTruncatingTheAnswer(t *testing.T) {
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

	// The remote reads until the client half-closes, answers, then hangs up. The
	// read deadline keeps the test from blocking if the EOF never arrives.
	sawEOF := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			sawEOF <- ""
			return
		}
		_ = c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		req, err := io.ReadAll(c)
		if err != nil {
			sawEOF <- ""
		} else {
			sawEOF <- string(req)
		}
		_, _ = c.Write([]byte("answered\n"))
		_ = c.Close()
	}()

	tun := &Tunnel{
		RemoteAddress:      "127.0.0.1",
		RemotePort:         port,
		InsecureSkipVerify: true,
		Silent:             true,
	}
	conn := &testConn{in: bytes.NewReader([]byte("GET / HTTP/1.1\r\nHost: test\r\n\r\n"))}

	tun.handleConnection(net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), conn)

	if got := conn.out.String(); got != "answered\n" {
		t.Fatalf("the remote's answer was truncated: got %q, want %q", got, "answered\n")
	}
	if got := <-sawEOF; got == "" {
		t.Error("the remote never saw EOF: the local side must half-close when its input ends")
	}
	if !conn.closed {
		t.Error("the local side must be closed when the remote hangs up")
	}
}
