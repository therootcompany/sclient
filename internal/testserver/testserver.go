// Package testserver is the fixture the tests share: a self-signed TLS server on
// loopback that reads a request to EOF before answering.
package testserver

import (
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
	"sync/atomic"
	"testing"
	"time"
)

// Reply is what the server answers once it sees the end of the request.
const Reply = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nhello from the server\r\n"

// FreePort returns a TCP port on 127.0.0.1 that nobody is holding.
func FreePort(t *testing.T) *net.TCPAddr {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	addr := ln.Addr().(*net.TCPAddr)
	_ = ln.Close()
	return addr
}

// Dial connects to a listener, waiting for it to come up.
func Dial(t *testing.T, addr string) (net.Conn, error) {
	t.Helper()

	for range 50 {
		conn, err := net.Dial("tcp", addr)
		if err == nil {
			return conn, nil
		}
		time.Sleep(2 * time.Millisecond)
	}
	return nil, errors.New("nothing bound " + addr)
}

// Blackhole is a TCP listener that never handshakes - the "remote is down"
// fixture.
func Blackhole(t *testing.T) (string, int, func()) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("blackhole: %v", err)
	}
	addr := ln.Addr().(*net.TCPAddr)
	return addr.IP.String(), addr.Port, func() { _ = ln.Close() }
}

// TLS starts the server on a random loopback port. It reads a request to EOF
// before answering - the behavior the relay has to satisfy. It returns the host,
// the port, a shutdown function, and a counter of the connections it accepted.
func TLS(t *testing.T) (string, int, func(), *atomic.Int32) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("tls server: key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
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
				_, _ = conn.Write([]byte(Reply))
			}()
		}
	}()

	host, rawPort, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		_ = ln.Close()
		t.Fatalf("tls server: address: %v", err)
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil {
		_ = ln.Close()
		t.Fatalf("tls server: port: %v", err)
	}

	return host, port, func() { _ = ln.Close() }, conns
}
