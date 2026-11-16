package sclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"
)

// stallTLS accepts TCP but never handshakes, so the deadline must fire.
func stallTLS(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn // held open; no handshake
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String()
}

func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sclient-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// readyTLS serves a real handshake. A TLS listener defers the handshake
// to the first read or write, so the accept loop must complete it
// explicitly or the client never sees a ServerHello.
func readyTLS(t *testing.T) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{selfSigned(t)},
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.(*tls.Conn).Handshake()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String()
}

// The dialer is never bare: Timeout bounds the connect, keep-alive is set.
func TestTunnelDialer(t *testing.T) {
	d := (&Tunnel{Timeout: 2 * time.Second}).dialer()
	if d.Timeout != 2*time.Second || d.KeepAlive != 30*time.Second {
		t.Fatalf("dialer = %+v, want a 2s connect timeout and 30s keep-alive", d)
	}
	d = (&Tunnel{}).dialer()
	if d.Timeout != 0 || d.KeepAlive != 30*time.Second {
		t.Fatalf("zero-timeout dialer = %+v, want no connect limit, 30s keep-alive", d)
	}
}

// One deadline covers connect + handshake: a server that accepts TCP but
// never handshakes fails at the Timeout instead of hanging.
func TestDialTLSStalledHandshake(t *testing.T) {
	remote := stallTLS(t)
	tun := &Tunnel{Timeout: 300 * time.Millisecond, InsecureSkipVerify: true}
	start := time.Now()
	_, err := tun.dialTLS(remote)
	if err == nil {
		t.Fatal("expected an error from a stalled handshake")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want the deadline", err)
	}
	if el := time.Since(start); el < 250*time.Millisecond || el > 2*time.Second {
		t.Fatalf("took %v, want ~300ms", el)
	}
}

// A zero Timeout imposes no deadline.
func TestDialTLSNoTimeout(t *testing.T) {
	remote := stallTLS(t)
	tun := &Tunnel{Timeout: 0, InsecureSkipVerify: true}
	done := make(chan error, 1)
	go func() { _, err := tun.dialTLS(remote); done <- err }()
	select {
	case err := <-done:
		t.Fatalf("returned %v, want it to wait without a deadline", err)
	case <-time.After(200 * time.Millisecond):
		// still waiting: correct for an unlimited tunnel
	}
}

// The deadline is not per-phase: a handshake inside the budget succeeds.
func TestDialTLSReady(t *testing.T) {
	remote := readyTLS(t)
	tun := &Tunnel{Timeout: 2 * time.Second, InsecureSkipVerify: true}
	conn, err := tun.dialTLS(remote)
	if err != nil {
		t.Fatalf("dialTLS: %v", err)
	}
	defer conn.Close()
	if !conn.ConnectionState().HandshakeComplete {
		t.Fatal("handshake not complete")
	}
}
