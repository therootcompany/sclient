package sshtlsproxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// testCert returns a self-signed certificate valid for "127.0.0.1".
func testCert(t *testing.T) tls.Certificate {
	t.Helper()
	cert, err := makeTestCert()
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func makeTestCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// loopbackTLSOK reports whether loopback TLS works here; some EDR/VPN
// filters break it, and the TLS tests skip themselves when it does.
var loopbackTLSOK = probeLoopbackTLS()

// serveTLS drives the handshake to completion on accept: tls.NewListener
// defers it to the first read or write, so an accept loop that just holds
// the connection leaves the peer hanging - indistinguishable from a
// blocked environment.
func serveTLS(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			if tc, ok := c.(*tls.Conn); ok {
				_ = tc.Handshake()
			}
		}(conn)
	}
}

func probeLoopbackTLS() bool {
	cert, err := makeTestCert()
	if err != nil {
		return false
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return false
	}
	defer ln.Close()
	tlsLn := tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}})
	go serveTLS(tlsLn)
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		return false
	}
	tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	_ = tc.SetDeadline(time.Now().Add(2 * time.Second))
	if err := tc.Handshake(); err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// The probe clock is the only cancel inside a dial, so "operation was
// canceled" must read as a timeout with the elapsed time.
func TestDialCandidateClockWording(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 0)
	defer cancel()
	cfg := Config{Host: "192.0.2.1", Timeout: 3 * time.Second}
	c := dialCandidateTCP(ctx, cfg, 22, &net.Dialer{}, noopTransport)
	if c.err == nil {
		t.Fatal("an expired context must not produce a candidate")
	}
	if !strings.Contains(c.err.Error(), "timed out after") {
		t.Errorf("expected a timeout message, got: %v", c.err)
	}
	if strings.Contains(c.err.Error(), "canceled") {
		t.Errorf("a clock timeout should not say canceled: %v", c.err)
	}
}

// A refused port is not a timeout: the real error must survive.
func TestDialCandidateRefusedPort(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	cfg := Config{Host: "127.0.0.1", Timeout: 2 * time.Second}
	c := dialCandidateTCP(ctx, cfg, 1, &net.Dialer{}, noopTransport)
	if c.err == nil {
		t.Fatal("expected a refused-port error")
	}
	if strings.Contains(c.err.Error(), "timed out") {
		t.Errorf("a refused port must not be reported as a Timeout: %v", c.err)
	}
}

// The clock and the caller are different cancels and the report must say
// which. A peer that accepts TCP and never speaks is the deterministic
// stand-in for a blackholed port: the dial is still in flight when either
// cancel fires.
func TestProbeWordingClockVsCaller(t *testing.T) {
	host, portStr, err := net.SplitHostPort(startSilentServer(t))
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}

	probe := func(ctx context.Context, timeout time.Duration) string {
		in, w := io.Pipe()
		defer w.Close()
		go func() { _, _ = w.Write([]byte("SSH-2.0-test-client\r\n")) }()
		var diag strings.Builder
		_ = Probe(ctx, Config{Host: host, SSHPort: port, TLSPort: port, Timeout: timeout}, in, io.Discard, &diag)
		return diag.String()
	}

	diag := probe(t.Context(), 300*time.Millisecond)
	if !strings.Contains(diag, "timed out after") {
		t.Errorf("the clock should read as a timeout: %s", diag)
	}
	if strings.Contains(diag, "canceled") {
		t.Errorf("the clock must not read as a cancellation: %s", diag)
	}

	// cancel inside the grace window, so the caller - not the clock - is the
	// one that ends the dial
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	diag = probe(ctx, 10*time.Second)
	if !strings.Contains(diag, "canceled after") {
		t.Errorf("a caller cancel should read as canceled: %s", diag)
	}
}

// noopTransport satisfies the transport-up callback where grace is untested.
var noopTransport = func(time.Duration) {}

func TestDialCandidatePlain(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	cfg := Config{
		Host:    "127.0.0.1",
		ALPN:    []string{"ssh"},
		Timeout: 2 * time.Second,
	}
	port, _ := splitPort(ln.Addr().String())

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()

	c := dialCandidateTCP(ctx, cfg, port, &net.Dialer{}, noopTransport)
	if c.err != nil {
		t.Fatalf("dialCandidateTCP: %v", c.err)
	}
	if c.conn == nil {
		t.Fatal("no conn")
	}
	_ = c.conn.Close()

	// Refused port.
	c = dialCandidateTCP(ctx, cfg, 1, &net.Dialer{}, noopTransport)
	if c.err == nil {
		t.Fatal("expected dial error on refused port")
	}
}

func TestDialCandidateTLS(t *testing.T) {
	if !loopbackTLSOK {
		t.Skip("loopback TLS broken in this environment (see probeLoopbackTLS)")
	}
	cert := testCert(t)
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsLn := tls.NewListener(inner, &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"ssh"},
	})
	defer tlsLn.Close()
	go serveTLS(tlsLn)

	host, portStr, err := net.SplitHostPort(inner.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		Host:    host,
		ALPN:    []string{"ssh"},
		Timeout: 2 * time.Second,
	}
	insecure := &tls.Config{InsecureSkipVerify: true, NextProtos: cfg.ALPN}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()

	// insecure: handshake + alpn ok
	c := dialCandidateTLS(ctx, cfg, port, &net.Dialer{}, insecure, noopTransport)
	if c.err != nil {
		t.Fatalf("dialCandidateTLS: %v", c.err)
	}
	_ = c.conn.Close()

	// verified: cert is self-signed, must fail
	c = dialCandidateTLS(ctx, cfg, port, &net.Dialer{}, &tls.Config{NextProtos: cfg.ALPN}, noopTransport)
	if c.err == nil {
		t.Fatal("expected certificate verification error")
	}

	// Front that completes TLS but advertises no ALPN: the handshake
	// succeeds and the negotiated protocol is empty. The candidate is
	// kept — the banner is still worth sending — and the note is
	// carried for the failure report.
	port2 := serveAt(t, cert, nil)
	c = dialCandidateTLS(ctx, cfg, port2, &net.Dialer{}, insecure, noopTransport)
	if c.err != nil {
		t.Fatalf("a no-ALPN front must not be rejected outright: %v", c.err)
	}
	if c.conn == nil {
		t.Fatal("expected a live connection to the no-ALPN front")
	}
	_ = c.conn.Close()
	if !strings.Contains(c.alpnNote, "required one of [ssh]") {
		t.Errorf("expected an ALPN note, got: %q", c.alpnNote)
	}

	// Front that advertises an ALPN the client never offered: Go's handshake
	// itself fails before the policy check ever sees a protocol. This is the
	// stock crypto/tls case. tlsrouter never does this - it sets NextProtos to
	// the client's own advertised ALPN (tlsrouter.go, GetConfigForClient), so a
	// front with no matching route closes the socket instead and the client sees
	// EOF (the router deliberately suppresses the TLS alert).
	port3 := serveAt(t, cert, []string{"h2"})
	c = dialCandidateTLS(ctx, cfg, port3, &net.Dialer{}, insecure, noopTransport)
	if c.err == nil {
		t.Fatal("expected handshake error when the front offers only h2")
	}
	if !strings.Contains(c.err.Error(), "no application protocol") {
		t.Errorf("expected an ALPN handshake error, got: %v", c.err)
	}
}

// serveAt starts a loopback TLS listener advertising the given ALPN.
func serveAt(t *testing.T, cert tls.Certificate, alpn []string) int {
	t.Helper()
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := tls.NewListener(inner, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: alpn})
	t.Cleanup(func() { _ = inner.Close() })
	go serveTLS(ln)
	_, portStr, err := net.SplitHostPort(inner.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	return port
}

func splitPort(addr string) (int, string) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, ""
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return 0, ""
	}
	return p, host
}

// TestResolvedDefaults pins the engine defaults.
func TestResolvedDefaults(t *testing.T) {
	got, dialer, tlsCfg := Config{Host: "example.com"}.resolved()
	if got.SSHPort != 22 || got.TLSPort != 443 {
		t.Errorf("ports = %d/%d, want 22/443", got.SSHPort, got.TLSPort)
	}
	if got.Timeout != 3*time.Second {
		t.Errorf("timeout = %v, want 3s", got.Timeout)
	}
	if len(got.ALPN) != 1 || got.ALPN[0] != "ssh" {
		t.Errorf("alpn = %v, want [ssh]", got.ALPN)
	}
	if dialer == nil {
		t.Error("nil dialer, want the default")
	}
	if dialer != nil && (dialer.Timeout != 3*time.Second || dialer.KeepAlive != 30*time.Second) {
		t.Errorf("dialer = %+v, want a 3s connect timeout and 30s keep-alive", dialer)
	}
	if tlsCfg == nil {
		t.Fatal("nil tls config, want the default")
	}
	if tlsCfg.ServerName != "example.com" {
		t.Errorf("server name = %q, want the host", tlsCfg.ServerName)
	}
	if len(tlsCfg.NextProtos) != 1 || tlsCfg.NextProtos[0] != "ssh" {
		t.Errorf("next protos = %v, want [ssh]", tlsCfg.NextProtos)
	}
	if tlsCfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("min version = %x, want TLS 1.2", uint16(tlsCfg.MinVersion))
	}

	// An explicitly empty ALPN list is "no ALPN", not "use the default".
	empty, _, _ := Config{ALPN: []string{}}.resolved()
	if len(empty.ALPN) != 0 {
		t.Errorf("explicit empty alpn = %v, want unchanged", empty.ALPN)
	}
}
