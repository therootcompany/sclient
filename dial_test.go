package sclient

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"sync/atomic"
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

// sniTLS serves a real handshake and records the SNI the client sent.
func sniTLS(t *testing.T) (string, *atomic.Value) {
	t.Helper()
	cert := selfSigned(t)
	seen := new(atomic.Value)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		GetCertificate: func(ch *tls.ClientHelloInfo) (*tls.Certificate, error) {
			seen.Store(ch.ServerName)
			return &cert, nil
		},
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
	return ln.Addr().String(), seen
}

// The handshake clock stands on its own: a server that accepts TCP but never
// handshakes fails on the handshake clock instead of hanging.
func TestDialTLSStalledHandshake(t *testing.T) {
	remote := stallTLS(t)
	tun := &Tunnel{TLSTimeout: 300 * time.Millisecond, InsecureSkipVerify: true}
	start := time.Now()
	_, err := tun.dialTLS(remote, tun.NextProtos)
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

// The name to verify is the operator's --servername, not the remote
// address: it is the SNI on the wire and the name the certificate is
// checked against.
func TestDialTLSServerName(t *testing.T) {
	remote, seen := sniTLS(t)
	tun := &Tunnel{TLSTimeout: 2 * time.Second, ServerName: "alt.example", InsecureSkipVerify: true}
	conn, err := tun.dialTLS(remote, tun.NextProtos)
	if err != nil {
		t.Fatalf("dialTLS: %v", err)
	}
	_ = conn.Close()
	if got, _ := seen.Load().(string); got != "alt.example" {
		t.Fatalf("SNI = %q, want the Tunnel.ServerName", got)
	}
}

// An unset --servername takes the remote host. tls.Dial did this implicitly;
// the bounded dial has to do it explicitly or the handshake has no name.
func TestTunnelTLSConfigServerName(t *testing.T) {
	if got := (&Tunnel{ServerName: "alt.example"}).tlsConfig("127.0.0.1", nil).ServerName; got != "alt.example" {
		t.Fatalf("ServerName = %q, want the operator's name", got)
	}
	if got := (&Tunnel{}).tlsConfig("example.com", nil).ServerName; got != "example.com" {
		t.Fatalf("ServerName = %q, want the remote host", got)
	}
}

// An empty ServerName is taken from the remote address: plain mode must
// verify the certificate, not fail on an incomplete config.
func TestDialTLSDefaultsServerName(t *testing.T) {
	remote := readyTLS(t)
	tun := &Tunnel{TLSTimeout: 2 * time.Second} // no ServerName, no InsecureSkipVerify
	_, err := tun.dialTLS(remote, tun.NextProtos)
	if err == nil {
		t.Fatal("a self-signed certificate must fail verification")
	}
	if strings.Contains(err.Error(), "ServerName or InsecureSkipVerify") {
		t.Fatalf("ServerName was not taken from the remote: %v", err)
	}
	if !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("err = %v, want a certificate error", err)
	}
}

// The clocks resolve to defaults when nothing is named, and the ceiling is the
// sum of the two - there is no unlimited mode and no separate ceiling.
func TestTunnelTimeouts(t *testing.T) {
	cases := []struct {
		name string
		tun  Tunnel
		want [3]time.Duration // connect, handshake, ceiling
	}{
		{"nothing named takes the defaults", Tunnel{}, [3]time.Duration{5 * time.Second, 45 * time.Second, 50 * time.Second}},
		{"a named connect clock moves the ceiling too", Tunnel{TCPTimeout: 2 * time.Second}, [3]time.Duration{2 * time.Second, 45 * time.Second, 47 * time.Second}},
		{"a named handshake clock moves the ceiling too", Tunnel{TLSTimeout: 2 * time.Second}, [3]time.Duration{5 * time.Second, 2 * time.Second, 7 * time.Second}},
		{"both clocks named add up", Tunnel{TCPTimeout: 2 * time.Second, TLSTimeout: 3 * time.Second}, [3]time.Duration{2 * time.Second, 3 * time.Second, 5 * time.Second}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			connect, handshake, ceiling := tc.tun.timeouts()
			if connect != tc.want[0] || handshake != tc.want[1] || ceiling != tc.want[2] {
				t.Fatalf("timeouts() = %v/%v/%v, want %v/%v/%v", connect, handshake, ceiling, tc.want[0], tc.want[1], tc.want[2])
			}
		})
	}
}

// Zero clocks are not "forever": every dial has a known limit, and the
// handshake runs on its own clock inside the ceiling.
func TestDialTLSUnnamedClocksAreBounded(t *testing.T) {
	remote := stallTLS(t)
	tun := &Tunnel{TCPTimeout: 300 * time.Millisecond, TLSTimeout: 300 * time.Millisecond, InsecureSkipVerify: true}
	start := time.Now()
	_, err := tun.dialTLS(remote, tun.NextProtos)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("a stalled handshake must fail, not hang")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want the deadline", err)
	}
	if elapsed < 300*time.Millisecond || elapsed > 2*time.Second {
		t.Fatalf("took %v, want the 300ms handshake clock", elapsed)
	}
}

// The deadline is not per-phase: a handshake inside the budget succeeds.
func TestDialTLSReady(t *testing.T) {
	remote := readyTLS(t)
	tun := &Tunnel{TLSTimeout: 2 * time.Second, InsecureSkipVerify: true}
	conn, err := tun.dialTLS(remote, tun.NextProtos)
	if err != nil {
		t.Fatalf("dialTLS: %v", err)
	}
	defer conn.Close()
	if !conn.ConnectionState().HandshakeComplete {
		t.Fatal("handshake not complete")
	}
}

// localPipe is one end of a net.Pipe as the tunnel sees it: the peer writes
// the payload and closes, so a silent client is a clean EOF, not a hang.
func localPipe(t *testing.T, payload string) netReadWriteCloser {
	t.Helper()
	client, peer := net.Pipe()
	go func() {
		_, _ = peer.Write([]byte(payload))
		_ = peer.Close()
	}()
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// Plain mode offers no ALPN by default; an SSH client on the local side says
// "ssh" for itself. A flag always wins - explicit, empty included.
func TestAlpnFor(t *testing.T) {
	cases := []struct {
		name   string
		next   []string
		client string
		want   []string
	}{
		{"SSH client offers ssh", nil, "SSH-2.0-OpenSSH_9.6\r\n", []string{"ssh"}},
		{"a legacy banner is still SSH", nil, "SSH-1.99-mod_ssh\r\n", []string{"ssh"}},
		{"HTTP is not SSH", nil, "GET / HTTP/1.1\r\n", nil},
		{"nothing is not SSH", nil, "", nil},
		{"the flag wins over the sniff", []string{"http/1.1"}, "SSH-2.0-OpenSSH_9.6\r\n", []string{"http/1.1"}},
		{"explicit empty offers nothing", []string{}, "SSH-2.0-OpenSSH_9.6\r\n", nil},
		{"a given list survives a non-SSH client", []string{"ssh"}, "GET / HTTP/1.1\r\n", []string{"ssh"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tun := &Tunnel{NextProtos: tc.next}
			conn := localPipe(t, tc.client)
			client := bufio.NewReader(conn)
			got := tun.alpnFor(client, conn)
			if !slices.Equal(got, tc.want) {
				t.Fatalf("alpnFor = %v, want %v", got, tc.want)
			}
			rest, err := io.ReadAll(client)
			if err != nil {
				t.Fatalf("relay read: %v", err)
			}
			if string(rest) != tc.client {
				t.Fatalf("the sniff ate the banner: %q", rest)
			}
		})
	}
}

// echoTLS records the ALPN the client advertised, echoes the first line, and
// closes.
func echoTLS(t *testing.T, offered *atomic.Value) string {
	t.Helper()
	cert := selfSigned(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		// GetConfigForClient runs for every ClientHello, SNI or not, which is
		// what makes the advertised ALPN list observable here.
		GetConfigForClient: func(ch *tls.ClientHelloInfo) (*tls.Config, error) {
			offered.Store(ch.SupportedProtos)
			return nil, nil
		},
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
			tc := c.(*tls.Conn)
			if err := tc.Handshake(); err != nil {
				_ = tc.Close()
				continue
			}
			line, _, err := bufio.NewReader(tc).ReadLine()
			if err == nil {
				_, _ = tc.Write(append(line, '\r', '\n'))
			}
			_ = tc.Close()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String()
}

// End to end: an SSH banner on the local side reaches the wire as the "ssh"
// ALPN, and the banner itself is still relayed.
func TestHandleConnectionSniffsSSH(t *testing.T) {
	cases := []struct {
		client string
		want   []string
	}{
		{"SSH-2.0-OpenSSH_9.6\r\n", []string{"ssh"}},
		{"GET / HTTP/1.1\r\n", nil},
	}
	for _, tc := range cases {
		offered := new(atomic.Value)
		remote := echoTLS(t, offered)
		client, peer := net.Pipe()
		t.Cleanup(func() { _ = client.Close(); _ = peer.Close() })
		go func() { _, _ = peer.Write([]byte(tc.client)) }()

		tun := &Tunnel{TLSTimeout: 2 * time.Second, InsecureSkipVerify: true}
		done := make(chan struct{})
		go func() { tun.handleConnection(remote, client); close(done) }()

		buf := make([]byte, 64)
		n, err := peer.Read(buf)
		if err != nil {
			t.Fatalf("read echo: %v", err)
		}
		if !bytes.HasPrefix(buf[:n], []byte("SSH-")) && !bytes.HasPrefix(buf[:n], []byte("GET ")) {
			t.Fatalf("echo = %q, want the client's banner relayed", buf[:n])
		}
		got, _ := offered.Load().([]string)
		if !slices.Equal(got, tc.want) {
			t.Fatalf("advertised ALPN = %v, want %v", got, tc.want)
		}
		_ = peer.Close() // the local side is done, so the session ends
		<-done
	}
}

// Verbose says what the dial negotiated; silent mode says nothing.
func TestReportConnectVerbose(t *testing.T) {
	remote := readyTLS(t)
	tun := &Tunnel{TLSTimeout: 2 * time.Second, InsecureSkipVerify: true, Verbose: true}
	conn, err := tun.dialTLS(remote, tun.NextProtos)
	if err != nil {
		t.Fatalf("dialTLS: %v", err)
	}
	defer conn.Close()

	out, err := os.CreateTemp(t.TempDir(), "verbose")
	if err != nil {
		t.Fatal(err)
	}
	restore := os.Stderr
	os.Stderr = out
	defer func() { os.Stderr = restore; _ = out.Close() }()

	tun.reportConnect(remote, conn, 20*time.Millisecond)
	_ = out.Close()
	line, err := os.ReadFile(out.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(line), "[verbose] "+remote) {
		t.Fatalf("verbose line = %q, want the remote named", line)
	}
	if !strings.Contains(string(line), "alpn (none)") {
		t.Fatalf("verbose line = %q, want the negotiated ALPN", line)
	}
}
