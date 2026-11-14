package sshtlsproxy

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// bannerServer accepts connections, reads the client banner, writes its
// own banner (plus optional extra bytes in the same write, as OpenSSH
// glues a KEXINIT to its banner), then echoes lines until "BYE".
func startBannerServer(t *testing.T, banner, extra, alpn string, cert *tls.Certificate) string {
	t.Helper()
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var ln net.Listener = inner
	if cert != nil {
		tlsCfg := &tls.Config{Certificates: []tls.Certificate{*cert}}
		if alpn != "" {
			tlsCfg.NextProtos = []string{alpn}
		}
		ln = tls.NewListener(inner, tlsCfg)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				r := bufio.NewReader(c)
				if _, err := readBanner(r); err != nil {
					return
				}
				// Banner plus extra bytes in one write (as OpenSSH
				// glues a KEXINIT to its banner).
				if extra != "" {
					if _, err := io.WriteString(c, banner+"\r\n"+extra+"\r\n"); err != nil {
						return
					}
				} else if _, err := io.WriteString(c, banner+"\r\n"); err != nil {
					return
				}
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					line = strings.TrimRight(line, "\r\n")
					if line == "BYE" {
						_, _ = io.WriteString(c, "GOODBYE\r\n")
						return
					}
					_, _ = io.WriteString(c, line+"\r\n")
				}
			}(conn)
		}
	}()
	t.Cleanup(func() { _ = inner.Close() })
	// Report the inner address: it is the real (non-TLS) port.
	return inner.Addr().String()
}

// runClient plays the ssh client side of a ProxyCommand: it sends its
// banner, talks to whichever server the probe chose, and returns what it
// saw. errOut is where the probe's diagnostics go. err is Probe's return
// value.
func runClient(t *testing.T, cfg Config, errOut io.Writer) (err error, lines []string) {
	t.Helper()
	// One pipe per direction: client->probe and probe->client.
	c2p, pIn := net.Pipe()
	pOut, p2c := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- Probe(t.Context(), cfg, pIn, pOut, errOut) }()

	if _, err := fmt.Fprintf(c2p, "SSH-2.0-test-client\r\n"); err != nil {
		t.Fatalf("client write: %v", err)
	}
	br := bufio.NewReader(p2c)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return <-done, lines
		}
		line = strings.TrimRight(line, "\r\n")
		lines = append(lines, line)
		switch line {
		case "KEXINIT-S":
			// read-ahead arrived; continue
		case "PING-ECHO":
			if _, err := fmt.Fprintf(c2p, "BYE\r\n"); err != nil {
				t.Fatalf("client write: %v", err)
			}
		case "GOODBYE":
			_ = c2p.Close()
			return <-done, lines
		default:
			if _, err := fmt.Fprintf(c2p, "PING-ECHO\r\n"); err != nil {
				t.Fatalf("client write: %v", err)
			}
		}
	}
}

func hostPort(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatal(err)
	}
	return host, port
}

func baseConfig(t *testing.T, host string, sshPort, tlsPort int) Config {
	t.Helper()
	alpn := []string{"ssh"}
	return Config{
		Host:    host,
		SSHPort: sshPort,
		TLSPort: tlsPort,
		ALPN:    alpn,
		Timeout: 3 * time.Second,
		TLS:     &tls.Config{InsecureSkipVerify: true, NextProtos: alpn},
	}
}

// TestRunPickTLS: both servers answer; the TLS one must win.
func TestRunPickTLS(t *testing.T) {
	if !loopbackTLSOK {
		t.Skip("loopback TLS broken in this environment (see probeLoopbackTLS)")
	}
	cert := testCert(t)
	tlsAddr := startBannerServer(t, "SSH-2.0-tls-server", "KEXINIT-S", "ssh", &cert)
	sshAddr := startBannerServer(t, "SSH-2.0-plain-server", "KEXINIT-P", "", nil)
	tlsHost, tlsPort := hostPort(t, tlsAddr)
	_, sshPort := hostPort(t, sshAddr)

	cfg := baseConfig(t, tlsHost, sshPort, tlsPort)
	err, lines := runClient(t, cfg, io.Discard)
	if err != nil {
		t.Fatalf("err = %v; lines: %q", err, lines)
	}
	if len(lines) < 2 {
		t.Fatalf("client saw too little: %q", lines)
	}
	if lines[0] != "SSH-2.0-tls-server" {
		t.Errorf("first banner = %q, want the TLS server's", lines[0])
	}
	// The KEXINIT glued to the TLS banner must arrive as read-ahead.
	if lines[1] != "KEXINIT-S" {
		t.Errorf("second line = %q, want %q (buffered read-ahead)", lines[1], "KEXINIT-S")
	}
}

// TestRunPickSSHWhenTLSDown: 443-side refused; plain ssh wins.
func TestRunPickSSHWhenTLSDown(t *testing.T) {
	sshAddr := startBannerServer(t, "SSH-2.0-plain-server", "", "", nil)
	sshHost, sshPort := hostPort(t, sshAddr)
	cfg := baseConfig(t, sshHost, sshPort, 1) // port 1: refused
	err, lines := runClient(t, cfg, io.Discard)
	if err != nil {
		t.Fatalf("err = %v; lines: %q", err, lines)
	}
	if len(lines) == 0 || lines[0] != "SSH-2.0-plain-server" {
		t.Errorf("banners = %q, want the plain server's first", lines)
	}
}

// TestRunPickTLSWithoutALPN: the TLS front terminates without the ALPN and
// the plain port answers too. The banner is still sent over the TLS side
// and, when it is answered, that connection wins: behind a tenant front the
// plain port is a different server (the TLS router's own sshd).
func TestRunPickTLSWithoutALPN(t *testing.T) {
	if !loopbackTLSOK {
		t.Skip("loopback TLS broken in this environment (see probeLoopbackTLS)")
	}
	cert := testCert(t)
	tlsAddr := startBannerServer(t, "SSH-2.0-tls-noalpn", "", "", &cert)
	sshAddr := startBannerServer(t, "SSH-2.0-plain-server", "", "", nil)
	tlsHost, tlsPort := hostPort(t, tlsAddr)
	_, sshPort := hostPort(t, sshAddr)

	cfg := baseConfig(t, tlsHost, sshPort, tlsPort)
	err, lines := runClient(t, cfg, io.Discard)
	if err != nil {
		t.Fatalf("err = %v; lines: %q", err, lines)
	}
	if len(lines) < 1 || lines[0] != "SSH-2.0-tls-noalpn" {
		t.Errorf("banners = %q, want the no-ALPN TLS server's first", lines)
	}
}

// TestRunNoALPNFailureMessage: the TLS front terminates without the ALPN and
// never answers the banner; the plain port is refused. Exit 255 and the
// diagnostic must carry the ALPN note, not just the raw read error.
func TestRunNoALPNFailureMessage(t *testing.T) {
	if !loopbackTLSOK {
		t.Skip("loopback TLS broken in this environment (see probeLoopbackTLS)")
	}
	cert := testCert(t)
	// Handshake completes, then the connection closes: no banner.
	tlsPort := serveAt(t, cert, nil)

	cfg := baseConfig(t, "127.0.0.1", 1, tlsPort) // plain side refused
	var diag strings.Builder
	err, _ := runClient(t, cfg, &diag)
	if !errors.Is(err, ErrNoServer) {
		t.Fatalf("want ErrNoServer, got %v; diag: %s", err, diag.String())
	}
	if !strings.Contains(diag.String(), "no usable server") {
		t.Errorf("expected a no-usable-server report, got: %s", diag.String())
	}
	if !strings.Contains(diag.String(), "TLS negotiated ALPN (none), required one of [ssh]") {
		t.Errorf("expected the ALPN note in the report, got: %s", diag.String())
	}
}

// TestRunNoneDown: both refused; exit 255.
func TestRunNoneDown(t *testing.T) {
	cfg := baseConfig(t, "127.0.0.1", 1, 1)
	err, _ := runClient(t, cfg, io.Discard)
	if !errors.Is(err, ErrNoServer) {
		t.Errorf("want ErrNoServer, got %v", err)
	}
}

// Intentionally NOT automated: a timing test for the blackholed-port
// fast-fail (grace arms on transport-up, so a dropped sibling port
// must not hold the probe to the full timeout) needs a dial that
// never completes — loopback cannot produce one, because closed local
// ports RST immediately and no transport-up event fires. Verified in
// the field instead: a dead host whose TLS front lacks the ALPN fails
// in ~200ms rather than --timeout.
