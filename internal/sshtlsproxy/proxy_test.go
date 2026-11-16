package sshtlsproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// bannerServer reads the client banner, replies with its own banner (plus
// optional extra bytes in the same write, like OpenSSH's glued KEXINIT),
// then echoes lines until "BYE".
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
				// banner + extra in one write, like a glued KEXINIT
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

// runClient plays the ssh client side of a ProxyCommand: sends its banner,
// talks to whichever server the probe chose, and returns what it saw.
func runClient(t *testing.T, cfg Config, errOut io.Writer) (err error, lines []string) {
	t.Helper()
	// one pipe per direction
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

// TestRunPlainWinsWithoutALPN: the ALPN gate closes a front that terminates
// TLS without an acceptable protocol, so the plain server is the one used.
func TestRunPlainWinsWithoutALPN(t *testing.T) {
	if !loopbackTLSOK {
		t.Skip("loopback TLS broken in this environment (see probeLoopbackTLS)")
	}
	cert := testCert(t)
	tlsAddr := startBannerServer(t, "SSH-2.0-tls-noalpn", "", "", &cert)
	sshAddr := startBannerServer(t, "SSH-2.0-plain-server", "", "", nil)
	_, tlsPort := hostPort(t, tlsAddr)
	_, sshPort := hostPort(t, sshAddr)

	cfg := baseConfig(t, "127.0.0.1", sshPort, tlsPort)
	err, lines := runClient(t, cfg, io.Discard)
	if err != nil {
		t.Fatalf("err = %v; lines: %q", err, lines)
	}
	if len(lines) < 1 || lines[0] != "SSH-2.0-plain-server" {
		t.Errorf("banners = %q, want the plain server's first", lines)
	}
}

// The gate is off when the operator names no protocol: the front is tried
// as usual and its banner wins.
func TestRunNoALPNRequirementStillConnects(t *testing.T) {
	if !loopbackTLSOK {
		t.Skip("loopback TLS broken in this environment (see probeLoopbackTLS)")
	}
	cert := testCert(t)
	tlsAddr := startBannerServer(t, "SSH-2.0-tls-noalpn", "", "", &cert)
	tlsHost, tlsPort := hostPort(t, tlsAddr)

	cfg := baseConfig(t, tlsHost, 1, tlsPort)
	cfg.ALPN = []string{}
	cfg.TLS.NextProtos = nil
	err, lines := runClient(t, cfg, io.Discard)
	if err != nil {
		t.Fatalf("err = %v; lines: %q", err, lines)
	}
	if len(lines) < 1 || lines[0] != "SSH-2.0-tls-noalpn" {
		t.Errorf("banners = %q, want the no-ALPN TLS server's first", lines)
	}
}

// TestRunNoALPNFailureMessage: the gate rejects the front and the plain port
// is refused; the 255 report must say which ALPN the front negotiated.
func TestRunNoALPNFailureMessage(t *testing.T) {
	if !loopbackTLSOK {
		t.Skip("loopback TLS broken in this environment (see probeLoopbackTLS)")
	}
	cert := testCert(t)
	// Handshake completes, no ALPN: the candidate never reaches the banner.
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
	if !strings.Contains(diag.String(), "negotiated ALPN (none), wanted one of [ssh]") {
		t.Errorf("expected the negotiated ALPN in the report, got: %s", diag.String())
	}
}

// TestRunPlainHostMismatch: the plain port answers, but its banner declares a
// host that is not the one asked for. That is the front's own sshd, not the
// tenant: refuse it and say so.
func TestRunPlainHostMismatch(t *testing.T) {
	sshAddr := startBannerServer(t, "SSH-2.0-OpenSSH_9.6 tlsrouter-v0.9.4 host:vms.example.com", "", "", nil)
	_, sshPort := hostPort(t, sshAddr)

	cfg := baseConfig(t, "127.0.0.1", sshPort, 1) // tls side refused
	cfg.ServerName = "guest.example.com"
	var diag strings.Builder
	err, lines := runClient(t, cfg, &diag)
	if !errors.Is(err, ErrNoServer) {
		t.Fatalf("want ErrNoServer, got %v; lines: %q", err, lines)
	}
	if !strings.Contains(diag.String(), `declares vms.example.com, not "guest.example.com"`) {
		t.Errorf("expected the host mismatch in the report, got: %s", diag.String())
	}
	if !strings.Contains(diag.String(), "SSH-2.0-OpenSSH_9.6") {
		t.Errorf("expected the answered banner in the report, got: %s", diag.String())
	}
}

// TestRunPlainHostMatches: one of the declared hosts is the name asked for,
// so the connection is used.
func TestRunPlainHostMatches(t *testing.T) {
	sshAddr := startBannerServer(t, "SSH-2.0-OpenSSH_9.6 tlsrouter-v0.9.4 host:vms.example.com,guest.example.com", "", "", nil)
	_, sshPort := hostPort(t, sshAddr)

	cfg := baseConfig(t, "127.0.0.1", sshPort, 1)
	cfg.ServerName = "guest.example.com"
	err, lines := runClient(t, cfg, io.Discard)
	if err != nil {
		t.Fatalf("err = %v; lines: %q", err, lines)
	}
	if len(lines) < 1 || lines[0] != "SSH-2.0-OpenSSH_9.6 tlsrouter-v0.9.4 host:vms.example.com,guest.example.com" {
		t.Errorf("banners = %q, want the declaring server's", lines)
	}
}

// TestRunTLSHostMismatch: TLS terminates and negotiates ssh, but the sshd on
// the other side of the route declares a different host. Neither candidate
// is the intended server.
func TestRunTLSHostMismatch(t *testing.T) {
	if !loopbackTLSOK {
		t.Skip("loopback TLS broken in this environment (see probeLoopbackTLS)")
	}
	cert := testCert(t)
	tlsAddr := startBannerServer(t, "SSH-2.0-OpenSSH_9.6 tlsrouter-v0.9.4 host:vms.example.com", "", "ssh", &cert)
	_, tlsPort := hostPort(t, tlsAddr)

	cfg := baseConfig(t, "127.0.0.1", 1, tlsPort) // plain side refused
	cfg.ServerName = "guest.example.com"
	var diag strings.Builder
	err, _ := runClient(t, cfg, &diag)
	if !errors.Is(err, ErrNoServer) {
		t.Fatalf("want ErrNoServer, got %v; diag: %s", err, diag.String())
	}
	if !strings.Contains(diag.String(), `declares vms.example.com, not "guest.example.com"`) {
		t.Errorf("expected the host mismatch in the report, got: %s", diag.String())
	}
}

// TestRunPlainWinsWhenTLSBlackholes: 443 accepts TCP but never handshakes,
// so the grace clock closes it. The plain candidate is already ready - it
// must still get its banner exchange. Reusing the spent dial clock for the
// exchange kills the write, so the probe reports nothing usable.
func TestRunPlainWinsWhenTLSBlackholes(t *testing.T) {
	tlsAddr := startSilentServer(t)
	sshAddr := startBannerServer(t, "SSH-2.0-plain-server", "", "", nil)
	_, tlsPort := hostPort(t, tlsAddr)
	_, sshPort := hostPort(t, sshAddr)

	cfg := baseConfig(t, "127.0.0.1", sshPort, tlsPort)
	err, lines := runClient(t, cfg, io.Discard)
	if err != nil {
		t.Fatalf("err = %v; lines: %q", err, lines)
	}
	if len(lines) < 1 || lines[0] != "SSH-2.0-plain-server" {
		t.Errorf("banners = %q, want the plain server's", lines)
	}
}

// The same blackholed front, but the plain sshd declares a host that is not
// the one asked for: the mismatch must be reported, not the write race.
func TestRunBlackholedTLSHostMismatch(t *testing.T) {
	tlsAddr := startSilentServer(t)
	sshAddr := startBannerServer(t, "SSH-2.0-OpenSSH_9.6 tlsrouter-v0.9.4 hostname:router.internal", "", "", nil)
	_, tlsPort := hostPort(t, tlsAddr)
	_, sshPort := hostPort(t, sshAddr)

	cfg := baseConfig(t, "127.0.0.1", sshPort, tlsPort)
	cfg.ServerName = "guest.example.com"
	var diag strings.Builder
	err, _ := runClient(t, cfg, &diag)
	if !errors.Is(err, ErrNoServer) {
		t.Fatalf("want ErrNoServer, got %v; diag: %s", err, diag.String())
	}
	if !strings.Contains(diag.String(), `declares router.internal, not "guest.example.com"`) {
		t.Errorf("expected the host mismatch in the report, got: %s", diag.String())
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

// startSilentServer accepts connections and never answers a banner: a peer
// with transport up but no SSH protocol behind it.
func startSilentServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					if _, err := c.Read(buf); err != nil {
						return
					}
				}
			}(c)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String()
}

// The caller's deadline must bound the whole probe, not just the dials: a
// 1s context against a 10s clock may not run to 10s.
func TestProbeHonorsCallerDeadline(t *testing.T) {
	host, portStr, err := net.SplitHostPort(startSilentServer(t))
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()

	in, inWriter := io.Pipe()
	defer inWriter.Close()
	go func() { _, _ = inWriter.Write([]byte("SSH-2.0-test-client\r\n")) }()

	cfg := baseConfig(t, host, port, port)
	cfg.Timeout = 10 * time.Second

	start := time.Now()
	if err := Probe(ctx, cfg, in, io.Discard, io.Discard); !errors.Is(err, ErrNoServer) {
		t.Fatalf("want ErrNoServer, got %v", err)
	}
	elapsed := time.Since(start)
	t.Logf("probe ran %v against a 10s clock under a 1s context", elapsed.Round(10*time.Millisecond))
	if elapsed > 3*time.Second {
		t.Fatalf("probe ran %v; the caller deadline was ignored", elapsed)
	}
}

// Cancelling the caller's context ends a spliced session; the probe clock
// must not be what bounds it.
func TestSpliceEndsOnCancel(t *testing.T) {
	host, portStr, err := net.SplitHostPort(startBannerServer(t, "SSH-2.0-server", "", "", nil))
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	clientToProxy, proxyIn := net.Pipe()
	proxyOut, proxyToClient := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- Probe(ctx, baseConfig(t, host, port, port), proxyIn, proxyOut, io.Discard) }()

	if _, err := fmt.Fprintf(clientToProxy, "SSH-2.0-test-client\r\n"); err != nil {
		t.Fatal(err)
	}
	clientOut := bufio.NewReader(proxyToClient)
	if _, err := clientOut.ReadString('\n'); err != nil {
		t.Fatalf("client read: %v", err)
	}

	cancel() // the caller ends the session
	if _, err := clientOut.ReadString('\n'); !errors.Is(err, io.EOF) {
		t.Fatalf("want EOF on the client side after cancel, got %v", err)
	}
	_ = clientToProxy.Close() // ssh exits, closing its stdin
	if err := <-done; err != nil {
		t.Fatalf("session ended with %v, want nil", err)
	}
}

// Not automated on purpose: the blackholed-port fast-fail needs a dial that
// never completes, and loopback cannot produce one (closed local ports RST
// immediately, so no transport-up event fires). Verified in the field: a
// dead host with an ALPN-less TLS front fails in ~200ms, not --timeout.
