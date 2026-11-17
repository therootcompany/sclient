package ssh

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/therootcompany/sclient/internal/tunnel"
)

// probeWait bounds a loopback probe: a real one finishes in a couple of hundred
// milliseconds at most.
const probeWait = 150 * time.Millisecond

// sshCert is a self-signed certificate for 127.0.0.1.
func sshCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{{127, 0, 0, 1}},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, key.Public(), key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// silentTLSServer accepts TLS connections and never completes a handshake.
func silentTLSServer(t *testing.T) int {
	t.Helper()

	cert, err := sshCert()
	if err != nil {
		t.Fatal(err)
	}
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	silent := tls.NewListener(inner, &tls.Config{Certificates: []tls.Certificate{cert}})
	go func() {
		for {
			conn, err := silent.Accept()
			if err != nil {
				return
			}
			_ = conn // accepted, never answered
		}
	}()
	t.Cleanup(func() { _ = inner.Close() })

	_, port, err := net.SplitHostPort(inner.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// slowTLSServer answers the banner only after a delay, so the plain port is ready
// first and the TLS handshake is still in flight when the grace period starts.
func slowTLSServer(t *testing.T, banner, alpn string, delay time.Duration) int {
	t.Helper()

	cert, err := sshCert()
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}
	if alpn != "" {
		tlsConfig.NextProtos = []string{alpn}
	}

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
			go func(c net.Conn) {
				defer c.Close()
				time.Sleep(delay)
				tlsConn := tls.Server(c, tlsConfig)
				if err := tlsConn.Handshake(); err != nil {
					return
				}
				r := bufio.NewReader(tlsConn)
				if _, err := readBanner(r); err != nil {
					return
				}
				_, _ = io.WriteString(tlsConn, banner+"\r\n")
				_, _ = r.ReadString('\n')
			}(conn)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })

	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// silentTCPServer accepts connections and never answers.
func silentTCPServer(t *testing.T) int {
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
			_ = conn // connected, never speaks
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })

	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// sshEcho starts a server that answers the banner exchange and echoes lines until
// it sees BYE. alpn is the protocol it offers; "" offers none. extra is written
// with the banner in one write, like OpenSSH's glued KEXINIT.
func sshEcho(t *testing.T, banner, extra, alpn string, overTLS bool) int {
	t.Helper()

	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	ln := inner
	if overTLS {
		cert, err := sshCert()
		if err != nil {
			t.Fatal(err)
		}
		tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}
		if alpn != "" {
			tlsConfig.NextProtos = []string{alpn}
		}
		ln = tls.NewListener(inner, tlsConfig)
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
				if _, err := io.WriteString(c, banner+"\r\n"+extra+"\r\n"); err != nil {
					return
				}
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					if strings.TrimRight(line, "\r\n") == "BYE" {
						_, _ = io.WriteString(c, "GOODBYE\r\n")
						return
					}
				}
			}(conn)
		}
	}()

	t.Cleanup(func() { _ = inner.Close() })

	_, port, err := net.SplitHostPort(inner.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// loopbackConfig points both probes at localhost with the given ports.
func loopbackConfig(tlsPort, sshPort int) Config {
	return Config{
		Host:               "localhost",
		SSHPort:            sshPort,
		TLSPort:            tlsPort,
		Verbose:            false,
		TCPTimeout:         50 * time.Millisecond,
		InsecureSkipVerify: true,
	}
}

// Both ports answer the banner: the TLS one wins.
func TestProbePrefersTLS(t *testing.T) {
	tlsPort := sshEcho(t, "SSH-2.0-tls-server", "", "ssh", true)
	sshPort := sshEcho(t, "SSH-2.0-plain-server", "", "", false)

	chosen, err := probe(context.Background(), loopbackConfig(tlsPort, sshPort), "SSH-2.0-client", io.Discard)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if chosen.name != "tls" {
		t.Errorf("probe chose %s (%s), want tls", chosen.name, chosen.address)
	}
	if chosen.banner != "SSH-2.0-tls-server" {
		t.Errorf("banner = %q, want the TLS server's", chosen.banner)
	}
}

// A TLS connection that is slow to answer is still the TLS connection: the plain
// port's undeclared banner proves nothing, so the handshake keeps its chance and
// the grace period does not cut it off.
func TestProbeSlowTLSStillWins(t *testing.T) {
	tlsPort := slowTLSServer(t, "SSH-2.0-slow-tls-server", "ssh", 60*time.Millisecond)
	sshPort := sshEcho(t, "SSH-2.0-plain-server", "", "", false)

	chosen, err := probe(context.Background(), loopbackConfig(tlsPort, sshPort), "SSH-2.0-client", io.Discard)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if chosen.name != "tls" {
		t.Errorf("probe chose %s (%s), want tls", chosen.name, chosen.address)
	}
	if chosen.banner != "SSH-2.0-slow-tls-server" {
		t.Errorf("banner = %q, want the slow TLS server's", chosen.banner)
	}
}

// TLS does not answer: the plain SSH port wins.
func TestProbeFallsBackToPlainSSH(t *testing.T) {
	sshPort := sshEcho(t, "SSH-2.0-plain-server", "", "", false)

	chosen, err := probe(context.Background(), loopbackConfig(1, sshPort), "SSH-2.0-client", io.Discard)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if chosen.name != "ssh" {
		t.Errorf("probe chose %s, want ssh", chosen.name)
	}
}

// The ALPN gate: TLS that does not name a protocol we asked for is not routing
// ssh, so the plain port wins.
func TestProbeALPNGate(t *testing.T) {
	tlsPort := sshEcho(t, "SSH-2.0-no-alpn", "", "", true)
	sshPort := sshEcho(t, "SSH-2.0-plain-server", "", "", false)

	cfg := loopbackConfig(tlsPort, sshPort)
	cfg.ALPN = []string{"ssh"}
	cfg.Verbose = true

	var report strings.Builder
	chosen, err := probe(context.Background(), cfg, "SSH-2.0-client", &report)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if chosen.name != "ssh" {
		t.Errorf("probe chose %s, want ssh", chosen.name)
	}
	if !strings.Contains(report.String(), "ALPN") {
		t.Errorf("verbose report should name the ALPN that lost: %q", report.String())
	}
}

// A server that speaks ALPN but not one of ours fails the handshake outright; the
// plain port still wins.
func TestProbeALPNMismatchAbortsTheHandshake(t *testing.T) {
	tlsPort := sshEcho(t, "SSH-2.0-http-only", "", "http/1.1", true)
	sshPort := sshEcho(t, "SSH-2.0-plain-server", "", "", false)

	cfg := loopbackConfig(tlsPort, sshPort)
	cfg.ALPN = []string{"ssh"}

	chosen, err := probe(context.Background(), cfg, "SSH-2.0-client", io.Discard)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if chosen.name != "ssh" {
		t.Errorf("probe chose %s, want ssh", chosen.name)
	}
}

// An explicit empty ALPN list turns the gate off.
func TestProbeALPNGateOff(t *testing.T) {
	tlsPort := sshEcho(t, "SSH-2.0-no-alpn", "", "", true)

	cfg := loopbackConfig(tlsPort, 1)
	cfg.ALPN = []string{}

	chosen, err := probe(context.Background(), cfg, "SSH-2.0-client", io.Discard)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if chosen.name != "tls" {
		t.Errorf("probe chose %s, want tls", chosen.name)
	}
}

// A name that does not resolve is one failure, named once, and no dial is tried.
func TestProbeLooksUpTheHostOnce(t *testing.T) {
	cfg := loopbackConfig(1, 1)
	cfg.Host = "does-not-exist.invalid" // RFC 2606: never resolves

	start := time.Now()
	var report strings.Builder
	_, err := probe(context.Background(), cfg, "SSH-2.0-client", &report)
	elapsed := time.Since(start)

	if !errors.Is(err, ErrNoServer) {
		t.Fatalf("probe: got %v, want ErrNoServer", err)
	}
	if count := strings.Count(report.String(), "no such host"); count != 1 {
		t.Errorf("report = %q, want the lookup named once", report.String())
	}
	if elapsed > 100*time.Millisecond {
		t.Errorf("probe dialled anyway: %s", ElapsedFor(elapsed))
	}
}

// SSH mode does not dial an IP over TLS unless the server is named: a proxy that
// routes by name has nothing to route on an address. Serve is the path callers
// take, so the resolution is tested there.
func TestProbeSkipsTLSForUnnamedIP(t *testing.T) {
	tlsPort := sshEcho(t, "SSH-2.0-tls-server", "", "ssh", true)
	sshPort := sshEcho(t, "SSH-2.0-plain-server", "", "", false)

	cfg := loopbackConfig(tlsPort, sshPort)
	cfg.Host = "127.0.0.1"
	cfg.Verbose = true
	cfg = cfg.resolved()

	var report strings.Builder
	chosen, err := probe(context.Background(), cfg, "SSH-2.0-client", &report)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if chosen.name != "ssh" {
		t.Errorf("probe chose %s, want ssh", chosen.name)
	}
	if !strings.Contains(report.String(), "no name to route on") {
		t.Errorf("report = %q, want the skipped TLS candidate", report.String())
	}
}

// A banner that declares a host other than the one dialled is a different server:
// it is refused, and the report says so. A banner that declares nothing is
// accepted - the rule is opt-in.
func TestProbeBannerMismatch(t *testing.T) {
	tlsPort := sshEcho(t, "SSH-2.0-OpenSSH_9.6 host:other.example.net", "", "ssh", true)

	cfg := loopbackConfig(tlsPort, 1)
	cfg.ServerName = "example.com"
	cfg.Verbose = true

	var report strings.Builder
	_, err := probe(context.Background(), cfg, "SSH-2.0-client", &report)
	if !errors.Is(err, ErrNoServer) {
		t.Fatalf("probe: got %v, want ErrNoServer", err)
	}
	if !strings.Contains(report.String(), "declares other.example.net") {
		t.Errorf("report = %q, want the mismatch", report.String())
	}
}

// The report of a session with no server names the command, then every candidate
// that lost, and ends with ssh's own closing line and the ports that were tried.
func TestProbeReportClosesLikeSSH(t *testing.T) {
	tlsPort := sshEcho(t, "SSH-2.0-OpenSSH_9.6 host:other.example.net", "", "ssh", true)
	sshPort := sshEcho(t, "SSH-2.0-OpenSSH_9.6 host:other.example.net", "", "", false)

	cfg := loopbackConfig(tlsPort, sshPort)
	cfg.Name = "ssh-tls-proxy"
	cfg = cfg.resolved()

	var report strings.Builder
	_, err := probe(context.Background(), cfg, "SSH-2.0-client", &report)
	if !errors.Is(err, ErrNoServer) {
		t.Fatalf("probe: got %v, want ErrNoServer", err)
	}

	lines := strings.Split(strings.TrimRight(report.String(), "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("report = %q, want a header, two candidates and the close line", report.String())
	}
	if lines[0] != "ssh-tls-proxy: localhost: no usable server" {
		t.Errorf("header = %q, want the command named", lines[0])
	}
	for _, line := range lines[1:3] {
		if !strings.HasPrefix(line, "  ") {
			t.Errorf("candidate line %q, want it indented", line)
		}
	}
	want := fmt.Sprintf(`ssh-tls-proxy: Connection closed by "localhost" ports [%d, %d]`, sshPort, tlsPort)
	if lines[3] != want {
		t.Errorf("close line = %q, want %q", lines[3], want)
	}
}

// A candidate refused by the ALPN gate reports the port it lost on and how long
// the handshake took.
func TestProbeALPNFailureNamesThePortAndTheElapsed(t *testing.T) {
	tlsPort := sshEcho(t, "SSH-2.0-no-alpn", "", "", true)

	cfg := loopbackConfig(tlsPort, 1)
	cfg = cfg.resolved()

	var report strings.Builder
	_, err := probe(context.Background(), cfg, "SSH-2.0-client", &report)
	if !errors.Is(err, ErrNoServer) {
		t.Fatalf("probe: got %v, want ErrNoServer", err)
	}

	want := fmt.Sprintf("  tls %d: negotiated ALPN (none) in ", tlsPort)
	if !strings.Contains(report.String(), want) {
		t.Errorf("report = %q, want %q", report.String(), want)
	}
	if strings.Contains(report.String(), "localhost:"+strconv.Itoa(tlsPort)) {
		t.Errorf("report = %q, want the port alone on the candidate line", report.String())
	}
}

// A name that does not resolve is reported before any dial, so the close line has
// no host to name and no port that was tried.
func TestProbeCloseLineWithoutAHost(t *testing.T) {
	cfg := loopbackConfig(1, 1)
	cfg.Host = "does-not-exist.invalid" // RFC 2606: never resolves
	cfg = cfg.resolved()

	var report strings.Builder
	_, err := probe(context.Background(), cfg, "SSH-2.0-client", &report)
	if !errors.Is(err, ErrNoServer) {
		t.Fatalf("probe: got %v, want ErrNoServer", err)
	}

	lines := strings.Split(strings.TrimRight(report.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("report = %q, want the cause and the close line", report.String())
	}
	if lines[0] != "sclient: does-not-exist.invalid: no usable server: no such host" {
		t.Errorf("cause line = %q, want the command, the name and the cause", lines[0])
	}
	want := `sclient: Connection closed by "NO SUCH HOST" port [0]`
	if lines[1] != want {
		t.Errorf("close line = %q, want %q", lines[1], want)
	}
}

// Naming the server makes the TLS probe fair game for an IP.
func TestProbeTriesTLSForNamedIP(t *testing.T) {
	tlsPort := sshEcho(t, "SSH-2.0-tls-server", "", "ssh", true)

	cfg := loopbackConfig(tlsPort, 1)
	cfg.Host = "127.0.0.1"
	cfg.ServerName = "127.0.0.1"

	chosen, err := probe(context.Background(), cfg, "SSH-2.0-client", io.Discard)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if chosen.name != "tls" {
		t.Errorf("probe chose %s, want tls", chosen.name)
	}
}

// SSH mode end to end: a local listener, the banner exchange, and the relay.
func TestSSHSessionRelaysTheWinner(t *testing.T) {
	tlsPort := sshEcho(t, "SSH-2.0-tls-server", "", "ssh", true)
	sshPort := sshEcho(t, "SSH-2.0-plain-server", "", "", false)

	local := freePort(t)
	cfg := loopbackConfig(tlsPort, sshPort)
	cfg.Silent = true

	done := make(chan error, 1)
	go func() { done <- Listen(context.Background(), cfg, local.String(), io.Discard) }()

	conn, err := dialLocal(local.String())
	if err != nil {
		t.Fatalf("connect to the local listener: %v", err)
	}
	defer conn.Close()

	if _, err := fmt.Fprintf(conn, "SSH-2.0-client\r\nBYE\r\n"); err != nil {
		t.Fatal(err)
	}

	conn.SetReadDeadline(time.Now().Add(probeWait))
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if first := strings.TrimSpace(string(got)); !strings.HasPrefix(first, "SSH-2.0-tls-server") {
		t.Errorf("the client saw %q, want the TLS server's banner first", first)
	}

	_ = done // the listener stays up; the session ended with it
}

// Bytes glued to the banner (OpenSSH's KEXINIT) survive the relay.
func TestProbeKeepsTheReadAhead(t *testing.T) {
	tlsPort := sshEcho(t, "SSH-2.0-tls-server", "KEXINIT-S", "ssh", true)

	chosen, err := probe(context.Background(), loopbackConfig(tlsPort, 1), "SSH-2.0-client", io.Discard)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	line, err := chosen.r.ReadString('\n')
	if err != nil {
		t.Fatalf("read the read-ahead: %v", err)
	}
	if strings.TrimRight(line, "\r\n") != "KEXINIT-S" {
		t.Errorf("read-ahead = %q, want KEXINIT-S", line)
	}
}

// A peer that connects and never speaks is refused on its own deadline: the
// handshake times out on the handshake clock, the banner read on the banner clock,
// and neither loses a race with the connect timeout.
func TestProbeRefusesSilentPeers(t *testing.T) {
	tlsPort := silentTLSServer(t) // accepts, never finishes the handshake
	sshPort := silentTCPServer(t) // accepts, never answers the banner

	cfg := loopbackConfig(tlsPort, sshPort)
	cfg.TCPTimeout = 100 * time.Millisecond

	var report strings.Builder
	start := time.Now()
	_, err := probe(context.Background(), cfg, "SSH-2.0-client", &report)
	elapsed := time.Since(start)
	if !errors.Is(err, ErrNoServer) {
		t.Fatalf("probe: got %v, want ErrNoServer", err)
	}
	if elapsed > 400*time.Millisecond {
		t.Errorf("probe ran %s against silent peers", ElapsedFor(elapsed))
	}
	if strings.Contains(report.String(), "closed network connection") {
		t.Errorf("the banner write lost the race with the probe deadline: %q", report.String())
	}
	if !strings.Contains(report.String(), "read banner") {
		t.Errorf("report = %q, want a banner read failure", report.String())
	}
}

// The caller's deadline bounds the probe even when the connect timeout is long.
func TestProbeHonorsCallerDeadline(t *testing.T) {
	tlsPort := silentTCPServer(t)
	sshPort := silentTCPServer(t)

	cfg := loopbackConfig(tlsPort, sshPort)
	cfg.TCPTimeout = 10 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := probe(ctx, cfg, "SSH-2.0-client", io.Discard)
	elapsed := time.Since(start)
	if !errors.Is(err, ErrNoServer) {
		t.Fatalf("probe: got %v, want ErrNoServer", err)
	}
	if elapsed > 300*time.Millisecond {
		t.Errorf("probe ran %s with a 10s connect timeout under a 100ms deadline", ElapsedFor(elapsed))
	}
}

// A plain banner that declares the name being dialled is proof on its own: the TLS
// handshake is cut short instead of running to its deadline.
func TestProbeDeclaredPlainWinsEarly(t *testing.T) {
	tlsPort := silentTLSServer(t)
	sshPort := sshEcho(t, "SSH-2.0-OpenSSH_9.6 host:localhost", "", "", false)

	cfg := loopbackConfig(tlsPort, sshPort)
	cfg.ServerName = "localhost"

	start := time.Now()
	chosen, err := probe(context.Background(), cfg, "SSH-2.0-client", io.Discard)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if chosen.name != "ssh" {
		t.Errorf("probe chose %s, want ssh", chosen.name)
	}
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Errorf("probe waited %s for a handshake it did not need", ElapsedFor(elapsed))
	}
}

// Stdio mode runs the same probe and relay on stdin and stdout.
func TestSSHStdio(t *testing.T) {
	tlsPort := sshEcho(t, "SSH-2.0-tls-server", "", "ssh", true)
	sshPort := sshEcho(t, "SSH-2.0-plain-server", "", "", false)

	inRead, inWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	outRead, outWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	oldIn, oldOut := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = inRead, outWrite
	defer func() { os.Stdin, os.Stdout = oldIn, oldOut }()

	_, _ = io.WriteString(inWrite, "SSH-2.0-client\r\nBYE\r\n")

	cfg := loopbackConfig(tlsPort, sshPort)
	cfg.Silent = true

	done := make(chan error, 1)
	go func() { done <- Serve(context.Background(), cfg, tunnel.StdioConn("-"), io.Discard) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("stdio: %v", err)
		}
	case <-time.After(probeWait):
		t.Fatal("stdio: the session never ended")
	}

	_ = outWrite.Close()
	got, err := io.ReadAll(outRead)
	if err != nil {
		t.Fatalf("stdio: read: %v", err)
	}
	if !strings.HasPrefix(string(got), "SSH-2.0-tls-server\r\n") || !strings.Contains(string(got), "GOODBYE") {
		t.Errorf("stdio: got %q, want the TLS banner then GOODBYE", string(got))
	}
}

// Canceling the context ends a session that is otherwise still open.
func TestSSHSessionEndsOnCancel(t *testing.T) {
	tlsPort := sshEcho(t, "SSH-2.0-tls-server", "", "ssh", true)
	sshPort := sshEcho(t, "SSH-2.0-plain-server", "", "", false)

	local := freePort(t)
	cfg := loopbackConfig(tlsPort, sshPort)
	cfg.Silent = true

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- Listen(ctx, cfg, local.String(), io.Discard) }()

	conn, err := dialLocal(local.String())
	if err != nil {
		t.Fatalf("connect to the local listener: %v", err)
	}
	defer conn.Close()

	if _, err := fmt.Fprintf(conn, "SSH-2.0-client\r\n"); err != nil {
		t.Fatal(err)
	}

	client := bufio.NewReader(conn)
	conn.SetReadDeadline(time.Now().Add(probeWait))
	if _, err := client.ReadString('\n'); err != nil {
		t.Fatalf("read the server banner: %v", err)
	}

	cancel()
	if _, err := client.ReadString('\n'); !errors.Is(err, io.EOF) {
		t.Errorf("after cancel the local side got %v, want EOF", err)
	}
	if err := <-done; err != nil {
		t.Errorf("the tunnel ended with %v, want nil", err)
	}
}

// SniffALPN fills in only an unset protocol list, and it never consumes the banner.
func TestSniffALPN(t *testing.T) {
	cases := []struct {
		name   string
		protos []string
		local  string
		want   []string
	}{
		{"ssh client, no list", nil, "SSH-2.0-OpenSSH_9.6\r\n", []string{"ssh"}},
		{"http client, no list", nil, "GET / HTTP/1.1\r\n", nil},
		{"the operator's list wins", []string{"h2"}, "SSH-2.0-OpenSSH_9.6\r\n", []string{"h2"}},
		{"an empty list offers nothing", []string{}, "SSH-2.0-OpenSSH_9.6\r\n", []string{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn, peer := net.Pipe()
			defer conn.Close()
			defer peer.Close()
			go func() { _, _ = io.WriteString(peer, tc.local) }()

			client := bufio.NewReader(conn)
			got := SniffALPN(tc.protos, client, conn)
			if !slices.Equal(got, tc.want) {
				t.Errorf("SniffALPN = %q, want %q", got, tc.want)
			}
			// the peek must not consume: the relay still sees the line
			want := strings.TrimRight(tc.local, "\r\n")
			rest, err := client.ReadString('\n')
			if err != nil || strings.TrimRight(rest, "\r\n") != want {
				t.Errorf("the peek consumed the banner: %q", rest)
			}
		})
	}
}

// ElapsedFor is the ssh package's own rendering, kept here for the test messages.
func ElapsedFor(d time.Duration) string { return tunnel.ElapsedText(d) }

func freePort(t *testing.T) *net.TCPAddr {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("local port: %v", err)
	}
	addr := ln.Addr().(*net.TCPAddr)
	_ = ln.Close()
	return addr
}

func dialLocal(addr string) (net.Conn, error) {
	for range 200 {
		conn, err := net.Dial("tcp", addr)
		if err == nil {
			return conn, nil
		}
		time.Sleep(5 * time.Millisecond)
	}
	return nil, fmt.Errorf("nothing listening on %s", addr)
}
