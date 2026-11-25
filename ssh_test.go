package sclient

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/therootcompany/sclient/internal/testserver"
)

// probeWait bounds a loopback probe: a real one finishes in a couple of hundred
// milliseconds at most.
const probeWait = 150 * time.Millisecond

// loopbackTunnel points both probes at localhost with the given ports.
func loopbackTunnel(tlsPort, sshPort int) *Tunnel {
	return &Tunnel{
		RemoteAddress:      "localhost",
		RemotePort:         tlsPort,
		SSHPort:            sshPort,
		TCPTimeout:         50 * time.Millisecond,
		InsecureSkipVerify: true,
	}
}

// sshAccept runs one SSH-mode session per local connection, the way the command
// does, and returns when ctx is canceled.
func sshAccept(ctx context.Context, tun *Tunnel, ln net.Listener, stderr io.Writer) error {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go func() { _ = tun.ServeSSH(ctx, conn, stderr, true, false) }()
	}
}

// Both ports answer the version string: the TLS one wins.
func TestProbePrefersTLS(t *testing.T) {
	tlsPort := testserver.SSHServer(t, "SSH-2.0-tls-server", "", "ssh", true)
	sshPort := testserver.SSHServer(t, "SSH-2.0-plain-server", "", "", false)

	chosen, err := loopbackTunnel(tlsPort, sshPort).probeSSH(context.Background(), "SSH-2.0-client", io.Discard, false, false)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if chosen.kind != "tls" {
		t.Errorf("probe chose %s (%s), want tls", chosen.kind, chosen.address)
	}
	if chosen.versionString != "SSH-2.0-tls-server" {
		t.Errorf("version string = %q, want the TLS server's", chosen.versionString)
	}
}

// A TLS connection that is slow to answer is still the TLS connection: the plain
// port's undeclared version string proves nothing, so the handshake keeps its chance and
// the grace period does not cut it off.
func TestProbeSlowTLSStillWins(t *testing.T) {
	tlsPort := testserver.SlowSSHServer(t, "SSH-2.0-slow-tls-server", "ssh", 60*time.Millisecond)
	sshPort := testserver.SSHServer(t, "SSH-2.0-plain-server", "", "", false)

	chosen, err := loopbackTunnel(tlsPort, sshPort).probeSSH(context.Background(), "SSH-2.0-client", io.Discard, false, false)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if chosen.kind != "tls" {
		t.Errorf("probe chose %s (%s), want tls", chosen.kind, chosen.address)
	}
	if chosen.versionString != "SSH-2.0-slow-tls-server" {
		t.Errorf("version string = %q, want the slow TLS server's", chosen.versionString)
	}
}

// TLS does not answer: the plain SSH port wins.
func TestProbeFallsBackToPlainSSH(t *testing.T) {
	sshPort := testserver.SSHServer(t, "SSH-2.0-plain-server", "", "", false)

	chosen, err := loopbackTunnel(1, sshPort).probeSSH(context.Background(), "SSH-2.0-client", io.Discard, false, false)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if chosen.kind != "ssh" {
		t.Errorf("probe chose %s, want ssh", chosen.kind)
	}
}

// The ALPN check: TLS that does not name a protocol we asked for is not routing
// ssh, so the plain port wins and the verbose report names the loser.
func TestProbeALPNCheck(t *testing.T) {
	tlsPort := testserver.SSHServer(t, "SSH-2.0-no-alpn", "", "", true)
	sshPort := testserver.SSHServer(t, "SSH-2.0-plain-server", "", "", false)

	tun := loopbackTunnel(tlsPort, sshPort)
	tun.NextProtos = []string{"ssh"}

	report := newReport()
	chosen, err := tun.probeSSH(context.Background(), "SSH-2.0-client", report, true, false)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if chosen.kind != "ssh" {
		t.Errorf("probe chose %s, want ssh", chosen.kind)
	}

	want := fmt.Sprintf("dial: tls %s: negotiated ALPN (none)", tun.Remote())
	if !strings.Contains(report.String(), want) {
		t.Errorf("report = %q, want %q", report.String(), want)
	}
}

// A server that speaks ALPN but not one of ours fails the handshake outright; the
// plain port still wins.
func TestProbeALPNMismatchAbortsTheHandshake(t *testing.T) {
	tlsPort := testserver.SSHServer(t, "SSH-2.0-http-only", "", "http/1.1", true)
	sshPort := testserver.SSHServer(t, "SSH-2.0-plain-server", "", "", false)

	tun := loopbackTunnel(tlsPort, sshPort)
	tun.NextProtos = []string{"ssh"}

	chosen, err := tun.probeSSH(context.Background(), "SSH-2.0-client", io.Discard, false, false)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if chosen.kind != "ssh" {
		t.Errorf("probe chose %s, want ssh", chosen.kind)
	}
}

// An explicit empty ALPN list turns the check off.
func TestProbeALPNCheckOff(t *testing.T) {
	tlsPort := testserver.SSHServer(t, "SSH-2.0-no-alpn", "", "", true)

	tun := loopbackTunnel(tlsPort, 1)
	tun.NextProtos = []string{}

	chosen, err := tun.probeSSH(context.Background(), "SSH-2.0-client", io.Discard, false, false)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if chosen.kind != "tls" {
		t.Errorf("probe chose %s, want tls", chosen.kind)
	}
}

// A name that does not resolve is one failure, named once, before any dial: the
// close line has no host to name and no port that was tried.
func TestProbeNoSuchHost(t *testing.T) {
	tun := loopbackTunnel(1, 1)
	tun.RemoteAddress = "does-not-exist.invalid" // RFC 2606: never resolves

	start := time.Now()
	_, err := tun.probeSSH(context.Background(), "SSH-2.0-client", io.Discard, false, true)
	elapsed := time.Since(start)

	if !errors.Is(err, ErrNoServer) {
		t.Fatalf("probe: got %v, want ErrNoServer", err)
	}

	report := err.Error()
	if count := strings.Count(report, "no such host"); count != 1 {
		t.Errorf("report = %q, want the lookup named once", report)
	}
	if elapsed > 100*time.Millisecond {
		t.Errorf("probe dialled anyway: %s", elapsedText(elapsed))
	}

	lines := strings.Split(strings.TrimRight(report, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("report = %q, want the cause and the close line", report)
	}
	if lines[0] != "does-not-exist.invalid: no usable server: no such host" {
		t.Errorf("cause line = %q, want the name and the cause", lines[0])
	}
	want := `Connection closed by "NO SUCH HOST" port [0]`
	if lines[1] != want {
		t.Errorf("close line = %q, want %q", lines[1], want)
	}
}

// SSH mode does not dial an IP over TLS unless the server is named: a proxy that
// routes by name has nothing to route on an address.
func TestProbeSkipsTLSForUnnamedIP(t *testing.T) {
	tlsPort := testserver.SSHServer(t, "SSH-2.0-tls-server", "", "ssh", true)
	sshPort := testserver.SSHServer(t, "SSH-2.0-plain-server", "", "", false)

	tun := loopbackTunnel(tlsPort, sshPort)
	tun.RemoteAddress = "127.0.0.1"

	report := newReport()
	chosen, err := tun.probeSSH(context.Background(), "SSH-2.0-client", report, true, false)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if chosen.kind != "ssh" {
		t.Errorf("probe chose %s, want ssh", chosen.kind)
	}
	if !strings.Contains(report.String(), "no name to route on") {
		t.Errorf("report = %q, want the skipped TLS candidate", report.String())
	}
}

// A version string that declares a host other than the one dialled is a different server:
// it is refused, and the report says so. A version string that declares nothing is
// accepted - the rule is opt-in.
func TestProbeVersionStringMismatch(t *testing.T) {
	tlsPort := testserver.SSHServer(t, "SSH-2.0-OpenSSH_9.6 host:other.example.net", "", "ssh", true)

	tun := loopbackTunnel(tlsPort, 1)
	tun.ServerName = "example.com"

	report := newReport()
	_, err := tun.probeSSH(context.Background(), "SSH-2.0-client", report, true, false)
	if !errors.Is(err, ErrNoServer) {
		t.Fatalf("probe: got %v, want ErrNoServer", err)
	}
	if !strings.Contains(report.String(), `excludes "example.com"`) {
		t.Errorf("report = %q, want the mismatch", report.String())
	}
}

// The report of a session with no server names the command, then every candidate
// A session with no server names the remote, then every candidate that lost.
// Only a session piped to ssh ends with ssh's closing line and the ports tried;
// a forwarded port has no ssh to answer to.
func TestProbeReportClosesLikeSSH(t *testing.T) {
	tlsPort := testserver.SSHServer(t, "SSH-2.0-OpenSSH_9.6 host:other.example.net", "", "ssh", true)
	sshPort := testserver.SSHServer(t, "SSH-2.0-OpenSSH_9.6 host:other.example.net", "", "", false)

	tun := loopbackTunnel(tlsPort, sshPort)

	_, err := tun.probeSSH(context.Background(), "SSH-2.0-client", io.Discard, false, true)
	if !errors.Is(err, ErrNoServer) {
		t.Fatalf("probe: got %v, want ErrNoServer", err)
	}

	// The report is the body; the command printing it names itself in front.
	lines := strings.Split(strings.TrimRight(err.Error(), "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("report = %q, want a header, two candidates and the close line", err.Error())
	}
	if lines[0] != "localhost: no usable server" {
		t.Errorf("header = %q, want the remote named", lines[0])
	}
	for _, line := range lines[1:3] {
		if !strings.HasPrefix(line, "  ") {
			t.Errorf("candidate line %q, want it indented", line)
		}
	}
	want := fmt.Sprintf(`Connection closed by "localhost" ports [%d, %d]`, sshPort, tlsPort)
	if lines[3] != want {
		t.Errorf("close line = %q, want %q", lines[3], want)
	}

	_, err = tun.probeSSH(context.Background(), "SSH-2.0-client", io.Discard, false, false)
	if strings.Contains(err.Error(), "Connection closed by") {
		t.Errorf("report for a forwarded port = %q, want no ssh close line", err.Error())
	}
}

// Naming the server makes the TLS probe fair game for an IP.
func TestProbeTriesTLSForNamedIP(t *testing.T) {
	tlsPort := testserver.SSHServer(t, "SSH-2.0-tls-server", "", "ssh", true)

	tun := loopbackTunnel(tlsPort, 1)
	tun.RemoteAddress = "127.0.0.1"
	tun.ServerName = "127.0.0.1"

	chosen, err := tun.probeSSH(context.Background(), "SSH-2.0-client", io.Discard, false, false)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if chosen.kind != "tls" {
		t.Errorf("probe chose %s, want tls", chosen.kind)
	}
}

// SSH mode end to end: a local listener, the version string exchange, and the relay.
func TestSSHSessionRelaysTheWinner(t *testing.T) {
	tlsPort := testserver.SSHServer(t, "SSH-2.0-tls-server", "KEXINIT-S", "ssh", true)
	sshPort := testserver.SSHServer(t, "SSH-2.0-plain-server", "KEXINIT-S", "", false)

	local := testserver.FreePort(t)
	tun := loopbackTunnel(tlsPort, sshPort)

	ln, err := net.Listen("tcp", local.String())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var stderr bytes.Buffer
	done := make(chan error, 1)
	go func() { done <- sshAccept(context.Background(), tun, ln, &stderr) }()

	conn, err := testserver.Dial(t, local.String())
	if err != nil {
		t.Fatalf("connect to the local listener: %v", err)
	}
	defer conn.Close()

	if _, err := fmt.Fprintf(conn, "SSH-2.0-client\r\nBYE\r\n"); err != nil {
		t.Fatal(err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(probeWait))
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "SSH-2.0-tls-server\r\nKEXINIT-S\r\nGOODBYE\r\n" {
		t.Errorf("the client saw %q, want the version string, the read-ahead glued to it, then GOODBYE", string(got))
	}
	// A forwarded connection says which port won.
	if !strings.Contains(stderr.String(), "[connect]") {
		t.Errorf("a forwarded session printed %q, want the [connect] line", stderr.String())
	}

	_ = done // the listener stays up; the session ended with it
}

// Bytes glued to the version string (OpenSSH's KEXINIT) survive the relay.
func TestProbeKeepsTheReadAhead(t *testing.T) {
	tlsPort := testserver.SSHServer(t, "SSH-2.0-tls-server", "KEXINIT-S", "ssh", true)

	chosen, err := loopbackTunnel(tlsPort, 1).probeSSH(context.Background(), "SSH-2.0-client", io.Discard, false, false)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	line, err := chosen.reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read the read-ahead: %v", err)
	}
	if strings.TrimRight(line, "\r\n") != "KEXINIT-S" {
		t.Errorf("read-ahead = %q, want KEXINIT-S", line)
	}
}

// A peer that connects and never speaks is refused on its own deadline: the
// handshake times out on the handshake deadline, the version string read on the version string
// timeout, and neither loses a race with the connect timeout.
func TestProbeRefusesSilentPeers(t *testing.T) {
	tlsPort := testserver.SilentTLS(t) // accepts, never finishes the handshake
	sshPort := testserver.SilentTCP(t) // accepts, never answers the version string

	tun := loopbackTunnel(tlsPort, sshPort)
	tun.TCPTimeout = 100 * time.Millisecond

	start := time.Now()
	_, err := tun.probeSSH(context.Background(), "SSH-2.0-client", io.Discard, false, false)
	elapsed := time.Since(start)
	if !errors.Is(err, ErrNoServer) {
		t.Fatalf("probe: got %v, want ErrNoServer", err)
	}
	if elapsed > 400*time.Millisecond {
		t.Errorf("probe ran %s against silent peers", elapsedText(elapsed))
	}

	report := err.Error()
	if strings.Contains(report, "closed network connection") {
		t.Errorf("the version string write lost the race with the probe deadline: %q", report)
	}
	if !strings.Contains(report, "read version string") {
		t.Errorf("report = %q, want a version string read failure", report)
	}
}

// The caller's deadline bounds the probe even when the connect timeout is long.
func TestProbeHonorsCallerDeadline(t *testing.T) {
	tlsPort := testserver.SilentTCP(t)
	sshPort := testserver.SilentTCP(t)

	tun := loopbackTunnel(tlsPort, sshPort)
	tun.TCPTimeout = 10 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := tun.probeSSH(ctx, "SSH-2.0-client", io.Discard, false, false)
	elapsed := time.Since(start)
	if !errors.Is(err, ErrNoServer) {
		t.Fatalf("probe: got %v, want ErrNoServer", err)
	}
	if elapsed > 300*time.Millisecond {
		t.Errorf("probe ran %s with a 10s connect timeout under a 100ms deadline", elapsedText(elapsed))
	}
}

// A plain version string that declares the name being dialled is proof on its own: the TLS
// handshake is cut short instead of running to its deadline.
func TestProbeDeclaredPlainWinsEarly(t *testing.T) {
	tlsPort := testserver.SilentTLS(t)
	sshPort := testserver.SSHServer(t, "SSH-2.0-OpenSSH_9.6 host:localhost", "", "", false)

	tun := loopbackTunnel(tlsPort, sshPort)
	tun.ServerName = "localhost"

	start := time.Now()
	chosen, err := tun.probeSSH(context.Background(), "SSH-2.0-client", io.Discard, false, false)
	if err != nil {
		t.Fatalf("probe: got %v, want ErrNoServer", err)
	}
	if chosen.kind != "ssh" {
		t.Errorf("probe chose %s, want ssh", chosen.kind)
	}
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Errorf("probe waited %s for a handshake it did not need", elapsedText(elapsed))
	}
}

// Stdio mode runs the same probe and relay on stdin and stdout.
func TestSSHStdio(t *testing.T) {
	tlsPort := testserver.SSHServer(t, "SSH-2.0-tls-server", "", "ssh", true)
	sshPort := testserver.SSHServer(t, "SSH-2.0-plain-server", "", "", false)

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

	tun := loopbackTunnel(tlsPort, sshPort)

	// A piped session is ssh's terminal; it says nothing about itself.
	var stderr bytes.Buffer
	done := make(chan error, 1)
	go func() { done <- tun.ServeSSH(context.Background(), StdioConn("-"), &stderr, false, false) }()

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
		t.Errorf("stdio: got %q, want the TLS version string then GOODBYE", string(got))
	}
	if strings.Contains(stderr.String(), "[connect]") {
		t.Errorf("stdio: a piped session printed %q, want only the failure report", stderr.String())
	}
}

// Canceling the context ends a session that is otherwise still open.
func TestSSHSessionEndsOnCancel(t *testing.T) {
	tlsPort := testserver.SSHServer(t, "SSH-2.0-tls-server", "KEXINIT-S", "ssh", true)
	sshPort := testserver.SSHServer(t, "SSH-2.0-plain-server", "KEXINIT-S", "", false)

	local := testserver.FreePort(t)
	tun := loopbackTunnel(tlsPort, sshPort)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	ln, err := net.Listen("tcp", local.String())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	done := make(chan error, 1)
	go func() { done <- sshAccept(ctx, tun, ln, io.Discard) }()

	conn, err := testserver.Dial(t, local.String())
	if err != nil {
		t.Fatalf("connect to the local listener: %v", err)
	}
	defer conn.Close()

	if _, err := fmt.Fprintf(conn, "SSH-2.0-client\r\n"); err != nil {
		t.Fatal(err)
	}

	client := bufio.NewReader(conn)
	_ = conn.SetReadDeadline(time.Now().Add(probeWait))
	if _, err := client.ReadString('\n'); err != nil {
		t.Fatalf("read the server version string: %v", err)
	}
	// Drain the read-ahead glued to the version string so the cancel is what ends the stream.
	if _, err := client.ReadString('\n'); err != nil {
		t.Fatalf("read the read-ahead: %v", err)
	}

	cancel()
	if _, err := client.ReadString('\n'); !errors.Is(err, io.EOF) {
		t.Errorf("after cancel the local side got %v, want EOF", err)
	}
	if err := <-done; err != nil {
		t.Errorf("the tunnel ended with %v, want nil", err)
	}
}

// A session canceled while the client is still silent ends on the context rather
// than hanging on stdin.
func TestSSHStdioCancel(t *testing.T) {
	tlsPort := testserver.SSHServer(t, "SSH-2.0-tls-server", "", "ssh", true)
	sshPort := testserver.SSHServer(t, "SSH-2.0-plain-server", "", "", false)

	inRead, inWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_, outWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	oldIn, oldOut := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = inRead, outWrite
	defer func() { os.Stdin, os.Stdout = oldIn, oldOut }()
	defer func() { _ = inWrite.Close(); _ = outWrite.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	tun := loopbackTunnel(tlsPort, sshPort)

	if err := tun.ServeSSH(ctx, StdioConn("-"), io.Discard, false, false); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("stdio cancel: ServeSSH returned %v, want the deadline", err)
	}
}

// sniffALPN fills in only an unset protocol list, and it never consumes the version string.
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
			got := sniffALPN(context.Background(), tc.protos, client, conn)
			if !slices.Equal(got, tc.want) {
				t.Errorf("sniffALPN = %q, want %q", got, tc.want)
			}
			// the peek must not consume: the relay still sees the line
			want := strings.TrimRight(tc.local, "\r\n")
			rest, err := client.ReadString('\n')
			if err != nil || strings.TrimRight(rest, "\r\n") != want {
				t.Errorf("the peek consumed the version string: %q", rest)
			}
		})
	}
}

// A version string is one line, capped at the RFC length, and must start with "SSH-".
// RFC 4253 section 4.2 counts the CR and the LF in the 255-character cap.
func TestReadVersionString(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"crlf", "SSH-2.0-OpenSSH_10.5\r\n", "SSH-2.0-OpenSSH_10.5"},
		{"lf", "SSH-2.0-OpenSSH_10.5\n", "SSH-2.0-OpenSSH_10.5"},
		{"not ssh", "HTTP/1.1 200 OK\r\n", ""},
		// RFC 4253 section 4.2: the server MAY send other lines before the version
		// string, and none of them start with "SSH-".
		{"pre-version lines", "prelude line\r\nSSH-2.0-OpenSSH_10.5\r\n", "SSH-2.0-OpenSSH_10.5"},
		// 253 characters plus CRLF is the longest the RFC allows.
		{"255 with CRLF", "SSH-" + strings.Repeat("x", 249) + "\r\n", "SSH-" + strings.Repeat("x", 249)},
		{"256 with CRLF", "SSH-" + strings.Repeat("x", 250) + "\r\n", ""},
		// no newline at all: bounded by the RFC limit, not by the buffer
		{"never terminates", "SSH-" + strings.Repeat("x", 4096), ""},
		{"read-ahead", "SSH-2.0-x\r\nKEXINIT-PAYLOAD", "SSH-2.0-x"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := bufio.NewReader(strings.NewReader(tc.input))
			version, err := readVersionString(r)
			if tc.want == "" {
				if err == nil {
					t.Errorf("readVersionString(%q) = %q, want an error", tc.input, version)
				}
				return
			}
			if err != nil {
				t.Fatalf("readVersionString: %v", err)
			}
			if version != tc.want {
				t.Errorf("version string = %q, want %q", version, tc.want)
			}
			if tc.name == "read-ahead" {
				rest, err := io.ReadAll(r)
				if err != nil || string(rest) != "KEXINIT-PAYLOAD" {
					t.Errorf("read-ahead = %q, want the bytes glued to the version string", string(rest))
				}
			}
		})
	}
}

// RFC 4253 section 4.2: everything after the protocol version is a comment. A
// server can name itself there; a version string that names no host declares nothing.
func TestDeclaredHosts(t *testing.T) {
	tests := []struct {
		versionString string
		want          []string
	}{
		{"SSH-2.0-OpenSSH_10.5", nil},
		{"SSH-2.0-OpenSSH_9.6p1 tlsrouter-v0.9.4-2eeb5da", nil},
		{"SSH-2.0-OpenSSH_9.6 host:a.example.com", []string{"a.example.com"}},
		{"SSH-2.0-OpenSSH_9.6 tlsrouter-v0.9.4 host:a.example.com", []string{"a.example.com"}},
		{"SSH-2.0-x hostname:b.example.com,c.example.com", []string{"b.example.com", "c.example.com"}},
		{"SSH-2.0-x HOST:a.example.com", []string{"a.example.com"}},
		{"SSH-2.0-x host:", nil},
		{"SSH-2.0-x myhost:a.example.com", nil}, // not a host: field
		{"SSH-2.0-x host:a.example.com,", []string{"a.example.com"}},
		{"SSH-2.0-x hostname:a.example.com host:web1.internal", []string{"a.example.com", "web1.internal"}},
	}
	for _, tc := range tests {
		got := declaredHosts(tc.versionString)
		if !slices.Equal(got, tc.want) {
			t.Errorf("declaredHosts(%q) = %v, want %v", tc.versionString, got, tc.want)
		}
	}
}

// A declared host that is not the name we asked for is a different server; a
// version string that declares nothing is no evidence either way.
func TestVersionStringMismatch(t *testing.T) {
	tests := []struct {
		want          string
		versionString string
		expect        string
	}{
		{"guest.example.com", "SSH-2.0-OpenSSH_9.6", ""},
		{"guest.example.com", "SSH-2.0-OpenSSH_9.6 tlsrouter-v0.9.4 host:guest.example.com", ""},
		{"guest.example.com", "SSH-2.0-x host:vms.example.com,guest.example.com", ""},
		{"Guest.example.com", "SSH-2.0-x HOST:guest.example.com", ""},
		{"guest.example.com", "SSH-2.0-x tlsrouter-v0.9.4 host:vms.example.com",
			`version string "SSH-2.0-x tlsrouter-v0.9.4 host:vms.example.com" excludes "guest.example.com"`},
		{"", "SSH-2.0-x host:vms.example.com", ""},          // no name asked: nothing to match
		{"192.0.2.1", "SSH-2.0-x host:vms.example.com", ""}, // an IP is not contradicted by names
	}
	for _, tc := range tests {
		if got := versionStringMismatch(tc.want, tc.versionString); got != tc.expect {
			t.Errorf("versionStringMismatch(%q, %q) = %q, want %q", tc.want, tc.versionString, got, tc.expect)
		}
	}
}

func TestGracePeriod(t *testing.T) {
	tests := []struct {
		elapsed time.Duration
		want    time.Duration
	}{
		// Half the elapsed time, floored at minGracePeriod (300ms).
		{0, minGracePeriod},
		{100 * time.Millisecond, minGracePeriod},
		{300 * time.Millisecond, minGracePeriod},
		{400 * time.Millisecond, minGracePeriod},
		{600 * time.Millisecond, 300 * time.Millisecond},
		{3 * time.Second, 1500 * time.Millisecond},
	}
	for _, tc := range tests {
		if got := gracePeriod(tc.elapsed); got != tc.want {
			t.Errorf("gracePeriod(%v) = %v, want %v", tc.elapsed, got, tc.want)
		}
	}
}

// newReport collects the probe's diagnostics, which arrive from the candidate
// goroutines, so the test writer has to be safe to write from both.
func newReport() *safeReport { return &safeReport{} }

type safeReport struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (r *safeReport) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.buf.Write(p)
}

func (r *safeReport) String() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.buf.String()
}
