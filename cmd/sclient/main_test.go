package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/therootcompany/sclient"
	"github.com/therootcompany/sclient/internal/testserver"
)

const (
	request   = "GET / HTTP/1.1\r\nHost: local\r\n\r\n"
	serveWait = 200 * time.Millisecond
)

func runSession(t *testing.T, tun *sclient.Tunnel, silent bool) (string, error) {
	t.Helper()

	var out bytes.Buffer
	cfg := MainConfig{silent: silent, stderr: &out}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- cfg.run(ctx, tun) }()

	conn, err := testserver.Dial(t, tun.Local())
	if err != nil {
		return "", err
	}
	defer conn.Close()

	_, _ = conn.Write([]byte(request))
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}

	_ = conn.SetReadDeadline(time.Now().Add(serveWait))
	got, err := io.ReadAll(conn)
	if err != nil {
		return "", fmt.Errorf("no reply through the listener: %w", err)
	}
	if string(got) != testserver.Reply {
		return "", fmt.Errorf("the client got %q, want %q", string(got), testserver.Reply)
	}

	cancel()
	return out.String(), <-done
}

// The version line appears once, whatever stream usage is written to.
func TestUsagePrintsVersionOnce(t *testing.T) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.Usage = func() { usage(fs) }

	var out bytes.Buffer
	fs.SetOutput(&out)
	fs.Usage()

	if got := strings.Count(out.String(), version); got != 1 {
		t.Errorf("usage printed the version %d times, want 1", got)
	}
}

// --help is the flag package's own: it is not declared, and parse answers it
// with ErrHelp. Declaring a "help" flag would take that special case away.
func TestBuiltInHelp(t *testing.T) {
	for _, arg := range []string{"-h", "-help", "--help"} {
		fs := flag.NewFlagSet(name, flag.ContinueOnError)
		fs.SetOutput(io.Discard)

		if err := fs.Parse([]string{arg}); !errors.Is(err, flag.ErrHelp) {
			t.Errorf("%q: got %v, want flag.ErrHelp", arg, err)
		}
	}

	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse([]string{"--bogus"}); errors.Is(err, flag.ErrHelp) {
		t.Error("an unknown flag is a usage error, not help")
	}
}

// The copyright spans the license year to the build year, or to "present"
// when the build carries no date.
func TestCopyrightYears(t *testing.T) {
	cases := []struct {
		date string
		want string
	}{
		{"2026-11-23", "2018-2026"},
		{"2026-11-23T09:12:03-05:00", "2018-2026"},
		{"2026-11-23 09:12:03-05:00", "2018-2026"},
		{"", "2018-present"},
		{"0001-01-01", "2018-present"},
		{"not a date", "2018-present"},
	}

	for _, c := range cases {
		if got := copyrightYears(c.date); got != c.want {
			t.Errorf("copyrightYears(%q): got %q, want %q", c.date, got, c.want)
		}
	}
}

// The build date prints without the T, keeping the offset the build carried.
// A date with no time is left alone; nothing invents a zone the build never had.
func TestDisplayBuildDate(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"2026-11-24T14:31:14-05:00", "2026-11-24 14:31:14-05:00"},
		{"2026-11-24T14:31:14Z", "2026-11-24 14:31:14+00:00"},
		{"2026-11-24 14:31:14-05:00", "2026-11-24 14:31:14-05:00"},
		{"2026-11-24", "2026-11-24"},
		{"0001-01-01", "0001-01-01"},
		{"", ""},
		{"not a date", "not a date"},
	}

	for _, c := range cases {
		if got := displayBuildDate(c.in); got != c.want {
			t.Errorf("displayBuildDate(%q): got %q, want %q", c.in, got, c.want)
		}
	}
}

// The defaults and rejections the parsers own.
func TestRemoteAddr(t *testing.T) {
	cases := []struct {
		in   string
		host string
		port int
		err  bool
	}{
		{"example.com", "example.com", 443, false}, // a bare host takes the default port
		{"[::1]", "::1", 443, false},               // bracketed IPv6, no port
		{" example.com ", "example.com", 443, false},
		{"::1", "", 0, true}, // ambiguous: "::1:443" is an IPv6 address
		{"2001:db8::1:443", "", 0, true},
		{"example.com:99999", "", 0, true},
		{"example.com:0", "", 0, true},
		{"example.com:", "", 0, true},
		{"", "", 0, true},
	}

	for _, c := range cases {
		host, port, err := remoteAddr(c.in)
		if c.err {
			if err == nil {
				t.Errorf("remoteAddr(%q): got %q:%d, want an error", c.in, host, port)
			}
			continue
		}
		if err != nil {
			t.Errorf("remoteAddr(%q): %v", c.in, err)
			continue
		}
		if host != c.host || port != c.port {
			t.Errorf("remoteAddr(%q): got %q:%d, want %q:%d", c.in, host, port, c.host, c.port)
		}
	}
}

func TestRunListener(t *testing.T) {
	host, port, shutdown, conns := testserver.TLS(t)
	defer shutdown()

	local := testserver.FreePort(t)
	tun := &sclient.Tunnel{
		RemoteAddress:      host,
		RemotePort:         port,
		LocalAddress:       "127.0.0.1",
		LocalPort:          local.Port,
		InsecureSkipVerify: true,
	}

	lines, err := runSession(t, tun, false)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	// The pre-flight probe, then the client.
	if count := conns.Load(); count != 2 {
		t.Errorf("run: the remote saw %d connections, want 2", count)
	}
	for _, want := range []string{"[listening]", "[connect]"} {
		if !strings.Contains(lines, want) {
			t.Errorf("run: the %s line is missing: got %q", want, lines)
		}
	}
	if strings.Contains(lines, "[error]") {
		t.Errorf("run: a clean session reported an error: got %q", lines)
	}
}

func TestRunSilent(t *testing.T) {
	host, port, shutdown, _ := testserver.TLS(t)
	defer shutdown()

	local := testserver.FreePort(t)
	tun := &sclient.Tunnel{
		RemoteAddress:      host,
		RemotePort:         port,
		LocalAddress:       "127.0.0.1",
		LocalPort:          local.Port,
		InsecureSkipVerify: true,
	}

	lines, err := runSession(t, tun, true)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if lines != "" {
		t.Errorf("run --silent: got %q, want nothing", lines)
	}
}

func TestRunBindFailure(t *testing.T) {
	host, port, shutdown, _ := testserver.TLS(t)
	defer shutdown()

	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupied port: %v", err)
	}
	defer taken.Close()

	addr := taken.Addr().(*net.TCPAddr)
	tun := &sclient.Tunnel{
		RemoteAddress:      host,
		RemotePort:         port,
		LocalAddress:       "127.0.0.1",
		LocalPort:          addr.Port,
		InsecureSkipVerify: true,
	}

	var out bytes.Buffer
	cfg := MainConfig{stderr: &out}
	if err := cfg.run(context.Background(), tun); err == nil {
		t.Error("run: binding an occupied port returned nil")
	}
}

func TestRunStdio(t *testing.T) {
	host, port, shutdown, conns := testserver.TLS(t)
	defer shutdown()

	inRead, inWrite, err := os.Pipe()
	if err != nil {
		t.Fatalf("stdio: pipe: %v", err)
	}
	payloadRead, payloadWrite, err := os.Pipe()
	if err != nil {
		t.Fatalf("stdio: pipe: %v", err)
	}

	oldIn, oldOut := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = inRead, payloadWrite
	defer func() { os.Stdin, os.Stdout = oldIn, oldOut }()

	_, _ = inWrite.Write([]byte(request))
	_ = inWrite.Close()

	tun := &sclient.Tunnel{
		RemoteAddress:      host,
		RemotePort:         port,
		LocalAddress:       "-",
		InsecureSkipVerify: true,
	}

	var diag bytes.Buffer
	cfg := MainConfig{stderr: &diag}
	if err := cfg.run(context.Background(), tun); err != nil {
		t.Fatalf("run stdio: %v", err)
	}

	_ = payloadWrite.Close()
	payload, err := io.ReadAll(payloadRead)
	if err != nil {
		t.Fatalf("run stdio: read payload: %v", err)
	}
	if string(payload) != testserver.Reply {
		t.Errorf("run stdio: payload is %q, want %q", string(payload), testserver.Reply)
	}
	if !strings.Contains(diag.String(), "(connected to") {
		t.Errorf("run stdio: the progress line is missing: got %q", diag.String())
	}
	// One session, one dial: stdio never probes.
	if count := conns.Load(); count != 1 {
		t.Errorf("run stdio: the remote saw %d connections, want 1", count)
	}
}

func TestDisplayAddr(t *testing.T) {
	cases := []struct {
		addr net.Addr
		want string
	}{
		{&net.TCPAddr{IP: net.IPv6loopback, Port: 3000}, "localhost:3000"},
		{&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 3000}, "localhost:3000"},
		{&net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 3000}, "192.0.2.1:3000"},
	}
	for _, c := range cases {
		if got := displayAddr(c.addr); got != c.want {
			t.Errorf("displayAddr(%s): got %q, want %q", c.addr, got, c.want)
		}
	}
}

// A bare number is a port on localhost; a bare host is not a listener.
func TestLocalAddr(t *testing.T) {
	cases := []struct {
		in   string
		host string
		port int
		err  bool
	}{
		{"3000", "localhost", 3000, false},
		{"[::1]:3000", "::1", 3000, false},
		{"localhost", "", 0, true},
		{"[::1]", "", 0, true},
		{"3000x", "", 0, true},
		{"", "", 0, true},
	}

	for _, c := range cases {
		host, port, err := localAddr(c.in)
		if c.err {
			if err == nil {
				t.Errorf("localAddr(%q): got %q:%d, want an error", c.in, host, port)
			}
			continue
		}
		if err != nil {
			t.Errorf("localAddr(%q): %v", c.in, err)
			continue
		}
		if host != c.host || port != c.port {
			t.Errorf("localAddr(%q): got %q:%d, want %q:%d", c.in, host, port, c.host, c.port)
		}
	}
}
