package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/therootcompany/sclient"
	"github.com/therootcompany/sclient/internal/testserver"
)

// A stdio session with no usable server prints the report, spoken by this command.
func TestRunStdioNoServer(t *testing.T) {
	tlsPort := testserver.SSHEcho(t, "SSH-2.0-OpenSSH_9.6 host:other.example.net", "", "ssh", true)
	sshPort := testserver.SSHEcho(t, "SSH-2.0-OpenSSH_9.6 host:other.example.net", "", "", false)

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

	tun := &sclient.Tunnel{
		RemoteAddress:      "localhost",
		RemotePort:         tlsPort,
		SSHPort:            sshPort,
		LocalAddress:       "-",
		NextProtos:         []string{"ssh"},
		InsecureSkipVerify: true,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var diag bytes.Buffer
	cfg := MainConfig{stderr: &diag}
	done := make(chan error, 1)
	go func() { done <- cfg.run(ctx, tun) }()

	err = <-done
	if !errors.Is(err, sclient.ErrNoServer) {
		t.Fatalf("run: got %v, want ErrNoServer", err)
	}
	if diag.Len() != 0 {
		t.Errorf("a failed session wrote %q to the diagnostics writer, want nothing", diag.String())
	}

	// main() prints what run() returns, in this command's own name.
	report := report(err)
	if !strings.HasPrefix(report, "ssh-tls-proxy: localhost: no usable server\n") {
		t.Errorf("report = %q, want the header spoken by this command", report)
	}
	if !strings.Contains(report, `Connection closed by "localhost"`) {
		t.Errorf("report = %q, want ssh's closing line for a piped session", report)
	}

	_ = outWrite.Close()
	if got, err := io.ReadAll(outRead); err == nil && len(got) != 0 {
		t.Errorf("stdio: a failed session wrote %q to stdout, want nothing", got)
	}
}

func TestRunStdio(t *testing.T) {
	tlsPort := testserver.SSHEcho(t, "SSH-2.0-tls-server", "", "ssh", true)
	sshPort := testserver.SSHEcho(t, "SSH-2.0-plain-server", "", "", false)

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

	tun := &sclient.Tunnel{
		RemoteAddress:      "localhost",
		RemotePort:         tlsPort,
		SSHPort:            sshPort,
		LocalAddress:       "-",
		NextProtos:         []string{"ssh"},
		InsecureSkipVerify: true,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	cfg := MainConfig{stderr: io.Discard, silent: true}
	done := make(chan error, 1)
	go func() { done <- cfg.run(ctx, tun) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("run: the session never ended")
	}

	_ = outWrite.Close()
	got, err := io.ReadAll(outRead)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.HasPrefix(string(got), "SSH-2.0-tls-server\r\n") || !strings.Contains(string(got), "GOODBYE") {
		t.Errorf("the ssh client saw %q, want the TLS banner then GOODBYE", string(got))
	}
}

// --listen binds a port and serves one session per connection.
func TestRunListen(t *testing.T) {
	tlsPort := testserver.SSHEcho(t, "SSH-2.0-tls-server", "", "ssh", true)
	sshPort := testserver.SSHEcho(t, "SSH-2.0-plain-server", "", "", false)

	local := testserver.FreePort(t)
	tun := &sclient.Tunnel{
		RemoteAddress:      "localhost",
		RemotePort:         tlsPort,
		SSHPort:            sshPort,
		LocalAddress:       "127.0.0.1",
		LocalPort:          local.Port,
		NextProtos:         []string{"ssh"},
		InsecureSkipVerify: true,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var out bytes.Buffer
	cfg := MainConfig{stderr: &out, silent: true}
	done := make(chan error, 1)
	go func() { done <- cfg.run(ctx, tun) }()

	conn, err := testserver.Dial(t, tun.Local())
	if err != nil {
		t.Fatalf("connect to the local listener: %v", err)
	}
	defer conn.Close()

	_, _ = fmt.Fprintf(conn, "SSH-2.0-client\r\nBYE\r\n")

	_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.HasPrefix(string(got), "SSH-2.0-tls-server") {
		t.Errorf("the ssh client saw %q, want the TLS server's banner", string(got))
	}

	cancel()
	if err := <-done; err != nil {
		t.Errorf("run: %v", err)
	}
}
