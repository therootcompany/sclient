package main

import (
	"bytes"
	"crypto/tls"
	"net"
	"slices"
	"sync"
	"testing"
	"time"
)

// signalWriter records writes and closes sig once the first write
// completes: the probe's failure report is a single Fprint, so the
// signal means the report is fully in the buffer.
type signalWriter struct {
	buf  bytes.Buffer
	sig  chan struct{}
	once sync.Once
}

func (s *signalWriter) Write(p []byte) (int, error) {
	n, err := s.buf.Write(p)
	s.once.Do(func() { close(s.sig) })
	return n, err
}

func TestSSHALPN(t *testing.T) {
	cases := []struct {
		name     string
		raw      string
		explicit bool
		want     []string
	}{
		{"unset takes ssh", "", false, []string{"ssh"}},
		{"explicit empty means no requirement", "", true, []string{}},
		{"explicit list", "h2,http/1.1", true, []string{"h2", "http/1.1"}},
		{"comma list", "ssh, ssh-tls", false, []string{"ssh", "ssh-tls"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sshALPN(tc.raw, tc.explicit)
			if !slices.Equal(got, tc.want) {
				t.Fatalf("sshALPN(%q, %v) = %v, want %v", tc.raw, tc.explicit, got, tc.want)
			}
		})
	}
}

func TestNewSSHConfigDefaults(t *testing.T) {
	cfg, err := newSSHConfig("example.com", "", []string{"ssh"}, false, false, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Name != "sclient" {
		t.Errorf("Name = %q, want sclient", cfg.Name)
	}
	if cfg.Host != "example.com" || cfg.TLSPort != 443 || cfg.SSHPort != 0 {
		t.Errorf("Host/TLSPort/SSHPort = %s %d %d, want example.com 443 0 (engine default 22)", cfg.Host, cfg.TLSPort, cfg.SSHPort)
	}
	if cfg.Timeout != 0 {
		t.Errorf("Timeout = %v, want 0 (engine default 3s)", cfg.Timeout)
	}
	if cfg.TLS == nil {
		t.Fatal("TLS is nil; the caller config must carry the defaults")
	}
	if cfg.TLS.ServerName != "example.com" {
		t.Errorf("ServerName = %q, want example.com", cfg.TLS.ServerName)
	}
	if cfg.TLS.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %x, want TLS 1.2", cfg.TLS.MinVersion)
	}
	if !slices.Equal(cfg.TLS.NextProtos, []string{"ssh"}) {
		t.Errorf("NextProtos = %v, want [ssh]", cfg.TLS.NextProtos)
	}
}

func TestNewSSHConfigPorts(t *testing.T) {
	cfg, err := newSSHConfig("example.com:8443", "", []string{"ssh"}, false, false, 2222, 2.5)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TLSPort != 8443 || cfg.SSHPort != 2222 || cfg.Timeout != 2500*time.Millisecond {
		t.Errorf("TLSPort/SSHPort/Timeout = %d %d %v, want 8443 2222 2.5s", cfg.TLSPort, cfg.SSHPort, cfg.Timeout)
	}
}

func TestNewSSHConfigIPv6(t *testing.T) {
	cfg, err := newSSHConfig("[2001:db8::1]:8443", "", []string{"ssh"}, false, false, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Host != "2001:db8::1" || cfg.TLSPort != 8443 {
		t.Errorf("Host/TLSPort = %s %d, want 2001:db8::1 8443", cfg.Host, cfg.TLSPort)
	}
}

func TestNewSSHConfigErrors(t *testing.T) {
	for _, bad := range []string{"example.com:abc", "example.com:0", "example.com:70000", ""} {
		if _, err := newSSHConfig(bad, "", []string{"ssh"}, false, false, 0, 0); err == nil {
			t.Errorf("newSSHConfig(%q): expected an error", bad)
		}
	}
}

// freePort returns a TCP port on loopback that is (just) not listening.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

// The listener mode: a local SSH client hitting a host where neither
// port answers gets EOF and the report lands on the probe's errOut.
// Fully offline: both target ports are refused on loopback.
func TestSSHListenerNoServer(t *testing.T) {
	cfg, err := newSSHConfig("127.0.0.1", "", []string{"ssh"}, false, false, freePort(t), 0)
	if err != nil {
		t.Fatal(err)
	}
	cfg.TLSPort = freePort(t)
	cfg.Timeout = 2 * time.Second

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var sw signalWriter
	sw.sig = make(chan struct{})
	go sshListen(cfg, ln, &sw)

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("SSH-2.0-e2e\r\n")); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected EOF from a dead target, got data")
	}

	// Wait for the report write to complete, then read the buffer:
	// channel sync, no race on the buffer itself.
	select {
	case <-sw.sig:
	case <-time.After(5 * time.Second):
		t.Fatal("no report written")
	}
	if !bytes.Contains(sw.buf.Bytes(), []byte("no usable server")) {
		t.Fatalf("report = %q, want a 'no usable server' block", sw.buf.String())
	}
}
