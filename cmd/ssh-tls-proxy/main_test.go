package main

import (
	"strings"
	"testing"
	"time"
)

// --tcp-timeout, --tls-timeout, --alpn and --insecure are post-processed into
// the config, so parsing them has to be checked end to end: an earlier version
// silently kept the defaults and ignored every one of them.
func TestParseArgsHonoursFlags(t *testing.T) {
	cfg, _, ok := parseArgs([]string{"--tcp-timeout", "5", "--alpn", "", "--ssh-port", "2222", "example.com"})
	if !ok {
		t.Fatal("parseArgs rejected a valid argument list")
	}
	if cfg.TCPTimeout != 5*time.Second {
		t.Errorf("tcp-timeout = %v, want 5s", cfg.TCPTimeout)
	}
	if len(cfg.ALPN) != 0 {
		t.Errorf("alpn = %v, want the empty list", cfg.ALPN)
	}
	// explicit --alpn '' is "no ALPN requirement", not "use the default"
	if cfg.ALPN == nil {
		t.Error("explicit --alpn '' must be a non-nil empty list, not the nil default")
	}
	if cfg.SSHPort != 2222 {
		t.Errorf("sshPort = %d, want 2222", cfg.SSHPort)
	}
	if cfg.Host != "example.com" {
		t.Errorf("host = %q, want example.com", cfg.Host)
	}
}

// An env var fills a flag only when the flag is absent.
func TestParseArgsEnvDoesNotOverrideFlags(t *testing.T) {
	t.Setenv("SSHTLSPROXY_TLS_TIMEOUT", "7")

	cfg, _, ok := parseArgs([]string{"--tls-timeout", "2", "example.com"})
	if !ok {
		t.Fatal("parseArgs rejected a valid argument list")
	}
	if cfg.TLSTimeout != 2*time.Second {
		t.Errorf("tls-timeout = %v, want the flag's 2s, not the env's 7s", cfg.TLSTimeout)
	}

	cfg, _, ok = parseArgs([]string{"example.com"})
	if !ok {
		t.Fatal("parseArgs rejected a valid argument list")
	}
	if cfg.TLSTimeout != 7*time.Second {
		t.Errorf("tls-timeout = %v, want the env's 7s", cfg.TLSTimeout)
	}
}

// A comma-separated ALPN list parses the way sclient's does.
func TestParseArgsAlpnList(t *testing.T) {
	want := []string{"ssh", "ssh-tls", "http/1.1"}
	cfg, tlsCfg, ok := parseArgs([]string{"--alpn", strings.Join(want, ","), "example.com"})
	if !ok {
		t.Fatal("parseArgs rejected a valid ALPN list")
	}
	if len(cfg.ALPN) != len(want) || cfg.ALPN[0] != "ssh" || cfg.ALPN[len(want)-1] != "http/1.1" {
		t.Errorf("alpn = %v, want %v", cfg.ALPN, want)
	}
	if len(tlsCfg.NextProtos) != len(want) {
		t.Errorf("next protos = %v, want %v", tlsCfg.NextProtos, want)
	}
}

// Zero is "the default", not "no limit": the engine fills in 5s and 45s. A
// negative clock is a usage error, and the env fills in only unset flags.
func TestParseArgsClocks(t *testing.T) {
	cfg, _, ok := parseArgs([]string{"example.com"})
	if !ok {
		t.Fatal("parseArgs rejected a bare host")
	}
	if cfg.TCPTimeout != 0 || cfg.TLSTimeout != 0 {
		t.Errorf("clocks = %v/%v, want 0/0 (the engine fills in 5s/45s)", cfg.TCPTimeout, cfg.TLSTimeout)
	}

	cfg, _, ok = parseArgs([]string{"--tcp-timeout", "2", "--tls-timeout", "30", "example.com"})
	if !ok {
		t.Fatal("parseArgs rejected the clocks")
	}
	if cfg.TCPTimeout != 2*time.Second || cfg.TLSTimeout != 30*time.Second {
		t.Errorf("clocks = %v/%v, want 2s/30s", cfg.TCPTimeout, cfg.TLSTimeout)
	}

	if _, _, ok := parseArgs([]string{"--tcp-timeout", "-1", "example.com"}); ok {
		t.Error("a negative connect clock must be rejected")
	}

	t.Setenv("SSHTLSPROXY_TLS_TIMEOUT", "20")
	cfg, _, ok = parseArgs([]string{"example.com"})
	if !ok || cfg.TLSTimeout != 20*time.Second {
		t.Errorf("env clock = %v, want 20s", cfg.TLSTimeout)
	}
	cfg, _, ok = parseArgs([]string{"--tls-timeout", "5", "example.com"})
	if !ok || cfg.TLSTimeout != 5*time.Second {
		t.Errorf("the flag must beat the env: %v, want 5s", cfg.TLSTimeout)
	}
}
