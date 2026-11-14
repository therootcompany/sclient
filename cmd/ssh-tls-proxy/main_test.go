package main

import (
	"strings"
	"testing"
	"time"
)

// --timeout, --alpn and --insecure are post-processed into the config, so
// parsing them has to be checked end to end: an earlier version silently kept
// the defaults and ignored every one of them.
func TestParseArgsHonoursFlags(t *testing.T) {
	cfg, _, ok := parseArgs([]string{"--timeout", "5", "--alpn", "", "--ssh-port", "2222", "example.com"})
	if !ok {
		t.Fatal("parseArgs rejected a valid argument list")
	}
	if cfg.Timeout != 5*time.Second {
		t.Errorf("timeout = %v, want 5s", cfg.Timeout)
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
	t.Setenv("SSHTLSPROXY_TIMEOUT", "7")

	cfg, _, ok := parseArgs([]string{"--timeout", "2", "example.com"})
	if !ok {
		t.Fatal("parseArgs rejected a valid argument list")
	}
	if cfg.Timeout != 2*time.Second {
		t.Errorf("timeout = %v, want the flag's 2s, not the env's 7s", cfg.Timeout)
	}

	cfg, _, ok = parseArgs([]string{"example.com"})
	if !ok {
		t.Fatal("parseArgs rejected a valid argument list")
	}
	if cfg.Timeout != 7*time.Second {
		t.Errorf("timeout = %v, want the env's 7s", cfg.Timeout)
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
