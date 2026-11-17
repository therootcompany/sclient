package main

import (
	"bytes"
	"flag"
	"slices"
	"strings"
	"testing"
)

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

func TestSSHMode(t *testing.T) {
	cases := []struct {
		name    string
		ssh     bool
		port    int
		named   bool
		want    int
		wantErr bool
	}{
		{"no flags: a plain TLS tunnel", false, 0, false, 0, false},
		{"--ssh means 22", true, 0, false, 22, false},
		{"naming the port is the mode", false, 2222, true, 2222, false},
		{"an explicit port beats --ssh", true, 2222, true, 2222, false},
		{"--ssh-port 0 is a mistake, not off", false, 0, true, 0, true},
		{"--ssh-port 70000 is not a port", false, 70000, true, 0, true},
	}
	for _, tc := range cases {
		got, err := sshMode(tc.ssh, tc.port, tc.named)
		if tc.wantErr {
			if err == nil {
				t.Errorf("%s: want an error, got port %d", tc.name, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
		}
		if got != tc.want {
			t.Errorf("%s: got %d, want %d", tc.name, got, tc.want)
		}
	}
}

func TestAlpnList(t *testing.T) {
	cases := []struct {
		raw      string
		explicit bool
		sshMode  bool
		want     []string
	}{
		{"", false, true, []string{"ssh"}}, // SSH mode defaults to ssh
		{"", false, false, nil},            // plain mode: sniff the local side
		{"", true, true, []string{}},       // an explicit empty list has no gate
		{"h2,http/1.1", true, true, []string{"h2", "http/1.1"}},
		{"ssh", true, false, []string{"ssh"}},
	}
	for _, tc := range cases {
		got := alpnList(tc.raw, tc.explicit, tc.sshMode)
		if !slices.Equal(got, tc.want) {
			t.Errorf("alpnList(%q, explicit=%v, ssh=%v) = %q, want %q", tc.raw, tc.explicit, tc.sshMode, got, tc.want)
		}
	}
}
