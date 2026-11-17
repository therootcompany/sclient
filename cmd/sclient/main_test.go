package main

import (
	"bytes"
	"flag"
	"slices"
	"strings"
	"testing"
)

// The stamp appears once, whichever stream usage is written to. Address parsing
// and port ranges are internal/cli's job and are tested there.
func TestUsagePrintsStampOnce(t *testing.T) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.Usage = func() { usage(fs) }

	var out bytes.Buffer
	fs.SetOutput(&out)
	fs.Usage()

	if got := strings.Count(out.String(), stamp.String()); got != 1 {
		t.Errorf("usage printed the stamp %d times, want 1", got)
	}
	if !strings.Contains(out.String(), "USAGE: "+name) {
		t.Errorf("usage = %q, want the USAGE line", out.String())
	}
}

// A bare remote takes the TLS port; a bare IPv6 keeps its default too.
func TestRemoteAddr(t *testing.T) {
	cases := []struct {
		in   string
		host string
		port int
		err  bool
	}{
		{"example.com", "example.com", 443, false},
		{"example.com:8443", "example.com", 8443, false},
		{"[::1]", "::1", 443, false},
		{"example.com:99999", "", 0, true},
		{"::1:443", "", 0, true},
	}
	for _, tc := range cases {
		host, port, err := remoteAddr(tc.in)
		if tc.err {
			if err == nil {
				t.Errorf("remoteAddr(%q): got %q:%d, want an error", tc.in, host, port)
			}
			continue
		}
		if err != nil {
			t.Errorf("remoteAddr(%q): %v", tc.in, err)
			continue
		}
		if host != tc.host || port != tc.port {
			t.Errorf("remoteAddr(%q) = %q:%d, want %q:%d", tc.in, host, port, tc.host, tc.port)
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
		{"localhost:3000", "localhost", 3000, false},
		{"[::1]:3000", "::1", 3000, false},
		{"localhost", "", 0, true},
		{"3000x", "", 0, true},
	}
	for _, tc := range cases {
		host, port, err := localAddr(tc.in)
		if tc.err {
			if err == nil {
				t.Errorf("localAddr(%q): got %q:%d, want an error", tc.in, host, port)
			}
			continue
		}
		if err != nil {
			t.Errorf("localAddr(%q): %v", tc.in, err)
			continue
		}
		if host != tc.host || port != tc.port {
			t.Errorf("localAddr(%q) = %q:%d, want %q:%d", tc.in, host, port, tc.host, tc.port)
		}
	}
}

// --ssh and --ssh-port: naming a port is the mode, --ssh is the shorthand for 22,
// and a named zero is a mistake rather than "off".
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
			t.Errorf("alpnList(%q, explicit %v, ssh %v) = %q, want %q",
				tc.raw, tc.explicit, tc.sshMode, got, tc.want)
		}
	}
}
