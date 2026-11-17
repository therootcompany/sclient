package main

import (
	"bytes"
	"flag"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestUsagePrintsVersionOnce(t *testing.T) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.Usage = func() { usage(fs) }

	var out bytes.Buffer
	fs.SetOutput(&out)
	fs.Usage()

	if got := strings.Count(out.String(), version); got != 1 {
		t.Errorf("usage printed the version %d times, want once", got)
	}
	if !strings.Contains(out.String(), "USAGE: "+name) {
		t.Errorf("usage = %q, want the USAGE line", out.String())
	}
}

func TestHostPort(t *testing.T) {
	cases := []struct {
		addr     string
		wantHost string
		wantPort int
		wantErr  bool
	}{
		{"example.com", "example.com", 0, false},
		{"example.com:8443", "example.com", 8443, false},
		{"[::1]", "::1", 0, false},
		{"[::1]:443", "::1", 443, false},
		{"", "", 0, true},
		{"::1:443", "", 0, true}, // ambiguous: an IPv6 with a port needs brackets
		{"example.com:x", "", 0, true},
	}
	for _, tc := range cases {
		host, port, err := hostPort(tc.addr)
		if tc.wantErr {
			if err == nil {
				t.Errorf("hostPort(%q): got no error, want one", tc.addr)
			}
			continue
		}
		if err != nil {
			t.Errorf("hostPort(%q): %v", tc.addr, err)
			continue
		}
		if host != tc.wantHost || port != tc.wantPort {
			t.Errorf("hostPort(%q) = %q, %d; want %q, %d", tc.addr, host, port, tc.wantHost, tc.wantPort)
		}
	}
}

// The default offers "ssh"; only an explicit empty list turns the gate off.
func TestAlpnList(t *testing.T) {
	cases := []struct {
		raw  string
		want []string
	}{
		{"ssh", []string{"ssh"}},
		{"h2,http/1.1", []string{"h2", "http/1.1"}},
		{"h2 http/1.1", []string{"h2", "http/1.1"}},
		{"", []string{}},
	}
	for _, tc := range cases {
		if got := alpnList(tc.raw); !slices.Equal(got, tc.want) {
			t.Errorf("alpnList(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

func TestCheckPort(t *testing.T) {
	for _, port := range []int{1, 22, 443, 65535} {
		if err := checkPort("tls-port", port); err != nil {
			t.Errorf("checkPort(%d): %v", port, err)
		}
	}
	for _, port := range []int{0, -1, 65536} {
		if err := checkPort("tls-port", port); err == nil {
			t.Errorf("checkPort(%d): got no error, want one", port)
		}
	}
}

func TestSeconds(t *testing.T) {
	if got := seconds(0); got != 0 {
		t.Errorf("seconds(0) = %v, want 0 (auto)", got)
	}
	if got := seconds(2.5); got != 2500*time.Millisecond {
		t.Errorf("seconds(2.5) = %v, want 2.5s", got)
	}
	if got := seconds(-1); got != 0 {
		t.Errorf("seconds(-1) = %v, want 0 (auto)", got)
	}
}
