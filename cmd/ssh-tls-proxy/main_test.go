package main

import (
	"bytes"
	"flag"
	"slices"
	"strings"
	"testing"
)

// The stamp appears once, and the positional form is spelled out. Splitting an
// address is internal/cli's job and is tested there.
func TestUsagePrintsStampOnce(t *testing.T) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.Usage = func() { usage(fs) }

	var out bytes.Buffer
	fs.SetOutput(&out)
	fs.Usage()

	if got := strings.Count(out.String(), stamp.String()); got != 1 {
		t.Errorf("usage printed the stamp %d times, want 1", got)
	}
	if !strings.Contains(out.String(), "USAGE: "+name+" [flags] <host>[:tls-port]") {
		t.Errorf("usage = %q, want the positional form", out.String())
	}
}

// A port on the positional address names the TLS side; without one the flag's
// default stands.
func TestHostAndPort(t *testing.T) {
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
		{"::1:443", "", 0, true},
	}
	for _, tc := range cases {
		host, port, err := hostAndPort(tc.addr)
		if tc.wantErr {
			if err == nil {
				t.Errorf("hostAndPort(%q): got no error, want one", tc.addr)
			}
			continue
		}
		if err != nil {
			t.Errorf("hostAndPort(%q): %v", tc.addr, err)
			continue
		}
		if host != tc.wantHost || port != tc.wantPort {
			t.Errorf("hostAndPort(%q) = %q, %d; want %q, %d", tc.addr, host, port, tc.wantHost, tc.wantPort)
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
