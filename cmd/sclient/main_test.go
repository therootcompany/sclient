package main

import (
	"bytes"
	"flag"
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
