package cli

import (
	"slices"
	"testing"
	"time"
)

func TestSplitHostPort(t *testing.T) {
	cases := []struct {
		addr    string
		host    string
		port    string
		hasPort bool
		err     bool
	}{
		{"example.com", "example.com", "", false, false},
		{" example.com ", "example.com", "", false, false},
		{"example.com:8443", "example.com", "8443", true, false},
		{"[::1]", "::1", "", false, false},
		{"[::1]:3000", "::1", "3000", true, false},
		{"2001:db8::1", "", "", false, true}, // an unbracketed IPv6 is ambiguous
		{"::1:443", "", "", false, true},     // an IPv6 with a port needs brackets
		{"2001:db8::1:443", "", "", false, true},
		{"example.com:99999", "example.com", "99999", true, false}, // the range is ParsePort's job
		{"", "", "", false, true},
	}
	for _, tc := range cases {
		host, port, hasPort, err := SplitHostPort(tc.addr)
		if tc.err {
			if err == nil {
				t.Errorf("SplitHostPort(%q): got %q, want an error", tc.addr, host)
			}
			continue
		}
		if err != nil {
			t.Errorf("SplitHostPort(%q): %v", tc.addr, err)
			continue
		}
		if host != tc.host || port != tc.port || hasPort != tc.hasPort {
			t.Errorf("SplitHostPort(%q) = %q, %q, %v; want %q, %q, %v",
				tc.addr, host, port, hasPort, tc.host, tc.port, tc.hasPort)
		}
	}
}

func TestParsePort(t *testing.T) {
	cases := []struct {
		raw  string
		want int
	}{
		{"1", 1},
		{"22", 22},
		{"443", 443},
		{"65535", 65535},
		{"0", 0},
		{"-1", 0},
		{"65536", 0},
		{"3000x", 0},
		{"", 0},
	}
	for _, tc := range cases {
		port, err := ParsePort(tc.raw)
		if tc.want == 0 {
			if err == nil {
				t.Errorf("ParsePort(%q): got %d, want an error", tc.raw, port)
			}
			continue
		}
		if port != tc.want {
			t.Errorf("ParsePort(%q) = %d, want %d", tc.raw, port, tc.want)
		}
	}
}

func TestPortOf(t *testing.T) {
	if err := PortOf("tls-port", 443); err != nil {
		t.Errorf("PortOf(443): %v", err)
	}
	for _, port := range []int{0, -1, 65536} {
		if err := PortOf("tls-port", port); err == nil {
			t.Errorf("PortOf(%d): got no error, want one", port)
		}
	}
}

func TestSeconds(t *testing.T) {
	cases := []struct {
		raw  float64
		want time.Duration
	}{
		{0, 0},
		{-1, 0},
		{2.5, 2500 * time.Millisecond},
		{1, time.Second},
	}
	for _, tc := range cases {
		if got := Seconds(tc.raw); got != tc.want {
			t.Errorf("Seconds(%v) = %v, want %v", tc.raw, got, tc.want)
		}
	}
}

func TestOptions(t *testing.T) {
	cases := []struct {
		raw  string
		want []string
	}{
		{"", nil},
		{"  ", nil},
		{"ssh", []string{"ssh"}},
		{"h2,http/1.1", []string{"h2", "http/1.1"}},
		{"h2 http/1.1", []string{"h2", "http/1.1"}},
		{"h2, http/1.1", []string{"h2", "http/1.1"}},
	}
	for _, tc := range cases {
		if got := Options(tc.raw); !slices.Equal(got, tc.want) {
			t.Errorf("Options(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

// The stamp is what a release build prints: the tag without its "v", a short
// commit, and a bare date.
func TestStamp(t *testing.T) {
	got := Stamp("sclient", "v1.5.1", "e656990deadbeef", "2026-11-17T10:15:02Z")
	want := Version{Name: "sclient", Version: "1.5.1", Commit: "e656990", Date: "2026-11-17"}
	if got != want {
		t.Errorf("Stamp = %q, want %q", got.String(), want.String())
	}

	// Nothing stamped: the defaults are honest placeholders, never an empty line.
	blank := Stamp("ssh-tls-proxy", "", "", "")
	if blank.Version == "" || blank.Commit == "" || blank.Date == "" {
		t.Errorf("Stamp with no build info = %q", blank.String())
	}
	if blank.Name != "ssh-tls-proxy" {
		t.Errorf("Stamp name = %q, want the command", blank.Name)
	}
}
