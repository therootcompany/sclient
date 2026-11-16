package sshtlsproxy

import (
	"bufio"
	"io"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestReadBanner(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"crlf", "SSH-2.0-OpenSSH_10.5\r\n", "SSH-2.0-OpenSSH_10.5"},
		{"lf", "SSH-2.0-OpenSSH_10.5\n", "SSH-2.0-OpenSSH_10.5"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := bufio.NewReader(strings.NewReader(tc.input))
			banner, err := readBanner(r)
			if err != nil {
				t.Fatalf("readBanner: %v", err)
			}
			if banner != tc.want {
				t.Errorf("banner = %q, want %q", banner, tc.want)
			}
		})
	}
}

func TestReadBannerTooLong(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("SSH-" + strings.Repeat("x", 253) + "\r\n"))
	if _, err := readBanner(r); err == nil {
		t.Fatal("expected error for 256-byte banner")
	}
}

// A peer that never sends a newline hits the RFC limit rather than
// buffering forever: the read is bounded, not just the result checked.
func TestReadBannerBounded(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("SSH-" + strings.Repeat("x", 4096)))
	if _, err := readBanner(r); err == nil {
		t.Fatal("expected a too-long error for a newline-less banner")
	}
}

func TestReadBannerNotSSH(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("HTTP/1.1 200 OK\r\n"))
	if _, err := readBanner(r); err == nil {
		t.Fatal("expected error for non-SSH banner")
	}
}

// Bytes arriving in the same segment as the banner (a glued KEXINIT) must
// survive in the reader for the caller to relay.
func TestReadBannerReadAhead(t *testing.T) {
	const kex = "KEXINIT-PAYLOAD"
	r := bufio.NewReader(strings.NewReader("SSH-2.0-x\r\n" + kex))
	if _, err := readBanner(r); err != nil {
		t.Fatalf("readBanner: %v", err)
	}
	rest, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read rest: %v", err)
	}
	if string(rest) != kex {
		t.Errorf("read-ahead = %q, want %q", rest, kex)
	}
}

// RFC 4253 section 4.2: everything after the protocol version is a comment.
// A front can name itself there; a banner that names no host declares nothing.
func TestDeclaredHosts(t *testing.T) {
	tests := []struct {
		banner string
		want   []string
	}{
		{"SSH-2.0-OpenSSH_10.5", nil},
		{"SSH-2.0-OpenSSH_9.6p1 tlsrouter-v0.9.4-2eeb5da", nil},
		{"SSH-2.0-OpenSSH_9.6 host:vms.example.com", []string{"vms.example.com"}},
		{"SSH-2.0-OpenSSH_9.6 tlsrouter-v0.9.4 host:vms.example.com", []string{"vms.example.com"}},
		{"SSH-2.0-x hostname:a.example.com,b.example.com", []string{"a.example.com", "b.example.com"}},
		{"SSH-2.0-x HOST:vms.example.com", []string{"vms.example.com"}},
		{"SSH-2.0-x host:", nil},
		{"SSH-2.0-x myhost:vms.example.com", nil}, // not a host: field
		{"SSH-2.0-x host:vms.example.com,", []string{"vms.example.com"}},
		{"SSH-2.0-x hostname:vms.example.com host:web1.internal", []string{"vms.example.com", "web1.internal"}},
	}
	for _, tc := range tests {
		got := declaredHosts(tc.banner)
		if len(got) != len(tc.want) {
			t.Errorf("declaredHosts(%q) = %v, want %v", tc.banner, got, tc.want)
			continue
		}
		if !slices.Equal(got, tc.want) {
			t.Errorf("declaredHosts(%q) = %v, want %v", tc.banner, got, tc.want)
		}
	}
}

// A declared host that is not the name we asked for is a different server;
// a banner that declares nothing is no evidence either way.
func TestBannerMismatch(t *testing.T) {
	tests := []struct {
		want   string
		banner string
		want_  string
	}{
		{"guest.example.com", "SSH-2.0-OpenSSH_9.6", ""},
		{"guest.example.com", "SSH-2.0-OpenSSH_9.6 tlsrouter-v0.9.4 host:guest.example.com", ""},
		{"guest.example.com", "SSH-2.0-x host:vms.example.com,guest.example.com", ""},
		{"Guest.example.com", "SSH-2.0-x HOST:guest.example.com", ""},
		{"guest.example.com", "SSH-2.0-x tlsrouter-v0.9.4 host:vms.example.com",
			`banner "SSH-2.0-x tlsrouter-v0.9.4 host:vms.example.com" declares vms.example.com, not "guest.example.com"`},
		{"", "SSH-2.0-x host:vms.example.com", ""},          // no name asked: nothing to match
		{"192.0.2.1", "SSH-2.0-x host:vms.example.com", ""}, // an IP is not contradicted by names
	}
	for _, tc := range tests {
		if got := bannerMismatch(tc.want, tc.banner); got != tc.want_ {
			t.Errorf("bannerMismatch(%q, %q) = %q, want %q", tc.want, tc.banner, got, tc.want_)
		}
	}
}

func TestGraceFor(t *testing.T) {
	tests := []struct {
		elapsed time.Duration
		want    time.Duration
	}{
		{0, minGrace},
		{100 * time.Millisecond, minGrace},
		{300 * time.Millisecond, 150 * time.Millisecond},
		{400 * time.Millisecond, 200 * time.Millisecond},
		{3 * time.Second, 1500 * time.Millisecond},
	}
	for _, tc := range tests {
		if got := graceFor(tc.elapsed); got != tc.want {
			t.Errorf("graceFor(%v) = %v, want %v", tc.elapsed, got, tc.want)
		}
	}
}
