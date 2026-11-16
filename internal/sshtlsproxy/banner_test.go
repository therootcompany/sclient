package sshtlsproxy

import (
	"bufio"
	"io"
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
