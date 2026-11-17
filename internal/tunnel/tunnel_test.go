package tunnel

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// A fast dial is 40ms. Rounding to 10ms printed "0s", which says nothing.
func TestElapsedText(t *testing.T) {
	cases := []struct {
		in   time.Duration
		want string
	}{
		{900 * time.Millisecond, "900ms"},
		{1200 * time.Millisecond, "1.2s"},
		{40 * time.Millisecond, "40ms"},
		{400 * time.Microsecond, "0ms"},
		{600 * time.Microsecond, "1ms"},
		{0, "0ms"},
	}
	for _, c := range cases {
		if got := ElapsedText(c.in); got != c.want {
			t.Errorf("ElapsedText(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

// DisplayAddr prints loopback as localhost.
func TestDisplayAddr(t *testing.T) {
	cases := []struct {
		addr net.Addr
		want string
	}{
		{&net.TCPAddr{IP: net.IPv6loopback, Port: 3000}, "localhost:3000"},
		{&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 3000}, "localhost:3000"},
		{&net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 3000}, "192.0.2.1:3000"},
	}
	for _, c := range cases {
		if got := DisplayAddr(c.addr); got != c.want {
			t.Errorf("DisplayAddr(%s): got %q, want %q", c.addr, got, c.want)
		}
	}
}

// Canceling ctx hangs up on both sides of a session that is still open, and the
// closed connections are a clean ending, not an error.
func TestPipeContextEndsOnCancel(t *testing.T) {
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- PipeContext(ctx, local, remote) }()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("PipeContext: got %v, want nil", err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("PipeContext: canceling the context did not end the session")
	}

	if _, err := local.Read(make([]byte, 1)); err == nil {
		t.Error("PipeContext: the local side stayed open after cancel")
	}
}

// 0 means 3x the connect, floored at 150ms; an explicit timeout wins.
func TestHandshakeDeadline(t *testing.T) {
	cases := []struct {
		tlsTimeout time.Duration
		connect    time.Duration
		want       time.Duration
	}{
		{0, time.Millisecond, minHandshakeDeadline},                   // auto, floored
		{0, 100 * time.Millisecond, 300 * time.Millisecond},           // auto, 3x the connect
		{300 * time.Millisecond, time.Second, 300 * time.Millisecond}, // explicit wins
		{-1, time.Second, 3 * time.Second},                            // nonsense falls back
	}
	for _, c := range cases {
		d := Dial{TLSTimeout: c.tlsTimeout}
		if got := d.HandshakeDeadline(c.connect); got != c.want {
			t.Errorf("HandshakeDeadline(timeout %s, connect %s): got %s, want %s",
				c.tlsTimeout, c.connect, got, c.want)
		}
	}
}

// A server that accepts the connection but never handshakes must time out.
func TestDialHonorsTLSDeadline(t *testing.T) {
	blackhole, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("blackhole: %v", err)
	}
	defer blackhole.Close()

	addr := blackhole.Addr().String()
	for _, d := range []Dial{
		{ServerName: "localhost"},                                     // auto: the 150ms floor
		{ServerName: "localhost", TLSTimeout: 100 * time.Millisecond}, // explicit
	} {
		start := time.Now()
		conn, err := d.DialTLS(context.Background(), addr, nil, nil)
		elapsed := time.Since(start)
		if err == nil {
			_ = conn.Close()
			t.Fatalf("DialTLS(%s): the handshake never timed out", addr)
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("DialTLS: got %v, want a deadline exceeded", err)
		}
		// The handshake deadline fired, not the 5s connect default.
		if elapsed > time.Second {
			t.Errorf("DialTLS: took %s, want well under the %s connect default",
				ElapsedText(elapsed), defaultTCPDeadline)
		}
	}
}
