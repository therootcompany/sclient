package sclient

import (
	"bytes"
	"io"
	"testing"
	"time"
)

// The regression: a keep-alive remote waits for the end of the request. If the
// local pump does not half-close, pipe never returns.
func TestPipeEndsBothStreams(t *testing.T) {
	local := &stubConn{in: bytes.NewBufferString("GET / HTTP/1.1\r\n\r\n"), out: &bytes.Buffer{}}
	remote := &stubRemote{reply: "reply", ended: make(chan struct{})}

	done := make(chan error, 1)
	go func() { done <- pipe(local, remote) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("pipe: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("pipe: the reply never arrived, so the session hangs")
	}

	if got, want := remote.got.String(), "GET / HTTP/1.1\r\n\r\n"; got != want {
		t.Errorf("pipe: remote got %q, want %q", got, want)
	}
	if got, want := local.out.String(), "reply"; got != want {
		t.Errorf("pipe: local got %q, want %q", got, want)
	}
	if !remote.halfClosed {
		t.Error("pipe: remote not half-closed")
	}
	if !local.closed || !remote.closed {
		t.Error("pipe: a stream was left open")
	}
}

// stubConn is the local side: stdin in, stdout out.
type stubConn struct {
	in     *bytes.Buffer
	out    *bytes.Buffer
	closed bool
}

func (c *stubConn) Read(b []byte) (int, error)  { return c.in.Read(b) }
func (c *stubConn) Write(b []byte) (int, error) { return c.out.Write(b) }
func (c *stubConn) Close() error                { c.closed = true; return nil }

// stubRemote is a keep-alive remote: it answers only once the request is over.
type stubRemote struct {
	got        bytes.Buffer
	reply      string
	halfClosed bool
	ended      chan struct{}
	closed     bool
}

func (r *stubRemote) Read(b []byte) (int, error) {
	<-r.ended
	if r.reply == "" {
		return 0, io.EOF
	}
	n := copy(b, []byte(r.reply))
	r.reply = r.reply[n:]
	return n, nil
}
func (r *stubRemote) Write(b []byte) (int, error) { return r.got.Write(b) }
func (r *stubRemote) CloseWrite() error           { r.halfClosed = true; close(r.ended); return nil }
func (r *stubRemote) Close() error                { r.closed = true; return nil }
