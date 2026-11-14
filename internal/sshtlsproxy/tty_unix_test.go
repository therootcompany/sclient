//go:build unix

package sshtlsproxy

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestIsDevNullStat(t *testing.T) {
	f, err := os.Open("/dev/null")
	if err != nil {
		t.Skip("no /dev/null: ", err)
	}
	defer f.Close()

	var st syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &st); err != nil {
		t.Fatal(err)
	}
	if !isDevNullStat(&st) {
		t.Error("fstat(/dev/null) not recognized as the null device")
	}

	reg := filepath.Join(t.TempDir(), "reg")
	if err := os.WriteFile(reg, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	rf, err := os.Open(reg)
	if err != nil {
		t.Fatal(err)
	}
	defer rf.Close()
	if err := syscall.Fstat(int(rf.Fd()), &st); err != nil {
		t.Fatal(err)
	}
	if isDevNullStat(&st) {
		t.Error("regular file recognized as the null device")
	}
}

// In a test run stderr is a pipe, not /dev/null, so StderrOrTTY must
// return the plain-stderr writer: writes still go to stderr, Close is
// a no-op, and stderr works afterwards.
func TestStderrOrTTYPlainStderr(t *testing.T) {
	w := StderrOrTTY()
	if _, err := w.Write([]byte("test: plain stderr path\n")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal("Close of the plain-stderr writer:", err)
	}
	if _, err := os.Stderr.WriteString("test: stderr still open\n"); err != nil {
		t.Fatal("os.Stderr unusable after Close:", err)
	}
}

// ttyTee must deliver every write to both sides and close the tty side.
func TestTTYTee(t *testing.T) {
	a, b := &buf{}, &buf{}
	closer := &closer{}
	w := &ttyTee{a: a, b: writerCloser{b, closer}}
	if _, err := w.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if a.s != "hello" || b.s != "hello" {
		t.Fatalf("sides = %q %q, want both \"hello\"", a.s, b.s)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if !closer.closed {
		t.Error("Close did not close the tty side")
	}
}

// A failing side surfaces through the tee, never silently dropped.
func TestTTYTeeError(t *testing.T) {
	aerr := errors.New("a failed")
	w := &ttyTee{a: failingWriter{aerr}, b: &buf{}}
	_, err := w.Write([]byte("x"))
	if !errors.Is(err, aerr) {
		t.Fatalf("err = %v, want %v", err, aerr)
	}
}

type buf struct{ s string }

func (b *buf) Write(p []byte) (int, error) { b.s += string(p); return len(p), nil }

type closer struct{ closed bool }

type writerCloser struct {
	w *buf
	c *closer
}

func (wc writerCloser) Write(p []byte) (int, error) { return wc.w.Write(p) }
func (wc writerCloser) Close() error {
	wc.c.closed = true
	return nil
}

type failingWriter struct{ err error }

func (f failingWriter) Write([]byte) (int, error) { return 0, f.err }
