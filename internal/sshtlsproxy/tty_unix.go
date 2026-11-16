//go:build unix

package sshtlsproxy

import (
	"errors"
	"io"
	"os"
	"syscall"
)

func isDevNullStat(st *syscall.Stat_t) bool {
	var nullst syscall.Stat_t
	if err := syscall.Stat("/dev/null", &nullst); err != nil {
		return false
	}
	return st.Mode&syscall.S_IFMT == syscall.S_IFCHR && st.Rdev == nullst.Rdev
}

// stderrIsDevNull reports fd 2 pointing at /dev/null, which OpenSSH does
// for a ProxyCommand when ControlPath and a valued ControlPersist are set.
func stderrIsDevNull() bool {
	var st syscall.Stat_t
	if err := syscall.Fstat(2, &st); err != nil {
		return false
	}
	return isDevNullStat(&st)
}

// openTTY opens the controlling terminal: the proxy is forked before a
// ControlPersist master daemon()s, so the tty is still reachable. No tty
// (cron, CI) means no fallback. O_NOCTTY: never adopt a tty.
func openTTY() (io.WriteCloser, bool) {
	f, err := os.OpenFile("/dev/tty", os.O_WRONLY|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, false
	}
	return f, true
}

// StderrOrTTY returns a diagnostic writer: os.Stderr, or - when stderr is
// /dev/null and a controlling terminal is reachable - a tee to both. The
// caller decides whether to use it and closes it when done.
func StderrOrTTY() io.WriteCloser {
	if !stderrIsDevNull() {
		return stderrOnly{}
	}
	if tty, ok := openTTY(); ok {
		return &ttyTee{a: os.Stderr, b: tty}
	}
	return stderrOnly{}
}

type ttyTee struct {
	a, b io.Writer
}

func (t *ttyTee) Write(p []byte) (int, error) {
	_, aerr := t.a.Write(p)
	n, berr := t.b.Write(p)
	return n, errors.Join(aerr, berr)
}

func (t *ttyTee) Close() error {
	if c, ok := t.b.(io.Closer); ok {
		return c.Close()
	}
	return nil
}
