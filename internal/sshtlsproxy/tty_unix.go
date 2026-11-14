//go:build unix

package sshtlsproxy

import (
	"errors"
	"io"
	"os"
	"syscall"
)

// isDevNullStat reports whether st describes the /dev/null device.
func isDevNullStat(st *syscall.Stat_t) bool {
	var nullst syscall.Stat_t
	if err := syscall.Stat("/dev/null", &nullst); err != nil {
		return false
	}
	return st.Mode&syscall.S_IFMT == syscall.S_IFCHR && st.Rdev == nullst.Rdev
}

// stderrIsDevNull reports whether fd 2 points at /dev/null, which
// OpenSSH does for a ProxyCommand when both ControlPath and a valued
// ControlPersist are set.
func stderrIsDevNull() bool {
	var st syscall.Stat_t
	if err := syscall.Fstat(2, &st); err != nil {
		return false
	}
	return isDevNullStat(&st)
}

// openTTY opens the controlling terminal for diagnostics. The proxy
// is forked before a ControlPersist master daemon()s, so the terminal
// is still reachable from here when the client runs in one. It fails
// when there is no controlling terminal (cron, CI, non-interactive
// scripts); then there is nowhere better to put the message.
// O_NOCTTY: never adopt a tty.
func openTTY() (io.WriteCloser, bool) {
	f, err := os.OpenFile("/dev/tty", os.O_WRONLY|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, false
	}
	return f, true
}

// StderrOrTTY returns a writer for diagnostic output: os.Stderr, or,
// when stderr is /dev/null and a controlling terminal is still
// reachable, a writer that tees os.Stderr and the terminal, so the
// report reaches the user. Without a terminal (cron, CI) the open
// fails and plain stderr is returned. The package only provides the
// choice; the caller decides whether to use it and closes the
// returned writer when done.
func StderrOrTTY() io.WriteCloser {
	if !stderrIsDevNull() {
		return stderrOnly{}
	}
	if tty, ok := openTTY(); ok {
		return &ttyTee{a: os.Stderr, b: tty}
	}
	return stderrOnly{}
}

// ttyTee writes each write to both sides and closes the tty side.
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
