//go:build unix

package sshtlsproxy

import (
	"os"
	"syscall"
)

// Stderr returns the diagnostic destination: os.Stderr, or - when OpenSSH
// has nullled fd 2 for a ProxyCommand (ControlPath + valued ControlPersist,
// since 8.0) - the controlling terminal, which is still reachable because
// the proxy is forked before the ControlMaster daemon()s.
//
// It returns *os.File so the caller can assign it straight to os.Stderr.
// fd 2 itself is untouched, so anything that captured os.Stderr before this
// call, or inherits fd 2, still sees /dev/null. The tty fd is never closed,
// exactly like os.Stderr itself.
func Stderr() *os.File {
	if !stderrIsDevNull() {
		return os.Stderr
	}
	tty, err := os.OpenFile("/dev/tty", os.O_WRONLY|syscall.O_NOCTTY, 0)
	if err != nil {
		return os.Stderr
	}
	return tty
}

// stderrIsDevNull reports fd 2 pointing at /dev/null.
func stderrIsDevNull() bool {
	var st syscall.Stat_t
	if err := syscall.Fstat(2, &st); err != nil {
		return false
	}
	return isDevNullStat(&st)
}

// isDevNullStat reports whether st describes the null device.
func isDevNullStat(st *syscall.Stat_t) bool {
	var nullst syscall.Stat_t
	if err := syscall.Stat("/dev/null", &nullst); err != nil {
		return false
	}
	return st.Mode&syscall.S_IFMT == syscall.S_IFCHR && st.Rdev == nullst.Rdev
}
