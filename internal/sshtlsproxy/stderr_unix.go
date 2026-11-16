//go:build unix

package sshtlsproxy

import (
	"os"
	"syscall"
)

// OpenSSH nulls a ProxyCommand's stderr when ControlPath is set with a
// valued ControlPersist (since 8.0). When that happens and the controlling
// terminal is still reachable - the proxy is forked before the ControlMaster
// daemon()s - point os.Stderr at it so the report and --verbose notes are
// visible instead of dropped.
//
// os.Stderr is replaced, not duplicated: fd 2 still points at /dev/null, so
// anything that captured os.Stderr before this init (the log package) or
// inherits fd 2 (a child process) is unaffected. This package does neither.
// The tty fd is never closed, exactly like os.Stderr itself.
func init() {
	if !stderrIsDevNull() {
		return
	}
	tty, err := os.OpenFile("/dev/tty", os.O_WRONLY|syscall.O_NOCTTY, 0)
	if err != nil {
		return
	}
	os.Stderr = tty
}

// isDevNullStat reports whether st describes the null device.
func isDevNullStat(st *syscall.Stat_t) bool {
	var nullst syscall.Stat_t
	if err := syscall.Stat("/dev/null", &nullst); err != nil {
		return false
	}
	return st.Mode&syscall.S_IFMT == syscall.S_IFCHR && st.Rdev == nullst.Rdev
}

// stderrIsDevNull reports fd 2 pointing at /dev/null.
func stderrIsDevNull() bool {
	var st syscall.Stat_t
	if err := syscall.Fstat(2, &st); err != nil {
		return false
	}
	return isDevNullStat(&st)
}
