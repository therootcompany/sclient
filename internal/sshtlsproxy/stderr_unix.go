//go:build unix

package sshtlsproxy

import (
	"os"
	"syscall"
)

// Stderr returns the diagnostic destination: os.Stderr, or - when OpenSSH
// nulls fd 2 for a ProxyCommand (ControlPath + valued ControlPersist, since
// 8.0) - the controlling terminal, still reachable because the proxy is
// forked before the ControlMaster daemon()s.
//
// It returns *os.File so the caller can assign it straight to os.Stderr.
// fd 2 itself is untouched, so anything that captured os.Stderr before this
// call, or inherits fd 2, still sees /dev/null. The tty fd is never closed,
// exactly like os.Stderr itself.
func Stderr() *os.File {
	var st, nullst syscall.Stat_t
	if err := syscall.Fstat(2, &st); err != nil {
		return os.Stderr
	}
	if err := syscall.Stat("/dev/null", &nullst); err != nil {
		return os.Stderr
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFCHR || st.Rdev != nullst.Rdev {
		return os.Stderr // a real pipe or terminal: nothing to repair
	}
	tty, err := os.OpenFile("/dev/tty", os.O_WRONLY|syscall.O_NOCTTY, 0)
	if err != nil {
		return os.Stderr // no controlling terminal (cron, CI): nowhere to go
	}
	return tty
}
