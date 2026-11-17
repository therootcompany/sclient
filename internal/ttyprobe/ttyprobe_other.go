//go:build !(linux || darwin || freebsd || openbsd || netbsd || dragonfly || windows)

package ttyprobe

import "os"

// No termios ioctl, no console handle, no /dev/null. Plan 9 would check Fd2path
// for "/dev/cons".
func isTerminal(_ *os.File) bool {
	return false
}

func isNullFD(_ *os.File) bool {
	return false
}
