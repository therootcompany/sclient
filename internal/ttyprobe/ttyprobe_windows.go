//go:build windows

package ttyprobe

import (
	"os"
	"syscall"
)

// isTerminal: GetConsoleMode answers only for a console handle.
func isTerminal(f *os.File) bool {
	var mode uint32
	return syscall.GetConsoleMode(syscall.Handle(f.Fd()), &mode) == nil
}

// isNullFD: Windows has "nul", not /dev/null.
func isNullFD(_ *os.File) bool {
	return false
}
