//go:build linux

package ttyprobe

import (
	"os"
	"syscall"
	"unsafe"
)

// isTerminal: the termios ioctl answers only for a terminal.
func isTerminal(f *os.File) bool {
	var t syscall.Termios
	r1, _, err := syscall.Syscall(syscall.SYS_IOCTL, uintptr(f.Fd()), syscall.TCGETS, uintptr(unsafe.Pointer(&t)))
	return err == 0 && r1 == 0
}

// isNullFD: the device number identifies /dev/null; a character device is not
// enough, since a terminal is one too.
func isNullFD(f *os.File) bool {
	var st, nullst syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &st); err != nil {
		return false
	}
	if err := syscall.Stat("/dev/null", &nullst); err != nil {
		return false
	}
	return st.Mode&syscall.S_IFMT == syscall.S_IFCHR && st.Rdev == nullst.Rdev
}
