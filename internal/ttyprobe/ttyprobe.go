// Package ttyprobe reports whether an open descriptor is a terminal, or
// /dev/null. Each platform file supplies the isTerminal and isNullFD behind the
// two exported names.
package ttyprobe

import "os"

// IsTerminal reports whether f is a terminal.
func IsTerminal(f *os.File) bool {
	return isTerminal(f)
}

// IsNullFD reports whether f is /dev/null.
func IsNullFD(f *os.File) bool {
	return isNullFD(f)
}
