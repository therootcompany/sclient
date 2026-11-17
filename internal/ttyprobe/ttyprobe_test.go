package ttyprobe

import (
	"os"
	"testing"
)

// None of these is a terminal. /dev/null is a character device, which is the
// case a terminal check gets wrong.
func TestTerminalAndNullProbes(t *testing.T) {
	type probe struct {
		label string
		file  *os.File
		null  bool
	}

	file, err := os.CreateTemp(t.TempDir(), "tty-*")
	if err != nil {
		t.Skip("temp file: ", err)
	}
	defer file.Close()

	pipeRead, pipeWrite, err := os.Pipe()
	if err != nil {
		t.Skip("pipe: ", err)
	}
	defer pipeRead.Close()
	defer pipeWrite.Close()

	cases := []probe{
		{"temp file", file, false},
		{"pipe", pipeWrite, false},
	}

	if devnull, err := os.Open("/dev/null"); err == nil {
		defer devnull.Close()
		cases = append(cases, probe{"/dev/null", devnull, true})
	}

	for _, c := range cases {
		if IsTerminal(c.file) {
			t.Errorf("IsTerminal(%s): got true, want false", c.label)
		}
		if got := IsNullFD(c.file); got != c.null {
			t.Errorf("IsNullFD(%s): got %v, want %v", c.label, got, c.null)
		}
	}

	// The true branch, when there is a controlling terminal to test against.
	tty, err := os.Open("/dev/tty")
	if err != nil {
		return
	}
	defer tty.Close()

	if !IsTerminal(tty) {
		t.Error("IsTerminal(/dev/tty): got false, want true")
	}
}
