//go:build unix

package sshtlsproxy

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// The init in stderr_unix.go depends on recognizing /dev/null as fd 2, so
// the stat test is the load-bearing one.
func TestIsDevNullStat(t *testing.T) {
	f, err := os.Open("/dev/null")
	if err != nil {
		t.Skip("no /dev/null: ", err)
	}
	defer f.Close()

	var st syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &st); err != nil {
		t.Fatal(err)
	}
	if !isDevNullStat(&st) {
		t.Error("fstat(/dev/null) not recognized as the null device")
	}

	reg := filepath.Join(t.TempDir(), "reg")
	if err := os.WriteFile(reg, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	rf, err := os.Open(reg)
	if err != nil {
		t.Fatal(err)
	}
	defer rf.Close()
	if err := syscall.Fstat(int(rf.Fd()), &st); err != nil {
		t.Fatal(err)
	}
	if isDevNullStat(&st) {
		t.Error("regular file recognized as the null device")
	}
}
