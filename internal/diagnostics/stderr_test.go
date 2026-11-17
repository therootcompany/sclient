package diagnostics

import (
	"os"
	"testing"
)

func TestTarget(t *testing.T) {
	path := t.TempDir() + "/diagnostics.log"

	for _, want := range []string{"", "/dev/null", path} {
		if got := Target("test", want); got == nil {
			t.Errorf("Target(%q): nil", want)
		}
	}

	if _, err := os.ReadFile(path); err != nil {
		t.Errorf("log file was not created: %v", err)
	}

	if got := Target("test", path+"/missing.log"); got != os.Stderr {
		t.Errorf("Target of an unopenable path: got %q, want os.Stderr", got.Name())
	}
}

func TestSSHNullsStderr(t *testing.T) {
	if sshNullsStderr(os.Stdin, os.Stdout, os.Stderr) {
		t.Error("a unit test is not a ProxyCommand")
	}

	devnull, err := os.Open("/dev/null")
	if err != nil {
		t.Skip("/dev/null: ", err) // Windows: the probe answers false
	}
	defer devnull.Close()

	connRead, connWrite, err := os.Pipe()
	if err != nil {
		t.Skip("pipe: ", err)
	}
	defer connRead.Close()
	defer connWrite.Close()

	if !sshNullsStderr(connWrite, connWrite, devnull) {
		t.Error("fd 0 and fd 1 on pipes with /dev/null on fd 2 is a ProxyCommand")
	}
}
