package main

import (
	"fmt"
	"os"

	"github.com/therootcompany/sclient/internal/ttyprobe"
)

// stderrTarget is where diagnostics go: --stderr if given, the controlling
// terminal when ssh has nullled the ProxyCommand's stderr, stderr otherwise.
func stderrTarget(path string) *os.File {
	if path != "" {
		out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "sclient: --stderr %q: %s; using stderr\n", path, err)
			return os.Stderr
		}
		return out
	}

	if maybeSSHControlMasterNull(os.Stdin, os.Stdout, os.Stderr) {
		terminal, err := os.OpenFile("/dev/tty", os.O_WRONLY, 0)
		if err == nil {
			return terminal
		}
	}
	return os.Stderr
}

// maybeSSHControlMasterNull reports whether ssh ran us with ControlMaster: a
// ProxyCommand's stderr is /dev/null then. Without ControlMaster, fd 2 is
// already the terminal, so there is nothing to redirect.
func maybeSSHControlMasterNull(stdin, stdout, stderr *os.File) bool {
	return !ttyprobe.IsTerminal(stdin) && !ttyprobe.IsTerminal(stdout) && ttyprobe.IsNullFD(stderr)
}
