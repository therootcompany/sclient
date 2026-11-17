// Package diagnostics decides where a command's progress and error lines go.
//
// ssh runs a ProxyCommand with stdout as the payload, and with ControlMaster it
// nulls the command's stderr as well. Diagnostics written to stderr are lost then,
// so each command asks this package for a destination.
package diagnostics

import (
	"fmt"
	"os"

	"github.com/therootcompany/sclient/internal/ttyprobe"
)

// Target returns where diagnostics should be written: the operator's path when
// one is given, the controlling terminal when ssh has nullled the
// ProxyCommand's stderr, and os.Stderr otherwise. name is the command, used when
// the path cannot be opened.
func Target(name, path string) *os.File {
	if path != "" {
		out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "%s: --stderr %q: %s; using stderr\n", name, path, err)
			return os.Stderr
		}
		return out
	}

	if sshNullsStderr(os.Stdin, os.Stdout, os.Stderr) {
		if terminal, err := os.OpenFile("/dev/tty", os.O_WRONLY, 0); err == nil {
			return terminal
		}
	}
	return os.Stderr
}

// sshNullsStderr reports whether ssh ran us with ControlMaster: a ProxyCommand's
// stderr is /dev/null then. Without ControlMaster, fd 2 is already the terminal,
// so there is nothing to redirect.
func sshNullsStderr(stdin, stdout, stderr *os.File) bool {
	return !ttyprobe.IsTerminal(stdin) && !ttyprobe.IsTerminal(stdout) && ttyprobe.IsNullFD(stderr)
}
