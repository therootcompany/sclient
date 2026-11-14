//go:build !unix

package sshtlsproxy

import "io"

// No /dev/null device identity or /dev/tty on this platform. Windows
// OpenSSH has no ControlMaster/ControlPersist, so the swallowed-stderr
// case does not arise; plain stderr is always the channel.
func StderrOrTTY() io.WriteCloser { return stderrOnly{} }
