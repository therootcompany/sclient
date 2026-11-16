//go:build !unix

package sshtlsproxy

import "io"

// Windows OpenSSH has no ControlMaster/ControlPersist, so the null-stderr
// case cannot arise; plain stderr is always the channel.
func StderrOrTTY() io.WriteCloser { return stderrOnly{} }
