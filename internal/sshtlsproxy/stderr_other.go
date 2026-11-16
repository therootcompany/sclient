//go:build !unix

package sshtlsproxy

import "os"

// Windows OpenSSH has no ControlMaster/ControlPersist, so a ProxyCommand's
// stderr is never nullled; plain stderr is always the channel.
func Stderr() *os.File { return os.Stderr }
