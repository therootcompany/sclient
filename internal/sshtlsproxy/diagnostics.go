package sshtlsproxy

import "os"

// stderrOnly writes to os.Stderr. Close is a no-op: closing os.Stderr
// closes fd 2 for the rest of the process, which the caller does not
// want when the writer is simply "stderr".
type stderrOnly struct{}

func (stderrOnly) Write(p []byte) (int, error) { return os.Stderr.Write(p) }
func (stderrOnly) Close() error                { return nil }
