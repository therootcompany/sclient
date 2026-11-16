package sshtlsproxy

import "os"

// stderrOnly writes to os.Stderr; Close is a no-op because closing
// os.Stderr closes fd 2 for the whole process.
type stderrOnly struct{}

func (stderrOnly) Write(p []byte) (int, error) { return os.Stderr.Write(p) }
func (stderrOnly) Close() error                { return nil }
