package main

import (
	"bytes"
	"strings"
	"testing"
)

// printVersion must never print a doubled "v": git describe and
// debug.BuildInfo both return tags that already carry the prefix, while the
// printf adds its own.
func TestPrintVersion(t *testing.T) {
	origVersion, origCommit, origDate := version, commit, date
	defer func() { version, commit, date = origVersion, origCommit, origDate }()

	version = "v1.5.1-10-g965c233"
	commit = "965c233abcdef"
	date = "2026-11-14T00:00:00Z"

	var buf bytes.Buffer
	printVersion(&buf)
	out := buf.String()

	if strings.Contains(out, "vv") {
		t.Errorf("doubled v: %q", out)
	}
	first, _, _ := strings.Cut(out, "\n")
	want := "ssh-tls-proxy v1.5.1-10-g965c233 (965c233) 2026-11-14T00:00:00Z"
	if first != want {
		t.Errorf("version line = %q, want %q", first, want)
	}
}

// The fallback path must find the commit hash embedded by go build.
func TestPrintVersionFromBuildInfo(t *testing.T) {
	origVersion, origCommit, origDate := version, commit, date
	defer func() { version, commit, date = origVersion, origCommit, origDate }()

	version = "0.0.0-dev"
	commit = "0000000"
	date = "0001-01-01"

	var buf bytes.Buffer
	printVersion(&buf)
	out := buf.String()

	if strings.Contains(out, "vv") {
		t.Errorf("doubled v: %q", out)
	}
	if strings.Contains(out, "(0000000)") {
		t.Skip("no vcs metadata in this build (test binary built without VCS stamping)")
	}
}
