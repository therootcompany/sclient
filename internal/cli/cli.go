// Package cli holds the argument handling the commands share: the release stamp,
// address and port parsing, and the seconds a timeout flag carries. Each command
// keeps its own flags, usage text, and exit codes.
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"time"
)

// Version is one command's release stamp. GoReleaser fills Version, Commit and
// Date with -X main.<field>; Stamp backfills whatever is unset so plain
// `go build`, `go run` and `go install` still print something true.
type Version struct {
	Name    string
	Version string
	Commit  string
	Date    string
}

func (v Version) String() string {
	return fmt.Sprintf("%s %s (%s) %s", v.Name, v.Version, v.Commit, v.Date)
}

// Print writes the stamp as one line.
func (v Version) Print(w io.Writer) {
	_, _ = fmt.Fprintln(w, v.String())
}

// Stamp normalizes the three build settings.
func Stamp(name, version, commit, date string) Version {
	if version == "" || commit == "" || date == "" {
		if info, ok := debug.ReadBuildInfo(); ok {
			if version == "" && info.Main.Version != "devel" {
				version = info.Main.Version
			}
			if commit == "" {
				commit = setting(info.Settings, "vcs.revision")
			}
			if date == "" {
				date = setting(info.Settings, "vcs.time")
			}
		}
	}

	version = strings.TrimPrefix(version, "v")
	if version == "" {
		version = "dev"
	}

	commit = commit[:min(len(commit), 7)]
	if commit == "" {
		commit = "0000000"
	}

	if when, err := time.Parse(time.RFC3339, date); err == nil {
		date = when.Format(time.DateOnly)
	} else {
		date = "0001-01-01"
	}

	return Version{Name: name, Version: version, Commit: commit, Date: date}
}

func setting(settings []debug.BuildSetting, key string) string {
	for _, item := range settings {
		if item.Key == key {
			return item.Value
		}
	}
	return ""
}

// PreParse handles -V and help before the flags are parsed, so they survive junk
// arguments. Both commands use the same spellings.
func PreParse(stamp Version, fs *flag.FlagSet, args []string) {
	if len(args) == 0 {
		return
	}
	switch args[0] {
	case "-V", "-version", "--version", "version":
		stamp.Print(os.Stdout)
		os.Exit(0)
	case "help", "-help", "--help":
		fs.SetOutput(os.Stdout)
		fs.Usage()
		os.Exit(0)
	}
}

// FailUsage reports a usage error on stderr, prints the usage, and exits 2.
func FailUsage(name string, fs *flag.FlagSet, msg string) {
	_, _ = fmt.Fprintf(os.Stderr, "%s: %s\n", name, msg)
	fs.Usage()
	os.Exit(2)
}

// SplitHostPort splits an address, reporting whether it carried a port.
// "::1:443" is itself a complete IPv6 address, so an unbracketed one is refused
// rather than guessed.
func SplitHostPort(addr string) (host, port string, hasPort bool, err error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", "", false, errors.New("empty address")
	}

	host, port, err = net.SplitHostPort(addr)
	if err == nil {
		return host, port, true, nil
	}
	if !strings.Contains(addr, ":") {
		return addr, "", false, nil
	}
	if strings.HasPrefix(addr, "[") && strings.HasSuffix(addr, "]") {
		return addr[1 : len(addr)-1], "", false, nil
	}
	return "", "", false, fmt.Errorf("%q: want <host>:<port>, or an IPv6 address in brackets", addr)
}

// ParsePort accepts a decimal port in 1..65535.
func ParsePort(raw string) (int, error) {
	port, err := strconv.Atoi(raw)
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("%q is not a port (1-65535)", raw)
	}
	return port, nil
}

// PortOf names a flag whose value is not a port.
func PortOf(flagName string, port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("--%s must be 1-65535, got %d", flagName, port)
	}
	return nil
}

// Seconds turns a flag value into a duration; zero means "not set".
func Seconds(raw float64) time.Duration {
	if raw <= 0 {
		return 0
	}
	return time.Duration(raw * float64(time.Second))
}

// Options parses "a,b,c", "a b c" and "a, b, c" the same way. Empty is nil.
func Options(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	return strings.Fields(strings.ReplaceAll(raw, ",", " "))
}
