package main

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

	"github.com/therootcompany/sclient/internal/ttyprobe"
)

const (
	licenseYear  = 2018
	licenseOwner = "AJ ONeal"
	licenseType  = "MIT or Apache-2.0"
)

// GoReleaser sets these at release time with -X main.version, -X main.commit,
// and -X main.date; init() fills in what is left unset for go run and go build.
var (
	version = ""
	commit  = ""
	date    = ""
)

// buildTimeLayout is how the build date is printed: date, time, and the
// offset the build carried - no T, and no invented zone.
const buildTimeLayout = "2006-01-02 15:04:05-07:00"

// displayBuildDate turns the build date (RFC3339, as goreleaser, git, and
// debug.ReadBuildInfo write it) into the display form. A date with no time is
// left alone rather than padded out with a zone the build never had.
func displayBuildDate(raw string) string {
	when, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return raw
	}
	return when.Format(buildTimeLayout)
}

// parseBuildDate reads either form: the build date or the display form.
func parseBuildDate(raw string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339, buildTimeLayout, time.DateOnly} {
		if when, err := time.Parse(layout, raw); err == nil {
			return when, nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognized build date %q", raw)
}

func shortCommit(c string) string {
	return c[:min(len(c), 7)]
}

// copyrightYears prints a date like 2018-2026 or 2018-present, depending on available build info.
func copyrightYears(buildDate string) string {
	first := strconv.Itoa(licenseYear)

	build, err := parseBuildDate(buildDate)
	if err != nil || build.Year() < 1000 {
		return first + "-present"
	}
	return first + "-" + strconv.Itoa(build.Year())
}

func printVersion(w io.Writer) {
	_, _ = fmt.Fprintf(w, "%s v%s %s (%s)\n", name, version, commit, date)
	_, _ = fmt.Fprintf(w, "Copyright (C) %s %s\n", copyrightYears(date), licenseOwner)
	_, _ = fmt.Fprintf(w, "Licensed under %s\n", licenseType)
}

// buildSetting returns one VCS setting, or "" when the binary has none.
func buildSetting(settings []debug.BuildSetting, key string) string {
	for _, setting := range settings {
		if setting.Key == key {
			return setting.Value
		}
	}
	return ""
}

func init() {
	// ldflags win; ReadBuildInfo is the fallback for go run and plain go build.
	if version == "" || commit == "" || date == "" {
		if bi, ok := debug.ReadBuildInfo(); ok {
			if version == "" && bi.Main.Version != "devel" {
				version = bi.Main.Version
			}
			if commit == "" {
				commit = buildSetting(bi.Settings, "vcs.revision")
			}
			if date == "" {
				date = buildSetting(bi.Settings, "vcs.time")
			}
		}
	}

	version = strings.TrimPrefix(version, "v")
	if version == "" {
		version = "dev"
	}
	if commit == "" {
		commit = "0000000"
	}
	if date == "" {
		date = "0001-01-01"
	}
	commit = shortCommit(commit)
	date = displayBuildDate(date)
}

// preParse answers -V and help before anything is parsed, so they survive junk
// arguments.
func preParse(fs *flag.FlagSet, args []string) {
	for _, arg := range args {
		switch arg {
		case "-V", "-version", "--version", "version":
			printVersion(os.Stdout)
			os.Exit(0)
		case "help", "-help", "--help":
			fs.SetOutput(os.Stdout)
			fs.Usage()
			os.Exit(0)
		}
	}
}

// failUsage reports a usage error and exits 2.
func failUsage(fs *flag.FlagSet, msg string) {
	_, _ = fmt.Fprintf(os.Stderr, "%s: %s\n", name, msg)
	fs.Usage()
	os.Exit(2)
}

// stderrTarget is where diagnostics go: --stderr if given, the controlling
// terminal when ssh has nullled the ProxyCommand's stderr, stderr otherwise.
func stderrTarget(path string) *os.File {
	if path != "" {
		out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "%s: --stderr %q: %s; using stderr\n", name, path, err)
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
// ProxyCommand's stderr is /dev/null then. Without ControlMaster, fd 2 is already
// the terminal, so there is nothing to redirect.
func maybeSSHControlMasterNull(stdin, stdout, stderr *os.File) bool {
	return !ttyprobe.IsTerminal(stdin) && !ttyprobe.IsTerminal(stdout) && ttyprobe.IsNullFD(stderr)
}

// splitHostPort splits an address, reporting whether it had a port.
// "::1:443" is itself a valid IPv6 address, so an unbracketed one is refused.
func splitHostPort(s string) (string, string, bool, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", "", false, errors.New("empty address")
	}

	host, port, err := net.SplitHostPort(s)
	if err == nil {
		return host, port, true, nil
	}
	if !strings.Contains(s, ":") {
		return s, "", false, nil
	}
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		return s[1 : len(s)-1], "", false, nil
	}
	return "", "", false, fmt.Errorf("%q: want <host>:<port>, or an IPv6 address in brackets", s)
}

// parsePort accepts a decimal port in 1..65535.
func parsePort(raw string) (int, error) {
	port, err := strconv.Atoi(raw)
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("%q is not a port (1-65535)", raw)
	}
	return port, nil
}

// portOf names a flag whose value is not a port.
func portOf(flagName string, port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("--%s must be 1-65535, got %d", flagName, port)
	}
	return nil
}

func toSeconds(raw float64) time.Duration {
	if raw <= 0 {
		return 0
	}
	return time.Duration(raw * float64(time.Second))
}

// parsers "a,b,c" "a b c" and "a, b, c" all the same
func parseOptionList(optionList string) []string {
	optionList = strings.TrimSpace(optionList)

	if len(optionList) == 0 {
		return nil
	}

	optionList = strings.ReplaceAll(optionList, ",", " ")
	options := strings.Fields(optionList)

	return options
}

// hostAndPort parses <host> or <host>:<port>. Without a port the caller keeps the
// TLS default.
func hostAndPort(s string) (string, int, error) {
	host, rawPort, hasPort, err := splitHostPort(s)
	if err != nil {
		return host, 0, err
	}
	if !hasPort {
		return host, 0, nil
	}
	port, err := parsePort(rawPort)
	if err != nil {
		return "", 0, err
	}
	return host, port, nil
}

// listenAddr parses --listen <host>:<port>; the port is required.
func listenAddr(s string) (string, int, error) {
	host, rawPort, hasPort, err := splitHostPort(s)
	if err != nil {
		return "", 0, err
	}
	if !hasPort {
		return "", 0, fmt.Errorf("want <host>:<port>, got %q", s)
	}
	port, err := parsePort(rawPort)
	if err != nil {
		return "", 0, err
	}
	return host, port, nil
}

// alpnList is --alpn as offered. The default "ssh" is the check; an explicit empty
// list turns it off.
func alpnList(raw string) []string {
	if list := parseOptionList(raw); list != nil {
		return list
	}
	return []string{}
}
