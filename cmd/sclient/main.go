package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/therootcompany/sclient"
)

const name = "sclient"

const (
	defaultRemotePort = 443
	defaultLocalHost  = "localhost"
)

// Stamped by goreleaser at release time (-X main.version, -X main.commit,
// -X main.date); init() fills in what is left unset for go run and go build.
var (
	version = ""
	commit  = ""
	date    = ""
)

type MainConfig struct {
	alpn       string
	insecure   bool
	servername string
	silent     bool
	stderr     string
	tcpTimeout float64
	tlsTimeout float64
	remote     string
	local      string
}

func shortCommit(c string) string {
	return c[:min(len(c), 7)]
}

func printVersion(w io.Writer) {
	_, _ = fmt.Fprintf(w, "%s %s (%s) %s\n", name, version, commit, date)
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
	if when, err := time.Parse(time.RFC3339, date); err == nil {
		date = when.Format(time.DateOnly)
	}
}

func usage(fs *flag.FlagSet) {
	w := fs.Output()
	printVersion(w)
	_, _ = fmt.Fprintf(w, "\nUSAGE: %s [flags] <remote> <local>\n", name)
	_, _ = fmt.Fprintf(w, "\n   ex: %s example.com 3000\n", name)
	_, _ = fmt.Fprintf(w, "      (example.com:443 <= localhost:3000)\n")
	_, _ = fmt.Fprintf(w, "\n   ex: %s example.com:8443 0.0.0.0:4080\n", name)
	_, _ = fmt.Fprintf(w, "\n   ex: %s example.com:443 -\n", name)
	_, _ = fmt.Fprintf(w, "\nFLAGS\n")
	fs.PrintDefaults()
	_, _ = fmt.Fprintln(w)
}

// failUsage reports a usage error and exits 2.
func failUsage(fs *flag.FlagSet, msg string) {
	_, _ = fmt.Fprintf(os.Stderr, "%s: %s\n", name, msg)
	fs.Usage()
	os.Exit(2)
}

func main() {
	cfg := MainConfig{}

	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.StringVar(&cfg.alpn, "alpn", "", "acceptable protocols, ex: 'h2,http/1.1' 'http/1.1' 'ssh'")
	fs.BoolVar(&cfg.insecure, "k", false, "alias for --insecure")
	fs.BoolVar(&cfg.silent, "s", false, "alias of --silent")
	fs.StringVar(&cfg.servername, "servername", "", "specify a servername different from <remote> (to disable SNI use an IP as <remote> and do not use this option)")
	fs.BoolVar(&cfg.insecure, "insecure", false, "ignore bad TLS (SSL/HTTPS) certificates")
	fs.BoolVar(&cfg.silent, "silent", false, "less verbose output")
	fs.StringVar(&cfg.stderr, "stderr", "", "where diagnostics go, ex sclient.log or /dev/null")
	fs.Float64Var(&cfg.tcpTimeout, "tcp-timeout", 0, "seconds for the TCP connect, DNS included (0 = default, 5s)")
	fs.Float64Var(&cfg.tlsTimeout, "tls-timeout", 0, "seconds for the TLS handshake (0 = auto, 3x the connect)")
	fs.Usage = func() { usage(fs) }

	// Before parsing: -V and help survive junk arguments.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-V", "-version", "--version", "version":
			printVersion(os.Stdout)
			os.Exit(0)
		case "help", "-help", "--help":
			fs.SetOutput(os.Stdout)
			fs.Usage()
			os.Exit(0)
		}
	}

	if err := fs.Parse(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		os.Exit(2) // flag printed the error and the usage
	}

	// stdout is the payload; --stderr says where the rest goes.
	os.Stderr = stderrTarget(cfg.stderr)

	switch args := fs.Args(); len(args) {
	case 2:
		cfg.remote = args[0]
		cfg.local = args[1]
	case 1:
		// We may omit the second argument if we're going straight to stdin
		if stat, _ := os.Stdin.Stat(); stat.Mode()&os.ModeCharDevice == 0 {
			cfg.remote = args[0]
			cfg.local = "|"
		} else {
			failUsage(fs, "want <remote> <local>")
		}
	default:
		failUsage(fs, "want <remote> <local>")
	}

	tun := &sclient.Tunnel{
		InsecureSkipVerify: cfg.insecure,
		ServerName:         cfg.servername,
		Silent:             cfg.silent,
		NextProtos:         parseOptionList(cfg.alpn),
		TCPTimeout:         toSeconds(cfg.tcpTimeout),
		TLSTimeout:         toSeconds(cfg.tlsTimeout),
	}

	remoteHost, remotePort, err := remoteAddr(cfg.remote)
	if err != nil {
		failUsage(fs, "remote: "+err.Error())
	}
	tun.RemoteAddress = remoteHost
	tun.RemotePort = remotePort

	if cfg.local == "-" || cfg.local == "|" {
		// User may specify stdin/stdout instead of net
		tun.LocalAddress = cfg.local
		tun.LocalPort = -1
	} else {
		localHost, localPort, err := localAddr(cfg.local)
		if err != nil {
			failUsage(fs, "local: "+err.Error())
		}
		tun.LocalAddress = localHost
		tun.LocalPort = localPort
	}

	// SIGINT or SIGTERM cancels ctx, which stops the tunnel.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := tun.DialAndListenContext(ctx); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}

// remoteAddr parses <host> or <host>:<port>; a bare host gets port 443.
func remoteAddr(s string) (string, int, error) {
	host, rawPort, hasPort, err := splitHostPort(s)
	if err != nil {
		return "", 0, err
	}
	if !hasPort {
		return host, defaultRemotePort, nil
	}
	port, err := parsePort(rawPort)
	if err != nil {
		return "", 0, fmt.Errorf("remote %q: %w", s, err)
	}
	return host, port, nil
}

// localAddr parses <port> or <host>:<port>; a bare port listens on localhost.
func localAddr(s string) (string, int, error) {
	host, rawPort, hasPort, err := splitHostPort(s)
	if err != nil {
		return "", 0, err
	}
	if !hasPort {
		port, err := parsePort(s)
		if err != nil {
			return "", 0, fmt.Errorf("local %q: want <port> or <host>:<port>", s)
		}
		return defaultLocalHost, port, nil
	}
	port, err := parsePort(rawPort)
	if err != nil {
		return "", 0, fmt.Errorf("local %q: %w", s, err)
	}
	return host, port, nil
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
