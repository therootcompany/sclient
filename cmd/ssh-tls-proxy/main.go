package main

import (
	"context"
	"crypto/tls"
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

	"git.rootprojects.org/root/sclient.go/internal/sshtlsproxy"
)

var (
	name         = "ssh-tls-proxy"
	version      = "0.0.0-dev"
	commit       = "0000000"
	date         = "0001-01-01"
	licenseYear  = "2018"
	licenseOwner = "AJ ONeal"
	licenseType  = "MPL-2.0"
)

// printVersion uses the ldflags stamp, or Go's own build info for a plain
// build. Version strings are stripped of "v" so the printf is the only
// place it is added.
func printVersion(w io.Writer) {
	if version == "0.0.0-dev" || commit == "0000000" {
		if bi, ok := debug.ReadBuildInfo(); ok {
			// "devel" for a plain build; the tag for `go install mod@vX.Y.Z`
			tag := strings.TrimPrefix(bi.Main.Version, "v")
			if tag != "" && tag != "devel" {
				version = tag
			}
			for _, s := range bi.Settings {
				switch s.Key {
				case "vcs.revision":
					if commit == "0000000" {
						commit = s.Value
					}
				case "vcs.time":
					if date == "0001-01-01" {
						date = s.Value
					}
				}
			}
		}
	}
	version = strings.TrimPrefix(version, "v")
	short := commit
	if len(short) > 7 {
		short = short[:7]
	}
	_, _ = fmt.Fprintf(w, "%s v%s (%s) %s\n", name, version, short, date)
	_, _ = fmt.Fprintf(w, "Copyright (C) %s %s\n", licenseYear, licenseOwner)
	_, _ = fmt.Fprintf(w, "Licensed under %s\n", licenseType)
}

func main() {
	// ssh nulls a ProxyCommand's stderr; Stderr() redirects it to the tty.
	// log captured os.Stderr at its own init, so log.SetOutput(os.Stderr)
	// would have to be called separately to route it too.
	os.Stderr = sshtlsproxy.Stderr()
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-V", "-version", "--version", "version":
			printVersion(os.Stdout)
			os.Exit(0)
		case "help", "-help", "--help":
			printVersion(os.Stdout)
			fmt.Fprintln(os.Stdout)
			fs := newFlagSet(&sshtlsproxy.Config{}, &rawFlags{})
			fs.SetOutput(os.Stdout)
			fs.Usage()
			os.Exit(0)
		}
	}

	cfg, tlsCfg, ok := parseArgs(os.Args[1:])
	if !ok {
		os.Exit(2)
	}
	cfg.Name = name
	cfg.TLS = tlsCfg
	// Ctrl-C or SIGTERM cancels the probe and the session
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// 0 session done, 255 no usable server (ssh convention), 1 client-side failure
	var code int
	switch err := sshtlsproxy.Probe(ctx, cfg, os.Stdin, os.Stdout, os.Stderr); {
	case errors.Is(err, sshtlsproxy.ErrNoServer):
		code = 255
	case err != nil:
		code = 1
	}
	os.Exit(code)
}

// rawFlags holds values that need post-processing before they can become
// a config: the ALPN list, the duration, the server name, the insecure alias.
type rawFlags struct {
	alpnRaw    string
	serverName string
	timeoutSec float64
	insecure   bool
}

func newFlagSet(cfg *sshtlsproxy.Config, raw *rawFlags) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)

	fs.IntVar(&cfg.SSHPort, "ssh-port", 22, "plain-SSH server port (usually %p)")
	fs.IntVar(&cfg.TLSPort, "tls-port", 443, "TLS-terminated SSH server port")
	fs.StringVar(&raw.alpnRaw, "alpn", "ssh", "acceptable ALPN protocols, ex: 'ssh' 'h2,http/1.1'")
	fs.Float64Var(&raw.timeoutSec, "timeout", 3, "overall timeout in seconds (0 = the default, 3)")
	fs.StringVar(&raw.serverName, "servername", "", "SNI / hostname to verify (default: <host>)")
	fs.BoolVar(&raw.insecure, "k", false, "alias for --insecure")
	fs.BoolVar(&raw.insecure, "insecure", false, "ignore bad TLS/SSL certificates")
	fs.BoolVar(&cfg.Verbose, "v", false, "alias for --verbose")
	fs.BoolVar(&cfg.Verbose, "verbose", false, "more verbose output")
	fs.BoolVar(&cfg.Silent, "s", false, "alias for --silent")
	fs.BoolVar(&cfg.Silent, "silent", false, "less verbose output")

	fs.Usage = func() {
		_, _ = fmt.Fprintf(fs.Output(), "USAGE\n  %s [flags] <host>\n\n", name)
		_, _ = fmt.Fprintf(fs.Output(), "example ssh_config:\n")
		_, _ = fmt.Fprintf(fs.Output(), "  Host *\n")
		_, _ = fmt.Fprintf(fs.Output(), "      ProxyCommand %s --timeout 3 --alpn ssh --ssh-port %%p %%h\n\n", name)
		_, _ = fmt.Fprintln(fs.Output(), "FLAGS")
		fs.PrintDefaults()
		_, _ = fmt.Fprintln(fs.Output(), "\nENVIRONMENT")
		_, _ = fmt.Fprintln(fs.Output(), "  SSHTLSPROXY_SSH_PORT     plain-SSH server port")
		_, _ = fmt.Fprintln(fs.Output(), "  SSHTLSPROXY_TLS_PORT     TLS-terminated SSH server port")
		_, _ = fmt.Fprintln(fs.Output(), "  SSHTLSPROXY_ALPN         acceptable ALPN protocols")
		_, _ = fmt.Fprintln(fs.Output(), "  SSHTLSPROXY_TIMEOUT      overall timeout in seconds")
		_, _ = fmt.Fprintln(fs.Output(), "  SSHTLSPROXY_SERVERNAME   SNI / hostname to verify")
	}

	return fs
}

func parseArgs(args []string) (sshtlsproxy.Config, *tls.Config, bool) {
	cfg := sshtlsproxy.Config{}
	raw := rawFlags{}
	fs := newFlagSet(&cfg, &raw)

	if err := fs.Parse(args); err != nil {
		return sshtlsproxy.Config{}, nil, false
	}

	// Visit sees only flags the operator gave, so it runs after Parse
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	if fs.NArg() != 1 {
		fmt.Fprintf(os.Stderr, "%s: expected exactly one <host> argument\n", name)
		fs.SetOutput(os.Stderr)
		fs.Usage()
		return sshtlsproxy.Config{}, nil, false
	}

	// Env vars fill in only unset flags; malformed values keep the default
	if !set["ssh-port"] {
		if v := os.Getenv("SSHTLSPROXY_SSH_PORT"); v != "" {
			if p, err := strconv.Atoi(v); err == nil {
				cfg.SSHPort = p
			}
		}
	}
	if !set["tls-port"] {
		if v := os.Getenv("SSHTLSPROXY_TLS_PORT"); v != "" {
			if p, err := strconv.Atoi(v); err == nil {
				cfg.TLSPort = p
			}
		}
	}
	if !set["alpn"] {
		if v := os.Getenv("SSHTLSPROXY_ALPN"); v != "" {
			raw.alpnRaw = v
		}
	}
	if !set["timeout"] {
		if v := os.Getenv("SSHTLSPROXY_TIMEOUT"); v != "" {
			if tsec, err := strconv.ParseFloat(v, 64); err == nil && tsec >= 0 {
				raw.timeoutSec = tsec
			}
		}
	}
	if !set["servername"] {
		raw.serverName = strings.TrimSpace(os.Getenv("SSHTLSPROXY_SERVERNAME"))
	}

	cfg.ALPN = splitList(raw.alpnRaw)
	// explicit --alpn "" = no ALPN requirement (non-nil empty, no note);
	// an omitted flag stays nil and takes the engine default
	if set["alpn"] && cfg.ALPN == nil {
		cfg.ALPN = []string{}
	}
	cfg.Timeout = time.Duration(raw.timeoutSec * float64(time.Second))

	// %h never carries a port, but if it does, treat it as the TLS port
	host := fs.Arg(0)
	if h, p, err := net.SplitHostPort(host); err == nil && !strings.Contains(h, ":") {
		port, aerr := strconv.Atoi(p)
		if aerr != nil {
			fmt.Fprintf(os.Stderr, "%s: %q: the port after the colon is not numeric\n", name, host)
			return sshtlsproxy.Config{}, nil, false
		}
		host, cfg.TLSPort = h, port
	}
	cfg.Host = host

	if cfg.Timeout < 0 {
		fmt.Fprintf(os.Stderr, "%s: --timeout must be 0 (the default, 3s) or a positive number of seconds\n", name)
		return sshtlsproxy.Config{}, nil, false
	}
	if cfg.SSHPort <= 0 || cfg.TLSPort <= 0 {
		fmt.Fprintf(os.Stderr, "%s: ports must be > 0\n", name)
		return sshtlsproxy.Config{}, nil, false
	}

	// the engine uses a supplied tls.Config as-is, so state every option
	serverName := raw.serverName
	if serverName == "" {
		serverName = host
	}
	tlsCfg := &tls.Config{
		ServerName:         serverName,
		NextProtos:         cfg.ALPN,
		InsecureSkipVerify: raw.insecure,
		MinVersion:         tls.VersionTLS12,
	}
	return cfg, tlsCfg, true
}

// splitList splits "a,b,c" "a b c" and "a, b, c" the same.
func splitList(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	return strings.Fields(strings.ReplaceAll(s, ",", " "))
}
