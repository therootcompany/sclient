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

	sclient "git.rootprojects.org/root/sclient.go"
)

// Replaced by goreleaser / ldflags at build time.
var (
	name    = "sclient"
	version = "0.0.0-dev"
	commit  = "0000000"
	date    = "0001-01-01"
)

// MainConfig is everything the CLI accepts, one field per flag.
type MainConfig struct {
	alpn       string
	insecure   bool
	servername string
	silent     bool
	verbose    bool
	tcpTimeout float64
	tlsTimeout float64
}

func printVersion(w io.Writer) {
	// git describe and debug.BuildInfo both return tags that already carry
	// the "v"; normalize here so this printf is the only place that adds it.
	if version == "0.0.0-dev" || commit == "0000000" {
		if bi, ok := debug.ReadBuildInfo(); ok {
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
	_, _ = fmt.Fprintf(w, "%s v%s (%s) %s\n", name, version, shortCommit(commit), date)
}

func main() {
	cfg := MainConfig{}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.Usage = func() {
		printVersion(os.Stderr)
		_, _ = fmt.Fprintf(os.Stderr, "\nUSAGE\n  %s [flags] <remote> <local>\n\n", name)
		_, _ = fmt.Fprintf(os.Stderr, "   ex: %s example.com 3000\n", name)
		_, _ = fmt.Fprintf(os.Stderr, "      (%s example.com:443 localhost:3000)\n", name)
		_, _ = fmt.Fprintf(os.Stderr, "   ex: %s example.com:8443 0.0.0.0:4080\n", name)
		_, _ = fmt.Fprintf(os.Stderr, "   ex: %s example.com:443 -\n", name)
		_, _ = fmt.Fprintf(os.Stderr, "\nFLAGS\n")
		fs.PrintDefaults()
		_, _ = fmt.Println()
	}

	fs.StringVar(&cfg.alpn, "alpn", "", "acceptable protocols, ex: 'h2,http/1.1' 'ssh'")
	fs.BoolVar(&cfg.insecure, "k", false, "alias for --insecure")
	fs.BoolVar(&cfg.silent, "s", false, "alias of --silent")
	fs.BoolVar(&cfg.verbose, "v", false, "alias for --verbose")
	fs.StringVar(&cfg.servername, "servername", "", "specify a servername different from <remote> (to disable SNI use an IP as <remote> and do not use this option)")
	fs.BoolVar(&cfg.insecure, "insecure", false, "ignore bad TLS/SSL/HTTPS certificates")
	fs.BoolVar(&cfg.silent, "silent", false, "less verbose output")
	fs.BoolVar(&cfg.verbose, "verbose", false, "show what each dial negotiated")
	fs.Float64Var(&cfg.tcpTimeout, "tcp-timeout", 0, "seconds for the TCP connect, DNS included. 0 = the default, 5s")
	fs.Float64Var(&cfg.tlsTimeout, "tls-timeout", 0, "seconds for the TLS handshake, measured from the connect. 0 = auto: twice that connect, floor 150ms")

	// Version and help work even when the rest of the arguments are junk:
	// handle them before parsing.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-V", "-version", "--version", "version":
			printVersion(os.Stdout)
			os.Exit(0)
		case "help", "-help", "--help":
			printVersion(os.Stdout)
			fmt.Println()
			fs.SetOutput(os.Stdout)
			fs.Usage()
			os.Exit(0)
		}
	}

	if err := fs.Parse(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		// ContinueOnError has already printed the reason; 2 is the usage
		// exit code.
		os.Exit(2)
	}

	if cfg.tcpTimeout < 0 || cfg.tlsTimeout < 0 {
		_, _ = fmt.Fprintf(os.Stderr, "%s: timeouts must be 0 (the default) or a positive number of seconds\n", name)
		fs.Usage()
		os.Exit(2)
	}

	alpns := parseOptionList(cfg.alpn)

	n := fs.NArg()
	remotestr := fs.Arg(0)
	localstr := fs.Arg(1)

	if n != 2 {
		// We may omit the second argument if we're going straight to stdin
		if stat, _ := os.Stdin.Stat(); n == 1 && (stat.Mode()&os.ModeCharDevice) == 0 {
			localstr = "|"
		} else {
			fs.Usage()
			os.Exit(2)
		}
	}

	tun := &sclient.Tunnel{
		RemotePort:         443,
		LocalAddress:       "localhost",
		InsecureSkipVerify: cfg.insecure,
		ServerName:         cfg.servername,
		Silent:             cfg.silent,
		Verbose:            cfg.verbose,
		NextProtos:         alpns,
		TCPTimeout:         seconds(cfg.tcpTimeout),
		TLSTimeout:         seconds(cfg.tlsTimeout),
	}

	remoteHost, remotePort, err := remoteAddr(remotestr, 443)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%s: %s\n", name, err)
		fs.Usage()
		os.Exit(2)
	}
	tun.RemoteAddress, tun.RemotePort = remoteHost, remotePort

	if localstr == "-" || localstr == "|" {
		// stdin/stdout instead of a local listener
		tun.LocalAddress = localstr
		tun.LocalPort = -1
	} else {
		localHost, localPort, err := localAddr(localstr)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "%s: %s\n", name, err)
			fs.Usage()
			os.Exit(2)
		}
		tun.LocalAddress, tun.LocalPort = localHost, localPort
	}

	if err := tun.DialAndListen(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}

// localAddr parses the local listen address: a bare number is a port on
// localhost; host:port (or [ipv6]:port) sets both.
func localAddr(s string) (string, int, error) {
	s = strings.TrimSpace(s)
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		p, cerr := strconv.Atoi(s)
		if cerr != nil || p < 1 || p > 65535 {
			return "", 0, fmt.Errorf("%q: expected <port> or <host>:<port>", s)
		}
		return "localhost", p, nil
	}
	p, cerr := strconv.Atoi(port)
	if cerr != nil || p < 1 || p > 65535 {
		return "", 0, fmt.Errorf("%q: %q is not a port", s, port)
	}
	return host, p, nil
}

// remoteAddr parses <host>, <host>:<port>, or [ipv6]:<port>; a bare host
// takes the default port.
func remoteAddr(s string, defaultPort int) (string, int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", 0, fmt.Errorf("empty address")
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		if strings.Contains(s, ":") {
			return "", 0, fmt.Errorf("%q: expected <host> or <host>:<port>", s)
		}
		return s, defaultPort, nil
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return "", 0, fmt.Errorf("%q: %q is not a port", s, port)
	}
	return host, p, nil
}

// shortCommit keeps the first 7 characters of the hash; anything shorter
// prints as-is rather than panicking on the slice.
func shortCommit(c string) string {
	return c[:min(len(c), 7)]
}

// seconds turns a flag value into a duration; a non-positive value leaves the
// field at zero, which the engine reads as "use the default".
func seconds(raw float64) time.Duration {
	if raw <= 0 {
		return 0
	}
	return time.Duration(raw * float64(time.Second))
}

// parseOptionList parses "a,b,c", "a b c", and "a, b, c" the same
func parseOptionList(optionList string) []string {
	optionList = strings.TrimSpace(optionList)
	if optionList == "" {
		return nil
	}
	return strings.Fields(strings.ReplaceAll(optionList, ",", " "))
}
