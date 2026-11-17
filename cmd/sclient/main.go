package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strconv"
	"strings"

	"github.com/therootcompany/sclient"
)

// Replaced by goreleaser / ldflags at build time.
var (
	name    = "sclient"
	version = "0.0.0-dev"
	commit  = "0000000"
	date    = "0001-01-01"
)

// init() fills in whatever ldflags left unset, once, at load time. Tags from
// git describe and debug.BuildInfo already carry the "v"; printVersion is the
// only place that adds it back.
func init() {
	if version != "0.0.0-dev" && commit != "0000000" {
		return
	}
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	if tag := strings.TrimPrefix(bi.Main.Version, "v"); tag != "" && tag != "devel" {
		version = tag
	}
	for _, setting := range bi.Settings {
		switch setting.Key {
		case "vcs.revision":
			if commit == "0000000" {
				commit = setting.Value
			}
		case "vcs.time":
			if date == "0001-01-01" {
				date = setting.Value
			}
		}
	}
}

// shortCommit keeps the first 7 characters of the hash; a hash shorter than
// that is printed as-is.
func shortCommit(c string) string {
	return c[:min(len(c), 7)]
}

func printVersion(w io.Writer) {
	_, _ = fmt.Fprintf(w, "%s v%s (%s) %s\n", name, version, shortCommit(commit), date)
}

// MainConfig is everything the CLI accepts, one field per flag.
type MainConfig struct {
	alpn       string
	insecure   bool
	servername string
	silent     bool
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

	// Every usage error leaves the same way: the reason, then the usage.
	fail := func(err error) {
		_, _ = fmt.Fprintf(os.Stderr, "%s: %s\n", name, err)
		fs.Usage()
		os.Exit(2)
	}

	fs.StringVar(&cfg.alpn, "alpn", "", "acceptable protocols, ex: 'h2,http/1.1' 'ssh' (unset: no ALPN is offered)")
	fs.BoolVar(&cfg.insecure, "k", false, "alias for --insecure")
	fs.BoolVar(&cfg.silent, "s", false, "alias of --silent")
	fs.StringVar(&cfg.servername, "servername", "", "specify a servername different from <remote> (to disable SNI use an IP as <remote> and do not use this option)")
	fs.BoolVar(&cfg.insecure, "insecure", false, "ignore bad TLS/SSL/HTTPS certificates")
	fs.BoolVar(&cfg.silent, "silent", false, "less verbose output")

	// Version and help work even when the rest of the arguments are junk, so
	// they are handled before parsing.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-V", "-version", "--version", "version":
			printVersion(os.Stdout)
			os.Exit(0)
		case "help", "-help", "--help":
			// fs.Usage prints the version, so this is the only place it is shown.
			fs.SetOutput(os.Stdout)
			fs.Usage()
			os.Exit(0)
		}
	}

	if err := fs.Parse(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		// ContinueOnError has already printed the reason; 2 is the usage code.
		os.Exit(2)
	}

	n := fs.NArg()
	remotestr := fs.Arg(0)
	localstr := fs.Arg(1)

	if n != 2 {
		// The local side may be omitted when stdin is piped: read stdin, write
		// stdout instead of listening.
		stat, err := os.Stdin.Stat()
		if err == nil && n == 1 && (stat.Mode()&os.ModeCharDevice) == 0 {
			localstr = "-"
		} else {
			fail(fmt.Errorf("expected <remote> and <local>, got %d arguments", n))
		}
	}

	tun := &sclient.Tunnel{
		RemotePort:         443,
		LocalAddress:       "localhost",
		InsecureSkipVerify: cfg.insecure,
		ServerName:         cfg.servername,
		Silent:             cfg.silent,
		NextProtos:         parseOptionList(cfg.alpn),
	}

	remote := strings.Split(remotestr, ":")
	if len(remote) == 2 {
		port, err := strconv.Atoi(remote[1])
		if err != nil {
			fail(fmt.Errorf("%q is not a port", remote[1]))
		}
		tun.RemotePort = port
	} else if len(remote) != 1 {
		fail(fmt.Errorf("%q: expected <remote> or <remote>:<port>", remotestr))
	}
	tun.RemoteAddress = remote[0]

	if localstr == "-" || localstr == "|" {
		// stdin/stdout instead of a local listener
		tun.LocalAddress = localstr
		tun.LocalPort = -1
	} else {
		local := strings.Split(localstr, ":")
		if len(local) == 1 {
			port, err := strconv.Atoi(local[0])
			if err != nil {
				fail(fmt.Errorf("%q is not a port", local[0]))
			}
			tun.LocalPort = port
		} else {
			port, err := strconv.Atoi(local[1])
			if err != nil {
				fail(fmt.Errorf("%q is not a port", local[1]))
			}
			tun.LocalAddress = local[0]
			tun.LocalPort = port
		}
	}

	if err := tun.DialAndListen(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}

// parseOptionList parses "a,b,c", "a b c", and "a, b, c" the same way.
func parseOptionList(optionList string) []string {
	optionList = strings.TrimSpace(optionList)
	if optionList == "" {
		return nil
	}
	return strings.Fields(strings.ReplaceAll(optionList, ",", " "))
}
