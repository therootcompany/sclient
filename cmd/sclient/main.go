package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/therootcompany/sclient"
	"github.com/therootcompany/sclient/internal/cli"
	"github.com/therootcompany/sclient/internal/diagnostics"
)

const name = "sclient"

const (
	defaultRemotePort = 443
	defaultLocalHost  = "localhost"
)

// Stamped by goreleaser at release time (-X main.version, -X main.commit,
// -X main.date); stamp normalizes what is left for go run and plain go build.
var (
	version = ""
	commit  = ""
	date    = ""
)

var stamp cli.Version

func init() { stamp = cli.Stamp(name, version, commit, date) }

type MainConfig struct {
	alpn       string
	insecure   bool
	servername string
	silent     bool
	verbose    bool
	ssh        bool
	sshPort    int
	stderr     string
	tcpTimeout float64
	tlsTimeout float64
	remote     string
	local      string
}

func printVersion(w io.Writer) { stamp.Print(w) }

func usage(fs *flag.FlagSet) {
	w := fs.Output()
	printVersion(w)
	_, _ = fmt.Fprintf(w, "\nUSAGE: %s [flags] <remote> <local>\n", name)
	_, _ = fmt.Fprintf(w, "\n   ex: %s example.com 3000\n", name)
	_, _ = fmt.Fprintf(w, "      (example.com:443 <= localhost:3000)\n")
	_, _ = fmt.Fprintf(w, "\n   ex: %s example.com:8443 0.0.0.0:4080\n", name)
	_, _ = fmt.Fprintf(w, "\n   ex: %s example.com:443 -\n", name)
	_, _ = fmt.Fprintf(w, "\n   ex: %s --ssh-port 22 example.com:443 localhost:3000\n", name)
	_, _ = fmt.Fprintf(w, "      (SSH mode: the plain port and the TLS port are probed at once)\n")
	_, _ = fmt.Fprintf(w, "\n   ex: ssh -o ProxyCommand='%s --ssh-port %%p %%h:443' example.com\n", name)
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
	fs.BoolVar(&cfg.verbose, "v", false, "alias of --verbose")
	fs.BoolVar(&cfg.verbose, "verbose", false, "show what each dial did (SSH mode: every candidate and its banner)")
	fs.BoolVar(&cfg.ssh, "ssh", false, "SSH mode shorthand for --ssh-port 22")
	fs.IntVar(&cfg.sshPort, "ssh-port", 0, "plain SSH port to probe alongside <remote>; turns on SSH mode (0 = plain TLS tunnel)")
	fs.StringVar(&cfg.stderr, "stderr", "", "where diagnostics go, ex sclient.log or /dev/null")
	fs.Float64Var(&cfg.tcpTimeout, "tcp-timeout", 0, "seconds for the TCP connect, DNS included (0 = default, 5s)")
	fs.Float64Var(&cfg.tlsTimeout, "tls-timeout", 0, "seconds for the TLS handshake (0 = auto, 3x the connect)")
	fs.Usage = func() { usage(fs) }

	// Before parsing: -V and help survive junk arguments.
	cli.PreParse(stamp, fs, os.Args[1:])

	if err := fs.Parse(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		os.Exit(2) // flag printed the error and the usage
	}

	// stdout is the payload; --stderr says where the rest goes.
	os.Stderr = diagnostics.Target(name, cfg.stderr)

	// Visit sees only the flags the operator gave, so it runs after Parse.
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })

	sshPort, err := sshMode(cfg.ssh, cfg.sshPort, set["ssh-port"])
	if err != nil {
		failUsage(fs, err.Error())
	}

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
		Verbose:            cfg.verbose,
		NextProtos:         alpnList(cfg.alpn, set["alpn"], sshPort > 0),
		TCPTimeout:         cli.Seconds(cfg.tcpTimeout),
		TLSTimeout:         cli.Seconds(cfg.tlsTimeout),
		SSHPort:            sshPort,
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
		// SSH mode already named every candidate that lost.
		if !errors.Is(err, sclient.ErrNoServer) {
			_, _ = fmt.Fprintf(os.Stderr, "%s: %s\n", tun.RemoteAddress, err)
		}
		os.Exit(1)
	}
}

// sshMode resolves --ssh against --ssh-port. Naming a port is the mode; --ssh
// is the shorthand for 22, and an explicit port always wins. A named zero is a
// mistake, not "off".
func sshMode(ssh bool, sshPort int, named bool) (int, error) {
	if sshPort < 0 || sshPort > 65535 {
		return 0, fmt.Errorf("--ssh-port must be 1-65535")
	}
	if sshPort > 0 {
		return sshPort, nil
	}
	if named {
		return 0, errors.New("--ssh-port must be 1-65535 (omit it for a plain TLS tunnel)")
	}
	if ssh {
		return 22, nil
	}
	return 0, nil
}

// alpnList is --alpn as offered. In SSH mode an unset list takes "ssh"; an
// explicit empty one offers nothing, which turns the ALPN gate off. In plain
// mode an unset list is left unset so the tunnel can sniff the local side.
func alpnList(raw string, explicit, sshMode bool) []string {
	list := cli.Options(raw)
	if list != nil {
		return list
	}
	if explicit {
		return []string{}
	}
	if sshMode {
		return []string{"ssh"}
	}
	return nil
}

// remoteAddr parses <host> or <host>:<port>; a bare host gets port 443.
func remoteAddr(s string) (string, int, error) {
	host, rawPort, hasPort, err := cli.SplitHostPort(s)
	if err != nil {
		return "", 0, err
	}
	if !hasPort {
		return host, defaultRemotePort, nil
	}
	port, err := cli.ParsePort(rawPort)
	if err != nil {
		return "", 0, fmt.Errorf("remote %q: %w", s, err)
	}
	return host, port, nil
}

// localAddr parses <port> or <host>:<port>; a bare port listens on localhost.
func localAddr(s string) (string, int, error) {
	host, rawPort, hasPort, err := cli.SplitHostPort(s)
	if err != nil {
		return "", 0, err
	}
	if !hasPort {
		port, err := cli.ParsePort(s)
		if err != nil {
			return "", 0, fmt.Errorf("local %q: want <port> or <host>:<port>", s)
		}
		return defaultLocalHost, port, nil
	}
	port, err := cli.ParsePort(rawPort)
	if err != nil {
		return "", 0, fmt.Errorf("local %q: %w", s, err)
	}
	return host, port, nil
}
