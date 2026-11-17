// ssh-tls-proxy is the SSH-specific tool: it puts an SSH client onto a server
// that speaks SSH through TLS, probing the plain SSH port and the TLS port at
// the same time and relaying the client onto whichever answers.
//
//	go get github.com/therootcompany/sclient/cmd/ssh-tls-proxy
//	ssh -o ProxyCommand='ssh-tls-proxy --ssh-port %p %h:443' example.com
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

const name = "ssh-tls-proxy"

const (
	defaultSSHPort = 22
	defaultTLSPort = 443
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

func printVersion(w io.Writer) { stamp.Print(w) }

type MainConfig struct {
	host       string
	servername string
	listen     string
	localHost  string
	localPort  int
	stderr     string
	alpn       string
	sshPort    int
	tlsPort    int
	tcpTimeout float64
	tlsTimeout float64
	insecure   bool
	silent     bool
	verbose    bool
}

func usage(fs *flag.FlagSet) {
	w := fs.Output()
	printVersion(w)
	_, _ = fmt.Fprintf(w, "\nUSAGE: %s [flags] <host>[:tls-port]\n", name)
	_, _ = fmt.Fprintf(w, "\n   ex: ssh -o ProxyCommand='%s --ssh-port %%p %%h:443' example.com\n", name)
	_, _ = fmt.Fprintf(w, "      (stdio: the SSH client is stdin and stdout)\n")
	_, _ = fmt.Fprintf(w, "\n   ex: %s --listen localhost:2222 example.com:443\n", name)
	_, _ = fmt.Fprintf(w, "      (stunnel-style: SSH clients connect to a local port)\n")
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
	fs.IntVar(&cfg.sshPort, "ssh-port", defaultSSHPort, "plain SSH port to probe alongside the TLS port")
	fs.IntVar(&cfg.tlsPort, "tls-port", defaultTLSPort, "TLS port the SSH server is wrapped in")
	fs.StringVar(&cfg.alpn, "alpn", "ssh", "protocols the TLS connection must negotiate; '' turns the gate off")
	fs.StringVar(&cfg.servername, "servername", "", "SNI name, and the host the banner must declare (default: <host>)")
	fs.StringVar(&cfg.listen, "listen", "", "bind a local port instead of relaying stdin/stdout, ex localhost:2222")
	fs.StringVar(&cfg.stderr, "stderr", "", "where diagnostics go, ex ssh-tls-proxy.log or /dev/null")
	fs.Float64Var(&cfg.tcpTimeout, "tcp-timeout", 0, "seconds for the TCP connect, DNS included (0 = default, 5s)")
	fs.Float64Var(&cfg.tlsTimeout, "tls-timeout", 0, "seconds for the TLS handshake (0 = auto, 3x the connect)")
	fs.BoolVar(&cfg.insecure, "k", false, "alias for --insecure")
	fs.BoolVar(&cfg.insecure, "insecure", false, "ignore bad TLS (SSL/HTTPS) certificates")
	fs.BoolVar(&cfg.silent, "s", false, "alias of --silent")
	fs.BoolVar(&cfg.silent, "silent", false, "less verbose output")
	fs.BoolVar(&cfg.verbose, "v", false, "alias of --verbose")
	fs.BoolVar(&cfg.verbose, "verbose", false, "name every candidate, its banner, and why it lost")
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

	args := fs.Args()
	if len(args) != 1 {
		failUsage(fs, "want <host>[:tls-port]")
	}

	host, tlsPort, err := hostAndPort(args[0])
	if err != nil {
		failUsage(fs, "host: "+err.Error())
	}
	if tlsPort != 0 {
		cfg.tlsPort = tlsPort // a port on the address names the TLS side
	}
	if err := cli.PortOf("ssh-port", cfg.sshPort); err != nil {
		failUsage(fs, err.Error())
	}
	if err := cli.PortOf("tls-port", cfg.tlsPort); err != nil {
		failUsage(fs, err.Error())
	}
	if cfg.listen != "" {
		host, port, err := listenAddr(cfg.listen)
		if err != nil {
			failUsage(fs, "--listen: "+err.Error())
		}
		cfg.localHost, cfg.localPort = host, port
	}

	cfg.host = host

	// SIGINT or SIGTERM cancels ctx, which ends the session.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, cfg); err != nil {
		// ErrNoServer already named every candidate that lost.
		if !errors.Is(err, sclient.ErrNoServer) {
			_, _ = fmt.Fprintf(os.Stderr, "%s: %s\n", cfg.host, err)
		}
		os.Exit(1)
	}
}

// run builds the proxy config and serves one session: stdio, or a local listener.
// run serves one SSH session through the library: stdio, or a local listener.
// The command is a wrapper around sclient.Tunnel, the same entry point the
// library's own users get.
func run(ctx context.Context, cfg MainConfig) error {
	tun := &sclient.Tunnel{
		RemoteAddress:      cfg.host,
		RemotePort:         cfg.tlsPort,
		SSHPort:            cfg.sshPort,
		ServerName:         cfg.servername,
		NextProtos:         alpnList(cfg.alpn),
		TCPTimeout:         cli.Seconds(cfg.tcpTimeout),
		TLSTimeout:         cli.Seconds(cfg.tlsTimeout),
		InsecureSkipVerify: cfg.insecure,
		Verbose:            cfg.verbose,
		Silent:             cfg.silent,
	}

	if cfg.listen == "" {
		tun.LocalAddress = "-" // the SSH client is stdin and stdout
		return tun.DialAndListenContext(ctx)
	}

	tun.LocalAddress = cfg.localHost
	tun.LocalPort = cfg.localPort
	return tun.DialAndListenContext(ctx)
}

// listenAddr parses --listen <host>:<port>; the port is required.
func listenAddr(s string) (string, int, error) {
	host, rawPort, hasPort, err := cli.SplitHostPort(s)
	if err != nil {
		return "", 0, err
	}
	if !hasPort {
		return "", 0, fmt.Errorf("want <host>:<port>, got %q", s)
	}
	port, err := cli.ParsePort(rawPort)
	if err != nil {
		return "", 0, err
	}
	return host, port, nil
}

// hostAndPort parses <host> or <host>:<port>. Without a port the caller keeps the
// TLS default.
func hostAndPort(s string) (string, int, error) {
	host, rawPort, hasPort, err := cli.SplitHostPort(s)
	if err != nil {
		return "", 0, err
	}
	if !hasPort {
		return host, 0, nil
	}
	port, err := cli.ParsePort(rawPort)
	if err != nil {
		return "", 0, fmt.Errorf("%q: %w", s, err)
	}
	return host, port, nil
}

// alpnList is --alpn as offered. The default "ssh" is the gate; an explicit empty
// list turns it off.
func alpnList(raw string) []string {
	if list := cli.Options(raw); list != nil {
		return list
	}
	return []string{}
}
