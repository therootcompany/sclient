// ssh-tls-proxy is the SSH-specific tool: it puts an SSH client onto a server
// that speaks SSH through TLS, probing the plain SSH port and the TLS port at
// the same time and relaying the client onto whichever answers.
//
//	go get github.com/therootcompany/sclient/cmd/ssh-tls-proxy
//	ssh -o ProxyCommand='ssh-tls-proxy --ssh-port %p %h:443' example.com
package main

import (
	"cmp"
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

	"github.com/therootcompany/sclient/internal/diagnostics"
	"github.com/therootcompany/sclient/internal/ssh"
	"github.com/therootcompany/sclient/internal/tunnel"
)

const name = "ssh-tls-proxy"

const (
	defaultSSHPort = 22
	defaultTLSPort = 443
)

// Stamped by goreleaser at release time (-X main.version, -X main.commit,
// -X main.date); init() fills in what is left unset for go run and go build.
var (
	version = ""
	commit  = ""
	date    = ""
)

type MainConfig struct {
	host       string
	servername string
	listen     string
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
	os.Stderr = diagnostics.Target(name, cfg.stderr)

	args := fs.Args()
	if len(args) != 1 {
		failUsage(fs, "want <host>[:tls-port]")
	}

	host, tlsPort, err := hostPort(args[0])
	if err != nil {
		failUsage(fs, "host: "+err.Error())
	}
	if tlsPort != 0 {
		cfg.tlsPort = tlsPort // a port on the address names the TLS side
	}
	if err := checkPort("ssh-port", cfg.sshPort); err != nil {
		failUsage(fs, err.Error())
	}
	if err := checkPort("tls-port", cfg.tlsPort); err != nil {
		failUsage(fs, err.Error())
	}

	cfg.host = host

	// SIGINT or SIGTERM cancels ctx, which ends the session.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, cfg); err != nil {
		// ssh.ErrNoServer already named every candidate that lost.
		if !errors.Is(err, ssh.ErrNoServer) {
			_, _ = fmt.Fprintf(os.Stderr, "%s: %s\n", cfg.host, err)
		}
		os.Exit(1)
	}
}

// run builds the proxy config and serves one session: stdio, or a local listener.
func run(ctx context.Context, cfg MainConfig) error {
	alpn := alpnList(cfg.alpn)

	proxy := ssh.Config{
		Host:       cfg.host,
		ServerName: cfg.servername,
		SSHPort:    cfg.sshPort,
		TLSPort:    cfg.tlsPort,
		ALPN:       alpn,
		TCPTimeout: seconds(cfg.tcpTimeout),
		TLSTimeout: seconds(cfg.tlsTimeout),
		Verbose:    cfg.verbose,
		Silent:     cfg.silent,
		Dial: tunnel.Dial{
			ServerName:         cmp.Or(cfg.servername, cfg.host),
			NextProtos:         alpn,
			InsecureSkipVerify: cfg.insecure,
			TCPTimeout:         seconds(cfg.tcpTimeout),
			TLSTimeout:         seconds(cfg.tlsTimeout),
		},
	}

	if cfg.listen == "" {
		return ssh.Serve(ctx, proxy, tunnel.StdioConn("-"), os.Stderr)
	}
	return ssh.Listen(ctx, proxy, cfg.listen, os.Stderr)
}

// hostPort parses <host> or <host>:<port>. Without a port the caller keeps the
// TLS default.
func hostPort(s string) (string, int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", 0, errors.New("empty address")
	}

	host, rawPort, err := net.SplitHostPort(s)
	if err == nil {
		port, err := parsePort(rawPort)
		if err != nil {
			return "", 0, fmt.Errorf("%q: %w", s, err)
		}
		return host, port, nil
	}
	if !strings.Contains(s, ":") {
		return s, 0, nil
	}
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		return s[1 : len(s)-1], 0, nil
	}
	return "", 0, fmt.Errorf("%q: want <host>:<port>, or an IPv6 address in brackets", s)
}

// checkPort names a flag whose value is not a port.
func checkPort(flagName string, port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("--%s must be 1-65535, got %d", flagName, port)
	}
	return nil
}

func parsePort(raw string) (int, error) {
	port, err := strconv.Atoi(raw)
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("%q is not a port (1-65535)", raw)
	}
	return port, nil
}

func seconds(raw float64) time.Duration {
	if raw <= 0 {
		return 0
	}
	return time.Duration(raw * float64(time.Second))
}

// alpnList is --alpn as offered. The default "ssh" is the gate; an explicit
// empty list turns it off.
func alpnList(raw string) []string {
	list := parseOptionList(raw)
	if list == nil {
		return []string{}
	}
	return list
}

// parsers "a,b,c" "a b c" and "a, b, c" all the same
func parseOptionList(optionList string) []string {
	optionList = strings.TrimSpace(optionList)
	if optionList == "" {
		return nil
	}
	optionList = strings.ReplaceAll(optionList, ",", " ")
	return strings.Fields(optionList)
}
