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
	"strconv"
	"strings"
	"syscall"
	"time"

	sclient "git.rootprojects.org/root/sclient.go"
	"git.rootprojects.org/root/sclient.go/internal/sshtlsproxy"
)

var (
	// commit refers to the abbreviated commit hash
	commit = "0000000"
	// version refers to the most recent tag, plus any commits made since then
	version = "v0.0.0-pre0+0000000"
	// GitTimestamp refers to the timestamp of the most recent commit
	date = "0000-00-00T00:00:00+0000"
)

func ver() string {
	return fmt.Sprintf("sclient %s (%s) %s", version, commit[:7], date)
}

func usage() {
	fmt.Fprintf(os.Stderr, "\n%s\n"+
		"\nusage: sclient <remote> <local>\n"+
		"\n"+
		"   ex: sclient example.com 3000\n"+
		"      (sclient example.com:443 localhost:3000)\n"+
		"\n"+
		"   ex: sclient example.com:8443 0.0.0.0:4080\n"+
		"\n"+
		"   ex: sclient example.com:443 -\n"+
		"\n"+
		"   ex: ssh -o ProxyCommand='sclient --ssh --ssh-port %%p %%n' example.com\n"+
		"      (dual-port SSH probe; the local side must be an SSH client)\n"+
		"\n"+
		"exit codes (--ssh): 0 done, 1 failure, 2 usage, 255 no usable server\n"+
		"\n", ver())
	flag.PrintDefaults()
	fmt.Println()
}

func main() {
	// ssh nulls a ProxyCommand's stderr; Stderr() redirects it to the tty.
	// log captured os.Stderr at its own init, so log.SetOutput(os.Stderr)
	// would have to be called separately to route it too.
	os.Stderr = sshtlsproxy.Stderr()
	if len(os.Args) >= 2 {
		if os.Args[1] == "-V" || strings.TrimLeft(os.Args[1], "-") == "version" {
			fmt.Printf("%s\n", ver())
			os.Exit(0)
			return
		}
	}

	var alpnList string
	var insecure bool
	var servername string
	var silent bool
	var sshMode bool
	var sshPort int
	var timeoutSec float64

	flag.Usage = usage

	flag.StringVar(&alpnList, "alpn", "", "acceptable protocols, ex: 'h2,http/1.1' 'http/1.1' 'ssh'")
	flag.BoolVar(&insecure, "k", false, "alias for --insecure")
	flag.BoolVar(&silent, "s", false, "alias of --silent")
	flag.StringVar(&servername, "servername", "", "specify a servername different from <remote> (to disable SNI use an IP as <remote> and do not use this option)")
	flag.BoolVar(&insecure, "insecure", false, "ignore bad TLS/SSL/HTTPS certificates")
	flag.BoolVar(&silent, "silent", false, "less verbose output")
	flag.BoolVar(&sshMode, "ssh", false, "SSH mode: probe the plain (22) and TLS (443) ports at once and splice the winner; the local side must be an SSH client")
	flag.IntVar(&sshPort, "ssh-port", 0, "plain-SSH server port, default 22 (--ssh)")
	flag.Float64Var(&timeoutSec, "timeout", 0, "seconds to wait until a remote connection is ready to communicate (TCP connect + TLS handshake). Plain mode: default 3, 0 = no limit. --ssh: the engine's probe clock, default 3")

	flag.Parse()

	// Visit sees only flags the operator gave, so it runs after Parse.
	set := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { set[f.Name] = true })

	alpns := splitList(alpnList)
	remotestr := flag.Arg(0)
	localstr := flag.Arg(1)

	i := flag.NArg()
	if i != 2 {
		// a missing second argument means stdio
		if stat, _ := os.Stdin.Stat(); i == 1 && (stat.Mode()&os.ModeCharDevice) == 0 {
			localstr = "|"
		} else {
			usage()
			os.Exit(1)
		}
	}

	sclient := &sclient.Tunnel{
		RemotePort:         443,
		LocalAddress:       "localhost",
		InsecureSkipVerify: insecure,
		ServerName:         servername,
		Silent:             silent,
		NextProtos:         alpns,
		Timeout:            time.Duration(plainTimeout(timeoutSec, set["timeout"]) * float64(time.Second)),
	}

	if sshMode {
		// --ssh replaces the Tunnel: the engine is the transport, and runSSH
		// only returns when the listener is shut down.
		runSSH(remotestr, localstr, servername, sshALPN(alpnList, set["alpn"]), insecure, silent, sshPort, timeoutSec)
		return
	}

	remoteHost, remotePort, err := remoteAddr(remotestr, 443)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sclient: %s\n", err)
		usage()
		os.Exit(2)
	}
	sclient.RemoteAddress, sclient.RemotePort = remoteHost, remotePort

	if localstr == "-" || localstr == "|" {
		sclient.LocalAddress = localstr
		sclient.LocalPort = -1
	} else {
		lhost, lport, err := localAddr(localstr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "sclient: %s\n", err)
			usage()
			os.Exit(2)
		}
		sclient.LocalAddress, sclient.LocalPort = lhost, lport
	}

	if err := sclient.DialAndListen(); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
	}
}

// splitList splits "a,b,c" "a b c" and "a, b, c" the same.
func splitList(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	return strings.Fields(strings.ReplaceAll(s, ",", " "))
}

// remoteAddr parses a remote target: <host>, <host>:<port> or
// [<ipv6>]:<port>. A bare host takes the default port.
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

// localAddr parses the local listen address: a bare number is a port on
// localhost; host:port (or [ipv6]:port) sets both.
func localAddr(s string) (string, int, error) {
	s = strings.TrimSpace(s)
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		p, err := strconv.Atoi(s)
		if err != nil {
			return "", 0, fmt.Errorf("%q: expected <port> or <host>:<port>", s)
		}
		return "localhost", p, nil
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return "", 0, fmt.Errorf("%q: %q is not a port", s, port)
	}
	return host, p, nil
}

// defaultPlainTimeout bounds one plain (non-ssh) remote connect - TCP
// connect plus TLS handshake - in seconds. OpenSSH's ConnectTimeout has no
// default, so there is no convention to copy; 3s matches the engine's probe
// clock and is roughly 20x the measured connect+handshake for a public host.
const defaultPlainTimeout = 3

// plainTimeout is the operator's --timeout for plain mode, or the default
// when unset. An explicit --timeout 0 means "no limit".
func plainTimeout(raw float64, explicit bool) float64 {
	if explicit {
		return raw
	}
	return defaultPlainTimeout
}

// runSSH is the --ssh transport: the stdio pair, or every accepted local
// connection, goes through the engine. The local side must be an SSH
// client; it returns when Ctrl-C or SIGTERM closes the listener.
func runSSH(remotestr, localstr, servername string, alpns []string, insecure, silent bool, sshPort int, timeoutSec float64) {
	// Ctrl-C or SIGTERM cancels in-flight probes and sessions. Plain mode has
	// no shutdown path, so it keeps the OS default: the signal ends the
	// process.
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	host, tlsPort, err := remoteAddr(remotestr, 443)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sclient: %s\n", err)
		usage()
		os.Exit(2)
	}
	cfg := newSSHConfig(host, tlsPort, servername, alpns, insecure, silent, sshPort, timeoutSec)

	if localstr == "-" || localstr == "|" {
		err := sshtlsproxy.Probe(ctx, cfg, os.Stdin, os.Stdout, os.Stderr)
		switch {
		case err == nil: // 0: session done
			os.Exit(0)
		case errors.Is(err, sshtlsproxy.ErrNoServer): // 255: ssh convention
			os.Exit(255)
		default: // 1: client-side failure
			_, _ = fmt.Fprintf(os.Stderr, "sclient: %s: %s\n", cfg.Host, err)
			os.Exit(1)
		}
	}

	lhost, lport, err := localAddr(localstr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sclient: %s\n", err)
		usage()
		os.Exit(2)
	}

	ln, err := net.Listen("tcp", net.JoinHostPort(lhost, strconv.Itoa(lport)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "sclient: %s\n", err)
		os.Exit(1)
	}
	if !silent {
		_, _ = fmt.Fprintf(os.Stdout, "[listening] %s:%d => %s:%d (ssh)\n", lhost, lport, cfg.Host, cfg.TLSPort)
	}
	sshListen(ctx, cfg, ln, os.Stderr)
}

// sshListen gives each accepted connection its own probe. Cancelling ctx
// closes the listener, which ends the accept loop.
func sshListen(ctx context.Context, cfg sshtlsproxy.Config, ln net.Listener, errOut io.Writer) {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			_ = sshtlsproxy.Probe(ctx, cfg, conn, conn, errOut)
		}()
	}
}

// newSSHConfig builds the engine config from an already-parsed host and
// TLS port. The engine uses a supplied tls.Config as-is, so the TLS 1.2
// floor comes from here.
func newSSHConfig(host string, tlsPort int, servername string, alpns []string, insecure, silent bool, sshPort int, timeoutSec float64) sshtlsproxy.Config {
	if servername == "" {
		servername = host // an IP literal: Go omits SNI itself
	}
	return sshtlsproxy.Config{
		Name:    "sclient",
		Host:    host,
		SSHPort: sshPort, // 0: the engine default 22
		TLSPort: tlsPort,
		ALPN:    alpns,                                            // as offered; ssh mode always supplies a list
		Timeout: time.Duration(timeoutSec * float64(time.Second)), // 0: the engine default 3s
		Silent:  silent,
		TLS: &tls.Config{
			ServerName:         servername,
			NextProtos:         alpns,
			InsecureSkipVerify: insecure,
			MinVersion:         tls.VersionTLS12,
		},
	}
}

// sshALPN resolves --alpn for --ssh mode: unset takes [ssh], an explicit
// list is as given, an explicit empty list means no ALPN requirement.
func sshALPN(raw string, explicit bool) []string {
	a := splitList(raw)
	if explicit && a == nil {
		return []string{}
	}
	if a == nil {
		return []string{"ssh"}
	}
	return a
}
