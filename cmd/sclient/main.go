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
	"strconv"
	"strings"
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
		"   ex: sclient --ssh example.com:443 -\n"+
		"      (dual-port SSH probe; the local side must be an SSH client)\n"+
		"\n"+
		"exit codes (--ssh): 0 done, 1 failure, 2 usage, 255 no usable server\n"+
		"\n", ver())
	flag.PrintDefaults()
	fmt.Println()
}

func main() {
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
	flag.Float64Var(&timeoutSec, "timeout", 0, "overall timeout in seconds, default 3 (--ssh)")

	flag.Parse()

	// Visit reports only the flags the operator actually gave, so it
	// runs after Parse.
	set := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { set[f.Name] = true })

	alpns := parseOptionList(alpnList)
	remotestr := flag.Arg(0)
	localstr := flag.Arg(1)

	i := flag.NArg()
	if i != 2 {
		// We may omit the second argument if we're going straight to stdin
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
	}

	if sshMode {
		// --ssh: the engine IS the transport; the Tunnel is unused.
		runSSH(remotestr, localstr, servername, sshALPN(alpnList, set["alpn"]), insecure, silent, sshPort, timeoutSec)
	}

	remote := strings.Split(remotestr, ":")
	//remoteAddr, remotePort, err := net.SplitHostPort(remotestr)
	if len(remote) == 2 {
		rport, err := strconv.Atoi(remote[1])
		if nil != err {
			usage()
			os.Exit(0)
		}
		sclient.RemotePort = rport
	} else if len(remote) != 1 {
		usage()
		os.Exit(0)
	}
	sclient.RemoteAddress = remote[0]

	if localstr == "-" || localstr == "|" {
		// User may specify stdin/stdout instead of net
		sclient.LocalAddress = localstr
		sclient.LocalPort = -1
	} else {
		// Test that argument is a local address
		local := strings.Split(localstr, ":")

		if len(local) == 1 {
			lport, err := strconv.Atoi(local[0])
			if nil != err {
				usage()
				os.Exit(0)
			}
			sclient.LocalPort = lport
		} else {
			lport, err := strconv.Atoi(local[1])
			if nil != err {
				usage()
				os.Exit(0)
			}
			sclient.LocalAddress = local[0]
			sclient.LocalPort = lport
		}
	}

	err := sclient.DialAndListen()
	if nil != err {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		//usage()
		//os.Exit(6)
	}
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

// runSSH is the --ssh transport: the stdio pair, or every connection
// accepted from the local listener, goes through the sshtlsproxy
// engine — dual-port probe, banner exchange, splice. The local side
// must be an SSH client: its first line must be an SSH-2.0 banner.
// It never returns.
func runSSH(remotestr, localstr, servername string, alpns []string, insecure, silent bool, sshPort int, timeoutSec float64) {
	cfg, err := newSSHConfig(remotestr, servername, alpns, insecure, silent, sshPort, timeoutSec)
	if nil != err {
		fmt.Fprintf(os.Stderr, "sclient: %s\n", err)
		usage()
		os.Exit(2)
	}

	if localstr == "-" || localstr == "|" {
		exitSSH(cfg.Host, sshtlsproxy.Probe(context.Background(), cfg, os.Stdin, os.Stdout, os.Stderr))
	}

	// local listener: the same naive split as the plain mode above
	local := strings.Split(localstr, ":")
	lhost, lport := "localhost", 0
	if len(local) == 1 {
		lport, err = strconv.Atoi(local[0])
	} else {
		lhost = local[0]
		lport, err = strconv.Atoi(local[1])
	}
	if nil != err {
		usage()
		os.Exit(2)
	}

	ln, err := net.Listen("tcp", net.JoinHostPort(lhost, strconv.Itoa(lport)))
	if nil != err {
		fmt.Fprintf(os.Stderr, "sclient: %s\n", err)
		os.Exit(1)
	}
	if !silent {
		_, _ = fmt.Fprintf(os.Stdout, "[listening] %s:%d => %s:%d (ssh)\n", lhost, lport, cfg.Host, cfg.TLSPort)
	}
	sshListen(cfg, ln, os.Stderr)
}

// sshListen serves --ssh connections on ln until the listener is
// closed; each connection gets its own probe.
func sshListen(cfg sshtlsproxy.Config, ln net.Listener, errOut io.Writer) {
	for {
		conn, err := ln.Accept()
		if nil != err {
			return
		}
		go func(conn net.Conn) {
			_ = sshtlsproxy.Probe(context.Background(), cfg, conn, conn, errOut)
		}(conn)
	}
}

// newSSHConfig builds the engine config for one --ssh target. A bare
// host takes the TLS port 443; host:port takes that port as the TLS
// port. The caller's *tls.Config is used as-is by the engine, so the
// TLS 1.2 floor comes from here, not the engine default.
func newSSHConfig(remotestr, servername string, alpns []string, insecure, silent bool, sshPort int, timeoutSec float64) (sshtlsproxy.Config, error) {
	host := remotestr
	tlsPort := 443
	if h, p, err := net.SplitHostPort(remotestr); nil == err {
		port, aerr := strconv.Atoi(p)
		if nil != aerr || port <= 0 || port > 65535 {
			return sshtlsproxy.Config{}, fmt.Errorf("%q: the port after the colon is not a valid port", remotestr)
		}
		host, tlsPort = h, port
	}
	if host == "" {
		return sshtlsproxy.Config{}, fmt.Errorf("empty host")
	}
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
	}, nil
}

// sshALPN resolves --alpn for --ssh mode: an unset flag takes the
// engine default [ssh] (made explicit here because the caller
// supplies the tls.Config); an explicit list is as given; an explicit
// --alpn ” means no ALPN requirement (non-nil empty: nothing
// offered, no note).
func sshALPN(raw string, explicit bool) []string {
	a := parseOptionList(raw)
	if explicit && nil == a {
		a = []string{}
	}
	if nil == a {
		a = []string{"ssh"}
	}
	return a
}

// exitSSH maps the engine result to an exit code: 0 done, 255 no
// usable server (ssh convention; the diagnostic report is already on
// stderr), 1 client-side failure.
func exitSSH(host string, err error) {
	switch {
	case nil == err:
		os.Exit(0)
	case errors.Is(err, sshtlsproxy.ErrNoServer):
		os.Exit(255)
	default:
		fmt.Fprintf(os.Stderr, "sclient: %s: %s\n", host, err)
		os.Exit(1)
	}
}
