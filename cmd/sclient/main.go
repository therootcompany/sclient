package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/therootcompany/sclient"
)

const (
	defaultRemotePort = 443
	defaultLocalHost  = "localhost"
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
	var stderrPath string
	var tcpTimeout float64
	var tlsTimeout float64

	flag.Usage = usage

	flag.StringVar(&alpnList, "alpn", "", "acceptable protocols, ex: 'h2,http/1.1' 'http/1.1' 'ssh'")
	flag.BoolVar(&insecure, "k", false, "alias for --insecure")
	flag.BoolVar(&silent, "s", false, "alias of --silent")
	flag.StringVar(&servername, "servername", "", "specify a servername different from <remote> (to disable SNI use an IP as <remote> and do not use this option)")
	flag.BoolVar(&insecure, "insecure", false, "ignore bad TLS/SSL/HTTPS certificates")
	flag.BoolVar(&silent, "silent", false, "less verbose output")
	flag.StringVar(&stderrPath, "stderr", "", "a file or device, ex sclient.log or /dev/null")
	flag.Float64Var(&tcpTimeout, "tcp-timeout", 0, "seconds for the TCP connect, DNS included (0 = default, 5s)")
	flag.Float64Var(&tlsTimeout, "tls-timeout", 0, "seconds for the TLS handshake, from the connect (0 = auto, 3x connection time)")

	flag.Parse()

	alpns := parseOptionList(alpnList)

	// stdout is the payload; --stderr says where the rest goes.
	os.Stderr = stderrTarget(stderrPath)

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

	tun := &sclient.Tunnel{
		InsecureSkipVerify: insecure,
		ServerName:         servername,
		Silent:             silent,
		NextProtos:         alpns,
		TCPTimeout:         toSeconds(tcpTimeout),
		TLSTimeout:         toSeconds(tlsTimeout),
	}

	remoteHost, remotePort, err := remoteAddr(remotestr)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "sclient: remote: %s\n", err)
		usage()
		os.Exit(1)
	}
	tun.RemoteAddress, tun.RemotePort = remoteHost, remotePort

	if localstr == "-" || localstr == "|" {
		// User may specify stdin/stdout instead of net
		tun.LocalAddress = localstr
		tun.LocalPort = -1
	} else {
		localHost, localPort, err := localAddr(localstr)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "sclient: local: %s\n", err)
			usage()
			os.Exit(1)
		}
		tun.LocalAddress, tun.LocalPort = localHost, localPort
	}

	// SIGINT or SIGTERM cancels ctx, which stops the tunnel.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := tun.DialAndListenContext(ctx); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%s\n", err)
		//usage()
		//os.Exit(6)
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
