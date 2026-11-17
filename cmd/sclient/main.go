package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	sclient "git.rootprojects.org/root/sclient.go"
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

	flag.Usage = usage

	flag.StringVar(&alpnList, "alpn", "", "acceptable protocols, ex: 'h2,http/1.1' 'http/1.1' 'ssh'")
	flag.BoolVar(&insecure, "k", false, "alias for --insecure")
	flag.BoolVar(&silent, "s", false, "alias of --silent")
	flag.StringVar(&servername, "servername", "", "specify a servername different from <remote> (to disable SNI use an IP as <remote> and do not use this option)")
	flag.BoolVar(&insecure, "insecure", false, "ignore bad TLS/SSL/HTTPS certificates")
	flag.BoolVar(&silent, "silent", false, "less verbose output")

	flag.Parse()

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

	remoteHost, remotePort, err := remoteAddr(remotestr, 443)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "sclient: %s\n", err)
		usage()
		os.Exit(0)
	}
	sclient.RemoteAddress, sclient.RemotePort = remoteHost, remotePort

	if localstr == "-" || localstr == "|" {
		// User may specify stdin/stdout instead of net
		sclient.LocalAddress = localstr
		sclient.LocalPort = -1
	} else {
		localHost, localPort, err := localAddr(localstr)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "sclient: %s\n", err)
			usage()
			os.Exit(0)
		}
		sclient.LocalAddress, sclient.LocalPort = localHost, localPort
	}

	if err := sclient.DialAndListen(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%s\n", err)
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

// parseOptionList parses "a,b,c", "a b c", and "a, b, c" the same
func parseOptionList(optionList string) []string {
	optionList = strings.TrimSpace(optionList)

	if len(optionList) == 0 {
		return nil
	}

	optionList = strings.ReplaceAll(optionList, ",", " ")
	options := strings.Fields(optionList)

	return options
}
