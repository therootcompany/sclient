package main

import (
	"crypto/tls"
	"flag"
	"fmt"
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
		RemotePort:   443,
		LocalAddress: "localhost",
		Silent:       silent,
		GetTLSConfig: func() *tls.Config {
			return &tls.Config{
				ServerName:         servername,
				NextProtos:         alpns,
				InsecureSkipVerify: insecure,
			}
		},
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
