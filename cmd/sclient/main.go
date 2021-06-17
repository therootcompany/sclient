package main

import (
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
	fmt.Fprintf(os.Stderr, "\nsclient %s\n"+
		"\nusage: sclient <remote> <local>\n"+
		"\n"+
		"   ex: sclient example.com 3000\n"+
		"      (sclient example.com:443 localhost:3000)\n"+
		"\n"+
		"   ex: sclient example.com:8443 0.0.0.0:4080\n"+
		"\n", ver())
	flag.PrintDefaults()
	fmt.Println()
}

func main() {
	if len(os.Args) >= 2 {
		if "version" == strings.TrimLeft(os.Args[1], "-") {
			fmt.Printf("%s\n", ver())
			os.Exit(0)
			return
		}
	}

	flag.Usage = usage
	insecure := flag.Bool("k", false, "ignore bad TLS/SSL/HTTPS certificates")
	quiet := flag.Bool("q", false, "don't output connection established messages")
	servername := flag.String("servername", "", "specify a servername different from <remote> (to disable SNI use an IP as <remote> and do use this option)")
	flag.BoolVar(insecure, "insecure", false, "ignore bad TLS/SSL/HTTPS certificates")
	flag.BoolVar(quiet, "quiet", false, "don't output connection established messages")
	flag.Parse()
	remotestr := flag.Arg(0)
	localstr := flag.Arg(1)

	i := flag.NArg()
	if 2 != i {
		// We may omit the second argument if we're going straight to stdin
		if stat, _ := os.Stdin.Stat(); 1 == i && (stat.Mode()&os.ModeCharDevice) == 0 {
			localstr = "|"
		} else {
			usage()
			os.Exit(1)
		}
	}

	sclient := &sclient.Tunnel{
		RemotePort:         443,
		LocalAddress:       "localhost",
		InsecureSkipVerify: *insecure,
		ServerName:         *servername,
		Quiet:              *quiet,
	}

	remote := strings.Split(remotestr, ":")
	//remoteAddr, remotePort, err := net.SplitHostPort(remotestr)
	if 2 == len(remote) {
		rport, err := strconv.Atoi(remote[1])
		if nil != err {
			usage()
			os.Exit(0)
		}
		sclient.RemotePort = rport
	} else if 1 != len(remote) {
		usage()
		os.Exit(0)
	}
	sclient.RemoteAddress = remote[0]

	if "-" == localstr || "|" == localstr {
		// User may specify stdin/stdout instead of net
		sclient.LocalAddress = localstr
		sclient.LocalPort = -1
	} else {
		// Test that argument is a local address
		local := strings.Split(localstr, ":")

		if 1 == len(local) {
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
