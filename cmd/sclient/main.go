package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	sclient "git.coolaj86.com/coolaj86/sclient.go"
)

func usage() {
	fmt.Fprintf(os.Stderr, "\nusage: sclient <remote> <local>\n"+
		"\n"+
		"   ex: sclient example.com 3000\n"+
		"      (sclient example.com:443 localhost:3000)\n"+
		"\n"+
		"   ex: sclient example.com:8443 0.0.0.0:4080\n"+
		"\n")
	flag.PrintDefaults()
	fmt.Println()
}

func main() {
	flag.Usage = usage
	insecure := flag.Bool("k", false, "ignore bad TLS/SSL/HTTPS certificates")
	servername := flag.String("servername", "", "specify a servername different from <remote> (to disable SNI use an IP as <remote> and do use this option)")
	flag.BoolVar(insecure, "insecure", false, "ignore bad TLS/SSL/HTTPS certificates")
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

	opts := &sclient.PipeOpts{
		RemotePort:         443,
		LocalAddress:       "localhost",
		InsecureSkipVerify: *insecure,
		ServerName:         *servername,
	}

	remote := strings.Split(remotestr, ":")
	//remoteAddr, remotePort, err := net.SplitHostPort(remotestr)
	if 2 == len(remote) {
		rport, err := strconv.Atoi(remote[1])
		if nil != err {
			usage()
			os.Exit(0)
		}
		opts.RemotePort = rport
	} else if 1 != len(remote) {
		usage()
		os.Exit(0)
	}
	opts.RemoteAddress = remote[0]

	if "-" == localstr || "|" == localstr {
		// User may specify stdin/stdout instead of net
		opts.LocalAddress = localstr
		opts.LocalPort = -1
	} else {
		// Test that argument is a local address
		local := strings.Split(localstr, ":")

		if 1 == len(local) {
			lport, err := strconv.Atoi(local[0])
			if nil != err {
				usage()
				os.Exit(0)
			}
			opts.LocalPort = lport
		} else {
			lport, err := strconv.Atoi(local[1])
			if nil != err {
				usage()
				os.Exit(0)
			}
			opts.LocalAddress = local[0]
			opts.LocalPort = lport
		}
	}

	sclient := &sclient.Tun{}
	err := sclient.DialAndListen(opts)
	if nil != err {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		//usage()
		//os.Exit(6)
	}
}
