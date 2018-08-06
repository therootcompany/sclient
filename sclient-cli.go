package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func usage() {
	fmt.Fprintf(os.Stderr, "\nusage: go run sclient*.go <remote> <local>\n"+
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
	flag.BoolVar(insecure, "insecure", false, "ignore bad TLS/SSL/HTTPS certificates")
	flag.Parse()

	// NArg, Arg, Args
	i := flag.NArg()
	if 2 != i {
		usage()
		os.Exit(0)
	}

	opts := &SclientOpts{}
	opts.RemotePort = 443
	opts.LocalAddress = "localhost"
	opts.InsecureSkipVerify = *insecure

	remote := strings.Split(flag.Arg(0), ":")
	//remoteAddr, remotePort, err := net.SplitHostPort(flag.Arg(0))
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

	local := strings.Split(flag.Arg(1), ":")
	//localAddr, localPort, err := net.SplitHostPort(flag.Arg(0))

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

	sclient := &Sclient{}
	err := sclient.DialAndListen(opts)
	if nil != err {
		usage()
		os.Exit(0)
	}
}
