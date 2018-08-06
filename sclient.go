package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
)

type SclientOpts struct {
	RemoteAddress      string
	RemotePort         int
	LocalAddress       string
	LocalPort          int
	InsecureSkipVerify bool
}

type Sclient struct{}

func pipe(r net.Conn, w net.Conn, t string) {
	buffer := make([]byte, 2048)
	for {
		done := false
		// NOTE: count may be > 0 even if there's an err
		count, err := r.Read(buffer)
		//fmt.Fprintf(os.Stdout, "[debug] (%s) reading\n", t)
		if nil != err {
			//fmt.Fprintf(os.Stdout, "[debug] (%s:%d) error reading %s\n", t, count, err)
			if io.EOF != err {
				fmt.Fprintf(os.Stderr, "[read error] (%s:%s) %s\n", t, count, err)
			}
			r.Close()
			//w.Close()
			done = true
		}
		if 0 == count {
			break
		}
		_, err = w.Write(buffer[:count])
		if nil != err {
			//fmt.Fprintf(os.Stdout, "[debug] %s error writing\n", t)
			if io.EOF != err {
				fmt.Fprintf(os.Stderr, "[write error] (%s) %s\n", t, err)
			}
			// TODO handle error closing?
			r.Close()
			//w.Close()
			done = true
		}
		if done {
			break
		}
	}
}

func handleConnection(remote string, conn net.Conn, opts *SclientOpts) {
	sclient, err := tls.Dial("tcp", remote,
		&tls.Config{InsecureSkipVerify: opts.InsecureSkipVerify})

	if err != nil {
		fmt.Fprintf(os.Stderr, "[error] (remote) %s\n", err)
		conn.Close()
		return
	}

	fmt.Fprintf(os.Stdout, "[connect] %s => %s:%d\n",
		strings.Replace(conn.RemoteAddr().String(), "[::1]:", "localhost:", 1), opts.RemoteAddress, opts.RemotePort)

	go pipe(conn, sclient, "local")
	pipe(sclient, conn, "remote")
}

func (*Sclient) DialAndListen(opts *SclientOpts) error {
	remote := opts.RemoteAddress + ":" + strconv.Itoa(opts.RemotePort)
	conn, err := tls.Dial("tcp", remote,
		&tls.Config{InsecureSkipVerify: opts.InsecureSkipVerify})

	if err != nil {
		fmt.Fprintf(os.Stderr, "[warn] '%s' may not be accepting connections: %s\n", remote, err)
	} else {
		conn.Close()
	}

	local := opts.LocalAddress + ":" + strconv.Itoa(opts.LocalPort)
	ln, err := net.Listen("tcp", local)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "[listening] %s:%d <= %s:%d\n",
		opts.RemoteAddress, opts.RemotePort, opts.LocalAddress, opts.LocalPort)

	for {
		conn, err := ln.Accept()
		if nil != err {
			fmt.Fprintf(os.Stderr, "[error] %s\n", err)
			continue
		}
		go handleConnection(remote, conn, opts)
	}
}
