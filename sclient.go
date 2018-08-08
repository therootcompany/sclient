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

// I wonder if I can get this to exactly mirror UnixAddr without passing it in
type stdaddr struct {
	net.UnixAddr
}

type stdnet struct {
	in   *os.File // os.Stdin
	out  *os.File // os.Stdout
	addr *stdaddr
}

func (rw *stdnet) Read(buf []byte) (n int, err error) {
	return rw.in.Read(buf)
}
func (rw *stdnet) Write(buf []byte) (n int, err error) {
	return rw.out.Write(buf)
}
func (rw *stdnet) Close() error {
	return rw.in.Close()
}
func (rw *stdnet) RemoteAddr() net.Addr {
	return rw.addr
}

// not all of net.Conn, just RWC and RemoteAddr()
type Rwc interface {
	io.ReadWriteCloser
	RemoteAddr() net.Addr
}

type SclientOpts struct {
	RemoteAddress      string
	RemotePort         int
	LocalAddress       string
	LocalPort          int
	InsecureSkipVerify bool
}

type Sclient struct{}

func pipe(r Rwc, w Rwc, t string) {
	buffer := make([]byte, 2048)
	for {
		done := false
		// NOTE: count may be > 0 even if there's an err
		//fmt.Fprintf(os.Stdout, "[debug] (%s) reading\n", t)
		count, err := r.Read(buffer)
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

func handleConnection(remote string, conn Rwc, opts *SclientOpts) {
	sclient, err := tls.Dial("tcp", remote,
		&tls.Config{InsecureSkipVerify: opts.InsecureSkipVerify})

	if err != nil {
		fmt.Fprintf(os.Stderr, "[error] (remote) %s\n", err)
		conn.Close()
		return
	}

	if "stdio" == conn.RemoteAddr().Network() {
		fmt.Fprintf(os.Stdout, "(connected to %s:%d and reading from %s)\n",
			opts.RemoteAddress, opts.RemotePort, conn.RemoteAddr().String())
	} else {
		fmt.Fprintf(os.Stdout, "[connect] %s => %s:%d\n",
			strings.Replace(conn.RemoteAddr().String(), "[::1]:", "localhost:", 1), opts.RemoteAddress, opts.RemotePort)
	}

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

	// use stdin/stdout
	if "-" == opts.LocalAddress || "|" == opts.LocalAddress {
		var name string
		network := "stdio"
		if "|" == opts.LocalAddress {
			name = "pipe"
		} else {
			name = "stdin"
		}
		conn := &stdnet{os.Stdin, os.Stdout, &stdaddr{net.UnixAddr{name, network}}}
		handleConnection(remote, conn, opts)
		return nil
	}

	// use net.Conn
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
