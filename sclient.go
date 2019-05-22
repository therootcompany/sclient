package sclient

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
)

// Tunnel specifies which remote encrypted connection to make available as a plain connection locally.
type Tunnel struct {
	RemoteAddress      string
	RemotePort         int
	LocalAddress       string
	LocalPort          int
	InsecureSkipVerify bool
	ServerName         string
}

// DialAndListen will create a test TLS connection to the remote address and then
// begin listening locally. Each local connection will result in a separate remote connection.
func (t *Tunnel) DialAndListen() error {
	remote := t.RemoteAddress + ":" + strconv.Itoa(t.RemotePort)
	conn, err := tls.Dial("tcp", remote,
		&tls.Config{
			ServerName:         t.ServerName,
			InsecureSkipVerify: t.InsecureSkipVerify,
		})

	if err != nil {
		fmt.Fprintf(os.Stderr, "[warn] '%s' may not be accepting connections: %s\n", remote, err)
	} else {
		conn.Close()
	}

	// use stdin/stdout
	if "-" == t.LocalAddress || "|" == t.LocalAddress {
		var name string
		network := "stdio"
		if "|" == t.LocalAddress {
			name = "pipe"
		} else {
			name = "stdin"
		}
		conn := &stdnet{os.Stdin, os.Stdout, &stdaddr{net.UnixAddr{name, network}}}
		t.handleConnection(remote, conn)
		return nil
	}

	// use net.Conn
	local := t.LocalAddress + ":" + strconv.Itoa(t.LocalPort)
	ln, err := net.Listen("tcp", local)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "[listening] %s:%d <= %s:%d\n",
		t.RemoteAddress, t.RemotePort, t.LocalAddress, t.LocalPort)

	for {
		conn, err := ln.Accept()
		if nil != err {
			fmt.Fprintf(os.Stderr, "[error] %s\n", err)
			continue
		}
		go t.handleConnection(remote, conn)
	}
}

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
type netReadWriteCloser interface {
	io.ReadWriteCloser
	RemoteAddr() net.Addr
}

func pipe(r netReadWriteCloser, w netReadWriteCloser, t string) {
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

func (t *Tunnel) handleConnection(remote string, conn netReadWriteCloser) {
	sclient, err := tls.Dial("tcp", remote,
		&tls.Config{
			ServerName:         t.ServerName,
			InsecureSkipVerify: t.InsecureSkipVerify,
		})

	if err != nil {
		fmt.Fprintf(os.Stderr, "[error] (remote) %s\n", err)
		conn.Close()
		return
	}

	if "stdio" == conn.RemoteAddr().Network() {
		fmt.Fprintf(os.Stdout, "(connected to %s:%d and reading from %s)\n",
			t.RemoteAddress, t.RemotePort, conn.RemoteAddr().String())
	} else {
		fmt.Fprintf(os.Stdout, "[connect] %s => %s:%d\n",
			strings.Replace(conn.RemoteAddr().String(), "[::1]:", "localhost:", 1), t.RemoteAddress, t.RemotePort)
	}

	go pipe(conn, sclient, "local")
	pipe(sclient, conn, "remote")
}
