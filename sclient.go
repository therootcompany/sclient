package sclient

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// Tunnel specifies which remote encrypted connection to make available as a plain connection locally.
type Tunnel struct {
	RemoteAddress      string
	RemotePort         int
	LocalAddress       string
	LocalPort          int
	InsecureSkipVerify bool
	NextProtos         []string
	ServerName         string
	Silent             bool
	// Timeout bounds how long one remote connection may take to be
	// ready to communicate: the TCP connect and the TLS handshake
	// together, under one deadline. Zero means no limit.
	Timeout time.Duration
}

// tlsConfig is the caller's TLS options, shared by every dial.
func (t *Tunnel) tlsConfig() *tls.Config {
	return &tls.Config{
		ServerName:         t.ServerName,
		NextProtos:         t.NextProtos,
		InsecureSkipVerify: t.InsecureSkipVerify,
	}
}

// dialer is the dialer for every remote connect: Timeout bounds the TCP
// connect (a zero Timeout means no limit, which is why the CLI supplies
// a default), and keep-alive is explicit rather than left to the
// platform. DNS resolution rides on the same context deadline.
func (t *Tunnel) dialer() *net.Dialer {
	return &net.Dialer{
		Timeout:   t.Timeout,
		KeepAlive: 30 * time.Second,
	}
}

// dialTLS connects (TCP) and completes the TLS handshake, the two
// phases sharing one deadline of t.Timeout; a zero Timeout imposes
// no limit. The returned connection is ready to communicate.
func (t *Tunnel) dialTLS(remote string) (*tls.Conn, error) {
	d := t.dialer()
	if t.Timeout <= 0 {
		return tls.Dial("tcp", remote, t.tlsConfig())
	}
	ctx, cancel := context.WithTimeout(context.Background(), t.Timeout)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", remote)
	if err != nil {
		return nil, err
	}
	tc := tls.Client(conn, t.tlsConfig())
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return tc, nil
}

// DialAndListen will create a test TLS connection to the remote address and then
// begin listening locally. Each local connection will result in a separate remote connection.
func (t *Tunnel) DialAndListen() error {
	remote := t.RemoteAddress + ":" + strconv.Itoa(t.RemotePort)
	conn, err := t.dialTLS(remote)

	if err != nil {
		fmt.Fprintf(os.Stderr, "[warn] '%s' may not be accepting connections: %s\n", remote, err)
	} else {
		_ = conn.Close()
	}

	// use stdin/stdout
	if t.LocalAddress == "-" || t.LocalAddress == "|" {
		var name string
		network := "stdio"
		if t.LocalAddress == "|" {
			name = "pipe"
		} else {
			name = "stdin"
		}
		conn := &stdnet{os.Stdin, os.Stdout, &stdaddr{net.UnixAddr{Name: name, Net: network}}}
		t.handleConnection(remote, conn)
		return nil
	}

	// use net.Conn
	local := t.LocalAddress + ":" + strconv.Itoa(t.LocalPort)
	ln, err := net.Listen("tcp", local)
	if err != nil {
		return err
	}

	if !t.Silent {
		_, _ = fmt.Fprintf(os.Stdout, "[listening] %s:%d <= %s:%d\n",
			t.RemoteAddress, t.RemotePort, t.LocalAddress, t.LocalPort)
	}

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
				fmt.Fprintf(os.Stderr, "[read error] (%s:%d) %s\n", t, count, err)
			}
			_ = r.Close()
			//w.Close()
			done = true
		}
		if count == 0 {
			break
		}
		_, err = w.Write(buffer[:count])
		if nil != err {
			//fmt.Fprintf(os.Stdout, "[debug] %s error writing\n", t)
			if io.EOF != err {
				fmt.Fprintf(os.Stderr, "[write error] (%s) %s\n", t, err)
			}
			// TODO handle error closing?
			_ = r.Close()
			//w.Close()
			done = true
		}
		if done {
			break
		}
	}
}

func (t *Tunnel) handleConnection(remote string, conn netReadWriteCloser) {
	sclient, err := t.dialTLS(remote)

	if err != nil {
		fmt.Fprintf(os.Stderr, "[error] (remote) %s\n", err)
		_ = conn.Close()
		return
	}

	if !t.Silent {
		if conn.RemoteAddr().Network() == "stdio" {
			_, _ = fmt.Fprintf(os.Stdout, "(connected to %s:%d and reading from %s)\n",
				t.RemoteAddress, t.RemotePort, conn.RemoteAddr().String())
		} else {
			_, _ = fmt.Fprintf(os.Stdout, "[connect] %s => %s:%d\n",
				strings.Replace(conn.RemoteAddr().String(), "[::1]:", "localhost:", 1), t.RemoteAddress, t.RemotePort)
		}
	}

	go pipe(conn, sclient, "local")
	pipe(sclient, conn, "remote")
}
