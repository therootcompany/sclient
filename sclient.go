package sclient

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
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
}

// DialAndListen will create a test TLS connection to the remote address and then
// begin listening locally. Each local connection will result in a separate remote connection.
func (t *Tunnel) DialAndListen() error {
	remote := t.RemoteAddress + ":" + strconv.Itoa(t.RemotePort)
	conn, err := tls.Dial("tcp", remote,
		&tls.Config{
			ServerName:         t.ServerName,
			NextProtos:         t.NextProtos,
			InsecureSkipVerify: t.InsecureSkipVerify,
		})

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
	defer func() { _ = ln.Close() }()

	if !t.Silent {
		_, _ = fmt.Fprintf(os.Stdout, "[listening] %s:%d <= %s:%d\n",
			t.RemoteAddress, t.RemotePort, t.LocalAddress, t.LocalPort)
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("local listener: %w", err)
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

// pipe relays local <-> remote in both directions, ending each stream when its
// source is exhausted, then hangs up on both.
func pipe(local io.ReadWriteCloser, remote io.ReadWriteCloser) error {
	var (
		wg        sync.WaitGroup
		localErr  error
		remoteErr error
	)

	wg.Go(func() { localErr = pipeToRemote(local, remote) })
	wg.Go(func() { remoteErr = pipeToLocal(remote, local) })
	wg.Wait()

	_ = remote.Close()
	return errors.Join(localErr, remoteErr)
}

// pipeToRemote copies local to remote, then half-closes the remote so a
// keep-alive server sees EOF without losing its buffered answer.
func pipeToRemote(local io.Reader, remote io.WriteCloser) error {
	_, err := io.Copy(remote, local)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
		return err
	}
	if cw, ok := remote.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return remote.Close()
}

// pipeToLocal copies remote to local, then hangs up on the local side.
func pipeToLocal(remote io.Reader, local io.WriteCloser) error {
	_, err := io.Copy(local, remote)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
		return err
	}
	return local.Close()
}

func (t *Tunnel) handleConnection(remote string, conn netReadWriteCloser) {
	remoteConn, err := tls.Dial("tcp", remote,
		&tls.Config{
			ServerName:         t.ServerName,
			NextProtos:         t.NextProtos,
			InsecureSkipVerify: t.InsecureSkipVerify,
		})

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

	if err := pipe(conn, remoteConn); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "[copy error] %s\n", err)
	}
}
