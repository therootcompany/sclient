package sclient

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
)

// Tunnel specifies which remote encrypted connection to make available as a plain connection locally.
type Tunnel struct {
	RemoteAddress       string
	RemotePort          int
	LocalAddress        string
	LocalPort           int
	InsecureSkipVerify  bool
	NextProtos          []string
	ServerName          string
	Silent              bool
	HttpAuthURL         string
	AuthToken           string
	HttpUpgradeProtocol string
}

func (t *Tunnel) httpAuth(conn net.Conn) (bool, error) {
	url := t.HttpAuthURL
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "http://" + url
	}
	parts := strings.SplitN(url, "//", 2)
	path := "/"
	if idx := strings.Index(parts[1], "/"); idx != -1 {
		path = parts[1][idx:]
	}
	host := parts[0]

	req, _ := http.NewRequest("GET", path, nil)
	req.Host = host
	if t.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+t.AuthToken)
	}
	if t.HttpUpgradeProtocol != "" {
		req.Header.Set("Upgrade", t.HttpUpgradeProtocol)
	}
	req.ContentLength = 0
	req.Close = true

	if err := req.Write(conn); nil != err {
		return false, err
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if nil != err {
		return false, err
	}

	resp := string(buf[:n])

	if t.HttpUpgradeProtocol != "" {
		if strings.Contains(resp, "101") && strings.Contains(strings.ToLower(resp), "upgrade: "+strings.ToLower(t.HttpUpgradeProtocol)) {
			return true, nil
		}
		if !strings.Contains(resp, "200") && !strings.Contains(resp, "201") && !strings.Contains(resp, "202") && !strings.Contains(resp, "204") {
			return false, fmt.Errorf("authentication failed: %s", resp)
		}
	}

	if !strings.Contains(resp, "200") && !strings.Contains(resp, "201") && !strings.Contains(resp, "202") && !strings.Contains(resp, "204") {
		return false, fmt.Errorf("authentication failed: %s", resp)
	}

	return false, nil
}

// DialAndListen will create a test TLS connection to the remote address and then
// begin listening locally. Each local connection will result in a separate remote connection.
func (t *Tunnel) DialAndListen() error {
	remote := t.RemoteAddress + ":" + strconv.Itoa(t.RemotePort)

	var nextProtos []string = t.NextProtos
	if t.HttpAuthURL != "" {
		nextProtos = []string{"http/1.1"}
	}

	conn, err := tls.Dial("tcp", remote,
		&tls.Config{
			ServerName:         t.ServerName,
			NextProtos:         nextProtos,
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
	var sclient net.Conn

	if t.HttpAuthURL != "" {
		authConn, err := tls.Dial("tcp", remote,
			&tls.Config{
				ServerName:         t.ServerName,
				NextProtos:         []string{"http/1.1"},
				InsecureSkipVerify: t.InsecureSkipVerify,
			})

		if err != nil {
			fmt.Fprintf(os.Stderr, "[error] (auth connection) %s\n", err)
			_ = conn.Close()
			return
		}

		upgraded, err := t.httpAuth(authConn)
		if nil != err {
			fmt.Fprintf(os.Stderr, "[error] (authentication) %s\n", err)
			_ = conn.Close()
			_ = authConn.Close()
			return
		}

		if t.HttpUpgradeProtocol != "" && upgraded {
			sclient = authConn
		} else {
			_ = authConn.Close()

			var nextProtos []string = t.NextProtos
			if len(nextProtos) == 0 {
				nextProtos = []string{"ssh"}
			}

			sclient, err = tls.Dial("tcp", remote,
				&tls.Config{
					ServerName:         t.ServerName,
					NextProtos:         nextProtos,
					InsecureSkipVerify: t.InsecureSkipVerify,
				})

			if err != nil {
				fmt.Fprintf(os.Stderr, "[error] (remote) %s\n", err)
				_ = conn.Close()
				return
			}
		}
	} else {
		var dialErr error
		sclient, dialErr = tls.Dial("tcp", remote,
			&tls.Config{
				ServerName:         t.ServerName,
				NextProtos:         t.NextProtos,
				InsecureSkipVerify: t.InsecureSkipVerify,
			})

		if dialErr != nil {
			fmt.Fprintf(os.Stderr, "[error] (remote) %s\n", dialErr)
			_ = conn.Close()
			return
		}
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
