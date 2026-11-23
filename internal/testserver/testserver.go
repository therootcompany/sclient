// Package testserver is the fixture the tests share: loopback servers with known
// behavior - a TLS server that answers a request, and SSH banner servers on plain
// TCP and over TLS.
package testserver

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Reply is what the TLS server answers once it sees the end of the request.
const Reply = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nhello from the server\r\n"

// FreePort returns a TCP port on 127.0.0.1 that nobody is holding.
func FreePort(t *testing.T) *net.TCPAddr {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	addr := ln.Addr().(*net.TCPAddr)
	_ = ln.Close()
	return addr
}

// Dial connects to a listener, waiting for it to come up.
func Dial(t *testing.T, addr string) (net.Conn, error) {
	t.Helper()

	for range 50 {
		conn, err := net.Dial("tcp", addr)
		if err == nil {
			return conn, nil
		}
		time.Sleep(2 * time.Millisecond)
	}
	return nil, errors.New("nothing bound " + addr)
}

// Blackhole is a TCP listener that never handshakes - the "remote is down"
// fixture.
func Blackhole(t *testing.T) (string, int, func()) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("blackhole: %v", err)
	}
	addr := ln.Addr().(*net.TCPAddr)
	return addr.IP.String(), addr.Port, func() { _ = ln.Close() }
}

// TLS starts the server on a random loopback port. It returns the host, the port,
// a shutdown function, and a counter of the connections it accepted.
func TLS(t *testing.T) (string, int, func(), *atomic.Int32) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("tls server: listen: %v", err)
	}
	server := tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{selfSigned()}})

	conns := &atomic.Int32{}
	go func() {
		for {
			conn, err := server.Accept()
			if err != nil {
				return
			}
			conns.Add(1)
			go func() {
				defer conn.Close()
				if _, err := io.ReadAll(conn); err != nil {
					return
				}
				_, _ = conn.Write([]byte(Reply))
			}()
		}
	}()

	host, rawPort, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		_ = ln.Close()
		t.Fatalf("tls server: address: %v", err)
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil {
		_ = ln.Close()
		t.Fatalf("tls server: port: %v", err)
	}

	return host, port, func() { _ = ln.Close() }, conns
}

// SilentTCP accepts connections and never speaks: a peer that must be timed out.
func SilentTCP(t *testing.T) int {
	t.Helper()
	return acceptOnly(t, nil)
}

// SilentTLS accepts TLS connections and never finishes the handshake.
func SilentTLS(t *testing.T) int {
	t.Helper()
	return acceptOnly(t, &tls.Config{Certificates: []tls.Certificate{selfSigned()}})
}

// SSHEcho answers the banner exchange and echoes lines until it sees BYE.
// alpn is the protocol it offers over TLS; "" offers none. extra is written with
// the banner in one write, like OpenSSH's glued KEXINIT. It returns the port.
func SSHEcho(t *testing.T, banner, extra, alpn string, overTLS bool) int {
	t.Helper()

	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ssh echo: listen: %v", err)
	}

	ln := inner
	if overTLS {
		config := &tls.Config{Certificates: []tls.Certificate{selfSigned()}}
		if alpn != "" {
			config.NextProtos = []string{alpn}
		}
		ln = tls.NewListener(inner, config)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				r := bufio.NewReader(c)
				if _, err := r.ReadString('\n'); err != nil {
					return
				}
				if _, err := io.WriteString(c, banner+"\r\n"+extra+"\r\n"); err != nil {
					return
				}
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					if strings.TrimRight(line, "\r\n") == "BYE" {
						_, _ = io.WriteString(c, "GOODBYE\r\n")
						return
					}
				}
			}(conn)
		}
	}()

	t.Cleanup(func() { _ = inner.Close() })
	return port(inner.Addr())
}

// SlowSSHEcho answers the banner only after a delay, so the plain port is ready
// first and this handshake is still in flight when the grace period starts.
func SlowSSHEcho(t *testing.T, banner, alpn string, delay time.Duration) int {
	t.Helper()

	config := &tls.Config{Certificates: []tls.Certificate{selfSigned()}}
	if alpn != "" {
		config.NextProtos = []string{alpn}
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("slow ssh echo: listen: %v", err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				time.Sleep(delay)
				tlsConn := tls.Server(c, config)
				if err := tlsConn.Handshake(); err != nil {
					return
				}
				r := bufio.NewReader(tlsConn)
				if _, err := r.ReadString('\n'); err != nil {
					return
				}
				_, _ = io.WriteString(tlsConn, banner+"\r\n")
				_, _ = r.ReadString('\n')
			}(conn)
		}
	}()

	t.Cleanup(func() { _ = ln.Close() })
	return port(ln.Addr())
}

// acceptOnly accepts and ignores every connection, optionally behind TLS.
func acceptOnly(t *testing.T, tlsConfig *tls.Config) int {
	t.Helper()

	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("silent server: listen: %v", err)
	}

	ln := inner
	if tlsConfig != nil {
		ln = tls.NewListener(inner, tlsConfig)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn
		}
	}()

	t.Cleanup(func() { _ = inner.Close() })
	return port(inner.Addr())
}

// selfSigned is a throwaway certificate for 127.0.0.1.
func selfSigned() tls.Certificate {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{{127, 0, 0, 1}},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, key.Public(), key)
	if err != nil {
		panic(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func port(addr net.Addr) int {
	_, raw, err := net.SplitHostPort(addr.String())
	if err != nil {
		return 0
	}
	p, err := strconv.Atoi(raw)
	if err != nil {
		return 0
	}
	return p
}
