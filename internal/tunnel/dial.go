// Package tunnel is the connection plumbing the plain and SSH modes share: the
// dial, the copy loop, and the stdio stand-in.
package tunnel

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"time"
)

// Dial is everything one dial needs: the name, the protocols, and the two clocks.
type Dial struct {
	ServerName         string
	NextProtos         []string
	InsecureSkipVerify bool
	TCPTimeout         time.Duration
	TLSTimeout         time.Duration
}

const (
	defaultTCPDeadline   = 5 * time.Second
	minHandshakeDeadline = 150 * time.Millisecond
	handshakeMultiplier  = 3
)

// ConnectClock is the TCP deadline: the operator's, or the default.
func (d Dial) ConnectClock() time.Duration {
	if d.TCPTimeout > 0 {
		return d.TCPTimeout
	}
	return defaultTCPDeadline
}

// HandshakeDeadline bounds the handshake from the connect. Unset means auto:
// three times the connect, floored at 150ms.
func (d Dial) HandshakeDeadline(connect time.Duration) time.Duration {
	if d.TLSTimeout > 0 {
		return d.TLSTimeout
	}
	return max(handshakeMultiplier*connect, minHandshakeDeadline)
}

// TLSConfig is the client config for one dial. Go sends no SNI for an IP, but
// still checks it against the certificate.
func (d Dial) TLSConfig(protos []string) *tls.Config {
	return &tls.Config{
		ServerName:         d.ServerName,
		NextProtos:         protos,
		InsecureSkipVerify: d.InsecureSkipVerify,
	}
}

// DialTLS connects, then handshakes, each under its own deadline. onTransport,
// when given, is called the moment the socket is up.
func (d Dial) DialTLS(ctx context.Context, remote string, protos []string, onTransport func(time.Duration)) (*tls.Conn, error) {
	connect := d.ConnectClock()
	ctx, cancel := context.WithTimeout(ctx, connect+d.HandshakeDeadline(connect))
	defer cancel()

	start := time.Now()
	conn, err := (&net.Dialer{Timeout: connect}).DialContext(ctx, "tcp", remote)
	if err != nil {
		return nil, err
	}
	if onTransport != nil {
		onTransport(time.Since(start))
	}

	handshake, cancelHandshake := context.WithTimeout(ctx, d.HandshakeDeadline(time.Since(start)))
	defer cancelHandshake()

	remoteConn := tls.Client(conn, d.TLSConfig(protos))
	if err := remoteConn.HandshakeContext(handshake); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return remoteConn, nil
}

// DialPlain connects without TLS, on the same connect clock.
func (d Dial) DialPlain(ctx context.Context, remote string, onTransport func(time.Duration)) (net.Conn, error) {
	connect := d.ConnectClock()
	ctx, cancel := context.WithTimeout(ctx, connect)
	defer cancel()

	start := time.Now()
	conn, err := (&net.Dialer{Timeout: connect}).DialContext(ctx, "tcp", remote)
	if err != nil {
		return nil, err
	}
	if onTransport != nil {
		onTransport(time.Since(start))
	}
	return conn, nil
}

// BufferedConn reads through a bufio.Reader so bytes read early - a banner and
// the KEXINIT glued to it - stay in the stream, while writes and Close reach the
// connection.
type BufferedConn struct {
	R    *bufio.Reader
	Conn net.Conn
}

func (b *BufferedConn) Read(p []byte) (int, error)  { return b.R.Read(p) }
func (b *BufferedConn) Write(p []byte) (int, error) { return b.Conn.Write(p) }
func (b *BufferedConn) Close() error                { return b.Conn.Close() }
func (b *BufferedConn) RemoteAddr() net.Addr        { return b.Conn.RemoteAddr() }
func (b *BufferedConn) LocalAddr() net.Addr         { return b.Conn.LocalAddr() }
