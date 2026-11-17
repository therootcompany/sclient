// Package ssh probes a name's plain SSH port and its TLS port at the same time,
// runs the RFC 4253 section 4.2 banner exchange against whichever answers,
// prefers the TLS connection, and relays the local side onto the winner. The
// simultaneous probe is the point; trying one port and falling back to the other
// is a different, weaker tool.
//
// Two gates decide whether a candidate is usable:
//   - ALPN: a named protocol list is a requirement, not a hint. A TLS connection
//     that negotiates none of them has no ssh route for this name. An empty list
//     turns the gate off.
//   - Banner: a server that declares hosts in its banner comment, and none of
//     them is the name being dialled, is a different server. A banner that
//     declares nothing is accepted.
package ssh

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/therootcompany/sclient/internal/tunnel"
)

// ErrNoServer means neither port is usable. The report of why each one lost is
// already written to errOut.
var ErrNoServer = errors.New("no usable server")

// Config is one probe. Zero values take the engine defaults.
type Config struct {
	Host       string   // the address both ports are dialled on
	ServerName string   // the name the connection is for; defaults to Host
	SSHPort    int      // the plain SSH port
	TLSPort    int      // the TLS port; zero means 443
	ALPN       []string // nil takes "ssh"; an explicit empty list turns the gate off
	TCPTimeout time.Duration
	TLSTimeout time.Duration
	Verbose    bool
	Silent     bool
	Dial       tunnel.Dial
}

const (
	// minGrace is the floor for the grace a still-pending candidate gets.
	minGrace = 150 * time.Millisecond
	// bannerReadMargin sits inside the banner window, so a peer that never
	// answers times out on the read instead of losing the race with the close
	// that ends the window.
	bannerReadMargin = 20 * time.Millisecond
	// sniffWindow bounds the plain-mode peek: a local connection that says
	// nothing is not an SSH client. ssh writes its banner the instant it
	// connects, so a tenth of a second is plenty even over a real network.
	sniffWindow = 100 * time.Millisecond
)

// resolved fills in the engine defaults.
func (c Config) resolved() Config {
	if c.SSHPort == 0 {
		c.SSHPort = 22
	}
	if c.TLSPort == 0 {
		c.TLSPort = 443
	}
	if c.ServerName == "" {
		c.ServerName = c.Host
	}
	if c.ALPN == nil {
		c.ALPN = []string{"ssh"}
	}
	if c.Dial.ServerName == "" {
		c.Dial.ServerName = c.ServerName
	}
	if c.Dial.NextProtos == nil {
		c.Dial.NextProtos = c.ALPN
	}
	return c
}

// candidate is one attempt to reach the server.
type candidate struct {
	name    string // "ssh" or "tls"
	address string
	conn    net.Conn
	r       *bufio.Reader // keeps the read-ahead (a glued KEXINIT) for the relay
	banner  string
	err     error
	// mismatch is non-empty when a banner declared hosts and none of them is the
	// name being dialled: this candidate is a different server.
	mismatch string
	// declared is true when the banner named a host at all. A declared banner that
	// matches is proof of identity on its own, so the other port is no longer
	// worth waiting for.
	declared bool
}

// usable means the candidate connected, answered the banner, and was not
// contradicted by it.
func (c *candidate) usable() bool { return c.err == nil && c.mismatch == "" }

// Serve runs one SSH-mode session over an already-connected local side: stdio, or
// a connection the caller accepted.
func Serve(ctx context.Context, cfg Config, local net.Conn, errOut io.Writer) error {
	cfg = cfg.resolved()

	// Intercepting exactly one client line is safe: the server waits for the
	// client's banner before sending anything else (RFC 4253 4.2).
	client := bufio.NewReaderSize(local, 32*1024)
	clientBanner, err := readBanner(client)
	if err != nil {
		return fmt.Errorf("local: %w", err)
	}

	chosen, err := probe(ctx, cfg, clientBanner, errOut)
	if err != nil {
		closeOut(local)
		return err
	}

	if !cfg.Silent {
		_, _ = fmt.Fprintf(errOut, "[connect] %s => %s\n",
			tunnel.DisplayAddr(local.RemoteAddr()), chosen.address)
	}

	return relay(ctx, chosen, client, local, errOut)
}

// Listen binds a local port and runs one SSH-mode session per connection.
func Listen(ctx context.Context, cfg Config, localAddr string, errOut io.Writer) error {
	cfg = cfg.resolved()

	ln, err := net.Listen("tcp", localAddr)
	if err != nil {
		return err
	}
	defer func() { _ = ln.Close() }()

	if !cfg.Silent {
		_, _ = fmt.Fprintf(errOut, "[listening] %s (ssh) <= %s\n",
			net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.TLSPort)), localAddr)
	}

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("local listener: %w", err)
		}
		go func() {
			if err := Serve(ctx, cfg, conn, errOut); err != nil {
				_, _ = fmt.Fprintf(errOut, "[error] %s\n", err)
			}
		}()
	}
}

// probe dials both ports on their own clocks and returns the winner: the TLS
// connection if it speaks the ALPN we asked for, otherwise the plain SSH port.
func probe(ctx context.Context, cfg Config, clientBanner string, errOut io.Writer) (*candidate, error) {
	debugf := func(format string, args ...any) {
		if cfg.Verbose {
			_, _ = fmt.Fprintf(errOut, format+"\n", args...)
		}
	}

	// The outer bound on the probe: the connect clock plus the longest handshake
	// a candidate can spend, or the caller's own deadline if that is sooner. Each
	// dial keeps its own clock; the grace only shortens this one.
	connect := cfg.Dial.ConnectClock()
	deadline := time.Now().Add(connect + cfg.Dial.HandshakeDeadline(connect))
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	clock, cancelClock := context.WithCancelCause(ctx)
	defer cancelClock(nil)
	timer := time.AfterFunc(time.Until(deadline), func() { cancelClock(errProbeClock) })

	candidates := make(chan *candidate, 2)
	up := make(chan time.Duration, 2)

	// decided closes the moment a candidate is confirmed, so a handshake we no
	// longer need is cut short instead of running out its clock.
	decided := make(chan struct{})
	var decideOnce sync.Once
	decide := func() { decideOnce.Do(func() { close(decided) }) }

	go func() {
		candidates <- dialPlain(clock, cfg, clientBanner, func(elapsed time.Duration) { up <- elapsed }, debugf)
	}()
	if tryTLS(cfg) {
		go func() {
			candidates <- dialTLS(ctx, clock, cfg, clientBanner, func(elapsed time.Duration) { up <- elapsed }, decided, debugf)
		}()
	} else {
		err := errors.New("skipped: an IP address has no name to route on, use --servername")
		c := &candidate{name: "tls", address: net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.TLSPort)), err: err}
		candidates <- c
		debugf("dial: tls %s: %v", c.address, err)
	}

	var ready, failed []*candidate
	var chosen *candidate
	graceArmed := false
	settled := 0
	for settled < 2 && chosen == nil {
		select {
		// Arming the grace when a transport comes up - not when a candidate is
		// confirmed - is what keeps a blackholed port from holding the probe to
		// the full timeout.
		case elapsed := <-up:
			if !graceArmed {
				graceArmed = true
				until := time.Now().Add(graceFor(elapsed))
				if until.After(deadline) {
					until = deadline
				}
				timer.Reset(time.Until(until))
			}
		case c := <-candidates:
			settled++
			if c.err != nil {
				failed = append(failed, c)
				debugf("dial: %s %s: %v", c.name, c.address, c.err)
				continue
			}
			ready = append(ready, c)
			// A usable TLS candidate wins outright. A plain banner that declares the
			// name being dialled is proof on its own: take it, and stop the handshake
			// we no longer need. An undeclared banner proves nothing, so the TLS side
			// keeps its chance.
			if c.usable() && (c.name == "tls" || c.declared) {
				chosen = c
				decide()
			}
		}
	}

	timer.Stop() // the probe clock is done; the session is not probe-bounded

	// Drain whatever is still in flight so the report names every candidate.
	for settled < 2 {
		c := <-candidates
		settled++
		if c.err != nil {
			failed = append(failed, c)
			debugf("dial: %s %s: %v", c.name, c.address, c.err)
			continue
		}
		ready = append(ready, c)
	}

	if chosen == nil {
		chosen = pickCandidate(ready)
	}
	if chosen == nil {
		reportNoServer(cfg, ready, failed, errOut)
		return nil, ErrNoServer
	}

	debugf("chosen: %s %s", chosen.name, chosen.address)
	for _, c := range ready {
		if c != chosen {
			_ = c.conn.Close()
		}
	}
	_ = chosen.conn.SetDeadline(time.Time{}) // sessions may sit idle
	return chosen, nil
}

// tryTLS: an IP address carries no name, and a proxy that routes by name has
// nothing to route on, so an IP remote is only probed over TLS when the server is
// named.
func tryTLS(cfg Config) bool {
	return net.ParseIP(cfg.Host) == nil || cfg.ServerName != ""
}

// graceFor is half the time since the dials started, floored at minGrace.
func graceFor(elapsed time.Duration) time.Duration {
	return max(elapsed/2, minGrace)
}

// bannerWindow is how long a connected candidate may take to answer the banner:
// a quarter of the connect clock, floored at one grace period, never past the
// time left in the probe.
func bannerWindow(connect, remaining time.Duration) time.Duration {
	window := max(2*minGrace, connect/4)
	if remaining < window {
		window = max(minGrace, remaining)
	}
	return window
}

// dialPlain connects to the SSH port without TLS, then exchanges banners.
func dialPlain(clock context.Context, cfg Config, clientBanner string, onTransport func(time.Duration), debugf func(string, ...any)) *candidate {
	start := time.Now()
	c := &candidate{name: "ssh", address: net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.SSHPort))}

	conn, err := cfg.Dial.DialPlain(clock, c.address, onTransport)
	if err != nil {
		c.err = dialError(err, time.Since(start), clock)
		return c
	}
	c.conn = conn
	c.r = bufio.NewReaderSize(conn, 32*1024)
	return exchangeBanner(c, cfg, clientBanner, remainingOn(clock), debugf)
}

// dialTLS connects to the TLS port and applies the ALPN gate before the banner is
// sent: a server that will not name a protocol we asked for is not routing ssh for
// this name, so it never sees the banner.
func dialTLS(ctx, clock context.Context, cfg Config, clientBanner string, onTransport func(time.Duration), decided chan struct{}, debugf func(string, ...any)) *candidate {
	start := time.Now()
	c := &candidate{name: "tls", address: net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.TLSPort))}

	conn, err := cfg.Dial.DialPlain(clock, c.address, onTransport)
	if err != nil {
		c.err = dialError(err, time.Since(start), clock)
		return c
	}

	// The handshake is off the probe clock: the grace that closes a blackholed
	// port must not strangle it, and a server that already has a certificate
	// answers in a couple of round trips.
	handshake, cancelHandshake := context.WithTimeout(ctx, cfg.Dial.HandshakeDeadline(time.Since(start)))
	defer cancelHandshake()
	go func() {
		select {
		case <-decided:
			cancelHandshake()
		case <-handshake.Done():
		}
	}()

	tlsConn := tls.Client(conn, cfg.Dial.TLSConfig(cfg.ALPN))
	if err := tlsConn.HandshakeContext(handshake); err != nil {
		_ = conn.Close()
		c.err = dialError(fmt.Errorf("tls: %w", err), time.Since(start), clock)
		return c
	}

	// The gate: no banner for a server that is not routing ssh.
	negotiated := tlsConn.ConnectionState().NegotiatedProtocol
	if len(cfg.ALPN) > 0 && !slices.Contains(cfg.ALPN, negotiated) {
		_ = tlsConn.Close()
		name := "(none)"
		if negotiated != "" {
			name = strconv.Quote(negotiated)
		}
		c.err = fmt.Errorf("negotiated ALPN %s, wanted one of [%s]", name, strings.Join(cfg.ALPN, ", "))
		return c
	}

	c.conn = tlsConn
	c.r = bufio.NewReaderSize(tlsConn, 32*1024)
	return exchangeBanner(c, cfg, clientBanner, remainingOn(clock), debugf)
}

// exchangeBanner writes the client banner, reads the reply, and applies the host
// gate. A candidate that comes back with err set is not usable.
func exchangeBanner(c *candidate, cfg Config, clientBanner string, remaining time.Duration, debugf func(string, ...any)) *candidate {
	window := bannerWindow(cfg.Dial.ConnectClock(), remaining)
	_ = c.conn.SetReadDeadline(time.Now().Add(window - bannerReadMargin))
	defer c.conn.SetReadDeadline(time.Time{})

	if err := writeBanner(c.conn, clientBanner); err != nil {
		c.err = fmt.Errorf("write banner: %w", err)
		_ = c.conn.Close()
		return c
	}

	banner, err := readBanner(c.r)
	if err != nil {
		c.err = err
		_ = c.conn.Close()
		return c
	}

	c.banner = banner
	c.declared = len(declaredHosts(banner)) > 0
	debugf("banner: %s %s answered %q", c.name, c.address, banner)

	if mismatch := bannerMismatch(cfg.ServerName, banner); mismatch != "" {
		debugf("banner: %s %s: %s", c.name, c.address, mismatch)
		c.mismatch = mismatch
		_ = c.conn.Close()
	}
	return c
}

// remainingOn is how much time the probe clock has left.
func remainingOn(clock context.Context) time.Duration {
	dl, ok := clock.Deadline()
	if !ok {
		return minGrace
	}
	return time.Until(dl)
}

// pickCandidate prefers the TLS connection, but only when it is usable: a
// candidate contradicted by its own banner is not a server, it is a different one.
func pickCandidate(ready []*candidate) *candidate {
	for _, c := range ready {
		if c.name == "tls" && c.usable() {
			return c
		}
	}
	for _, c := range ready {
		if c.usable() {
			return c
		}
	}
	return nil
}

// relay writes the winner's banner to the local side, then copies both directions.
// The session is bounded by ctx, not by the probe clock.
func relay(ctx context.Context, chosen *candidate, client *bufio.Reader, local net.Conn, errOut io.Writer) error {
	if chosen.banner != "" {
		_, _ = fmt.Fprintf(local, "%s\r\n", chosen.banner)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := tunnel.Pipe(&tunnel.BufferedConn{R: client, Conn: local}, chosen.conn); err != nil {
			_, _ = fmt.Fprintf(errOut, "[copy error] %s\n", err)
		}
	}()

	select {
	case <-done:
	case <-ctx.Done():
		_ = local.Close()
		_ = chosen.conn.Close()
		<-done
	}
	return nil
}

// reportNoServer names every candidate and why it lost.
func reportNoServer(cfg Config, ready, failed []*candidate, errOut io.Writer) {
	if cfg.Silent {
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s: no usable server\n", cfg.Host)
	for _, c := range ready {
		fmt.Fprintf(&b, "  %s %s: %s\n", c.name, c.address, c.mismatch)
	}
	for _, c := range failed {
		fmt.Fprintf(&b, "  %s %s: %v\n", c.name, c.address, c.err)
	}
	fmt.Fprint(errOut, b.String())
}

// closeOut lets a client waiting on the pipe see EOF when we give up.
func closeOut(w io.Writer) {
	if c, ok := w.(io.Closer); ok {
		_ = c.Close()
	}
}

// errProbeClock marks a cancel that came from the probe clock - the timeout or the
// grace window - rather than from the caller.
var errProbeClock = errors.New("probe clock ran out")

// dialError names the reason a dial never connected: the clock gives a timeout, the
// caller pulling the plug gives a cancellation.
func dialError(err error, elapsed time.Duration, clock context.Context) error {
	timeout := fmt.Errorf("timed out after %s", tunnel.ElapsedText(elapsed))
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return timeout
	case errors.Is(err, context.Canceled):
		if errors.Is(context.Cause(clock), errProbeClock) {
			return timeout
		}
		return fmt.Errorf("canceled after %s", tunnel.ElapsedText(elapsed))
	}
	return err
}

// SniffALPN offers "ssh" when the local side opens with an SSH banner and the
// operator named no protocol list. The peek does not consume the banner: the relay
// still sees it.
func SniffALPN(nextProtos []string, client *bufio.Reader, conn net.Conn) []string {
	if nextProtos != nil {
		return nextProtos
	}
	_ = conn.SetReadDeadline(time.Now().Add(sniffWindow))
	defer conn.SetReadDeadline(time.Time{})
	head, err := client.Peek(len("SSH-"))
	if err != nil {
		return nil
	}
	if string(head) == "SSH-" {
		return []string{"ssh"}
	}
	return nil
}
