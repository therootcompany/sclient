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

// CloseError is a session that never got a server. ssh prints
// "Connection closed by UNKNOWN port 65535" when a ProxyCommand dies, so the
// failure names the reason and every port that was tried in the same shape.
type CloseError struct {
	// Name is the command reporting it, "sclient" or "ssh-tls-proxy".
	Name string
	// Reason is the name dialled, or the cause that stands in for it: an
	// unresolvable name has no host to name, so it says "NO SUCH HOST".
	Reason string
	// Ports are the ports actually dialled; none prints as port [0].
	Ports []int
	cause error
}

func (e CloseError) Error() string { return e.cause.Error() }

func (e CloseError) Unwrap() error { return e.cause }

// Line is the last line of a failed session, in ssh's own phrasing:
// Connection closed by "example.com" ports [22, 443].
func (e CloseError) Line() string {
	ports := e.Ports
	if len(ports) == 0 {
		ports = []int{0}
	}

	parts := make([]string, len(ports))
	for i, port := range ports {
		parts[i] = strconv.Itoa(port)
	}

	word := "port"
	if len(parts) > 1 {
		word = "ports"
	}
	return fmt.Sprintf("%s: Connection closed by %q %s [%s]", e.Name, e.Reason, word, strings.Join(parts, ", "))
}

// Config is one probe. Zero values take the engine defaults.
type Config struct {
	Host               string   // the address both ports are dialled on
	ServerName         string   // the name the connection is for; defaults to Host
	SSHPort            int      // the plain SSH port
	TLSPort            int      // the TLS port; zero means 443
	ALPN               []string // nil takes "ssh"; an explicit empty list turns the gate off
	TCPTimeout         time.Duration
	TLSTimeout         time.Duration
	InsecureSkipVerify bool
	Verbose            bool
	Silent             bool
	// Name is the command reporting a failure, so the last line reads
	// "sclient: Connection closed by ...". It defaults to "sclient".
	Name string
}

const (
	// minGracePeriod is the floor of the grace period a still-pending dial gets.
	minGracePeriod = 300 * time.Millisecond
	// bannerReadMargin sits inside the banner timeout, so a peer that never
	// answers times out on the read instead of losing the race with the deadline
	// that ends the read.
	bannerReadMargin = 20 * time.Millisecond
	// sniffTimeout bounds the plain-mode peek: a local connection that says
	// nothing is not an SSH client. ssh writes its banner the instant it
	// connects, so a tenth of a second is plenty even over a real network.
	sniffTimeout = 100 * time.Millisecond
)

// resolved fills in the engine defaults. A bare IP keeps no server name: a proxy
// that routes by name has nothing to route on, so naming the server is what makes
// the TLS side worth dialling.
func (c Config) resolved() Config {
	if c.SSHPort == 0 {
		c.SSHPort = 22
	}
	if c.TLSPort == 0 {
		c.TLSPort = 443
	}
	if c.ServerName == "" && net.ParseIP(c.Host) == nil {
		c.ServerName = c.Host
	}
	if c.ALPN == nil {
		c.ALPN = []string{"ssh"}
	}
	if c.Name == "" {
		c.Name = "sclient"
	}
	return c
}

// dial is the plumbing each candidate is connected with. The timeouts are the
// session's; the protocol list is the gate's.
func (c Config) dial() tunnel.Dial {
	return tunnel.Dial{
		ServerName:         c.ServerName,
		NextProtos:         c.ALPN,
		InsecureSkipVerify: c.InsecureSkipVerify,
		TCPTimeout:         c.TCPTimeout,
		TLSTimeout:         c.TLSTimeout,
	}
}

// candidate is one attempt to reach the server.
type candidate struct {
	name    string // "ssh" or "tls"
	address string
	port    int
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
			// ErrNoServer is already reported candidate by candidate; a second
			// "no usable server" line says nothing new.
			if err := Serve(ctx, cfg, conn, errOut); err != nil && !errors.Is(err, ErrNoServer) {
				_, _ = fmt.Fprintf(errOut, "[error] %s\n", err)
			}
		}()
	}
}

// probe dials both ports on their own deadlines and returns the winner: the TLS
// connection if it speaks the ALPN we asked for, otherwise the plain SSH port.
func probe(ctx context.Context, cfg Config, clientBanner string, errOut io.Writer) (*candidate, error) {
	debugf := func(format string, args ...any) {
		if cfg.Verbose {
			_, _ = fmt.Fprintf(errOut, format+"\n", args...)
		}
	}

	// One lookup before either dial: both ports are the same name, so a name that
	// does not resolve is one failure, not two.
	if _, err := net.LookupHost(cfg.Host); err != nil {
		reportClose(errOut, cfg, err, nil)
		return nil, ErrNoServer
	}

	// The outer bound on the probe: the connect timeout plus the longest handshake
	// a candidate can spend, or the caller's own deadline if that is sooner. Each
	// dial keeps its own deadline; the grace period only shortens this one.
	dial := cfg.dial()
	connect := dial.ConnectTimeout()
	deadline := time.Now().Add(connect + dial.HandshakeDeadline(connect))
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	probeCtx, cancelProbe := context.WithCancelCause(ctx)
	defer cancelProbe(nil)
	timer := time.AfterFunc(time.Until(deadline), func() { cancelProbe(errProbeDeadline) })

	candidates := make(chan *candidate, 2)
	connected := make(chan time.Duration, 2)

	// decided closes the moment a candidate is confirmed, so a handshake we no
	// longer need is cut short instead of running to its deadline.
	decided := make(chan struct{})
	var decideOnce sync.Once
	decide := func() { decideOnce.Do(func() { close(decided) }) }

	go func() {
		candidates <- dialPlain(probeCtx, cfg, clientBanner, func(elapsed time.Duration) { connected <- elapsed }, debugf)
	}()
	if tryTLS(cfg) {
		go func() {
			candidates <- dialTLS(ctx, probeCtx, cfg, clientBanner, func(elapsed time.Duration) { connected <- elapsed }, decided, debugf)
		}()
	} else {
		err := errors.New("skipped: an IP address has no name to route on, use --servername")
		c := &candidate{name: "tls", address: net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.TLSPort)), err: err}
		candidates <- c
		debugf("dial: tls %s: %v", c.address, err)
	}

	var ready, failed []*candidate
	var chosen *candidate
	graceStarted := false
	settled := 0
	for settled < 2 && chosen == nil {
		select {
		// The grace period starts when a connection is established - not when a
		// candidate is confirmed - so a blackholed port cannot hold the probe to
		// the full timeout.
		case elapsed := <-connected:
			if !graceStarted {
				graceStarted = true
				until := time.Now().Add(gracePeriod(elapsed))
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

	timer.Stop() // the probe deadline is done; the session is not probe-bounded

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

// gracePeriod is half the time since the dials started, floored at minGracePeriod.
func gracePeriod(elapsed time.Duration) time.Duration {
	return max(elapsed/2, minGracePeriod)
}

// bannerTimeout is how long a connected candidate may take to answer the banner:
// a quarter of the connect timeout, floored at one grace period, never past the
// time left in the probe.
func bannerTimeout(connect, remaining time.Duration) time.Duration {
	timeout := max(2*minGracePeriod, connect/4)
	if remaining < timeout {
		timeout = max(minGracePeriod, remaining)
	}
	return timeout
}

// dialPlain connects to the SSH port without TLS, then exchanges banners.
func dialPlain(probeCtx context.Context, cfg Config, clientBanner string, onConnected func(time.Duration), debugf func(string, ...any)) *candidate {
	start := time.Now()
	c := &candidate{name: "ssh", address: net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.SSHPort)), port: cfg.SSHPort}

	dial := cfg.dial()
	conn, err := dial.DialPlain(probeCtx, c.address, onConnected)
	if err != nil {
		c.err = dialError(err, time.Since(start), probeCtx)
		return c
	}
	c.conn = conn
	c.r = bufio.NewReaderSize(conn, 32*1024)
	return exchangeBanner(c, cfg, clientBanner, timeLeft(probeCtx), debugf)
}

// dialTLS connects to the TLS port and applies the ALPN gate before the banner is
// sent: a server that will not name a protocol we asked for is not routing ssh for
// this name, so it never sees the banner.
func dialTLS(ctx, probeCtx context.Context, cfg Config, clientBanner string, onConnected func(time.Duration), decided chan struct{}, debugf func(string, ...any)) *candidate {
	start := time.Now()
	c := &candidate{name: "tls", address: net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.TLSPort)), port: cfg.TLSPort}

	dial := cfg.dial()
	conn, err := dial.DialPlain(probeCtx, c.address, onConnected)
	if err != nil {
		c.err = dialError(err, time.Since(start), probeCtx)
		return c
	}

	// The handshake is off the probe deadline: the grace period that closes a
	// blackholed port must not cut it short, and a server that already has a
	// certificate answers in a couple of round trips.
	handshake, cancelHandshake := context.WithTimeout(ctx, dial.HandshakeDeadline(time.Since(start)))
	defer cancelHandshake()
	go func() {
		select {
		case <-decided:
			cancelHandshake()
		case <-handshake.Done():
		}
	}()

	tlsConn := tls.Client(conn, dial.TLSConfig(cfg.ALPN))
	if err := tlsConn.HandshakeContext(handshake); err != nil {
		_ = conn.Close()
		c.err = dialError(fmt.Errorf("tls: %w", err), time.Since(start), probeCtx)
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
		c.err = fmt.Errorf("negotiated ALPN %s in %s, wanted one of [%s]",
			name, tunnel.ElapsedText(time.Since(start)), strings.Join(cfg.ALPN, ", "))
		return c
	}

	c.conn = tlsConn
	c.r = bufio.NewReaderSize(tlsConn, 32*1024)
	return exchangeBanner(c, cfg, clientBanner, timeLeft(probeCtx), debugf)
}

// exchangeBanner writes the client banner, reads the reply, and applies the host
// gate. A candidate that comes back with err set is not usable.
func exchangeBanner(c *candidate, cfg Config, clientBanner string, remaining time.Duration, debugf func(string, ...any)) *candidate {
	timeout := bannerTimeout(cfg.dial().ConnectTimeout(), remaining)
	_ = c.conn.SetReadDeadline(time.Now().Add(timeout - bannerReadMargin))
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

// timeLeft is how much time the probe deadline has left.
func timeLeft(probeCtx context.Context) time.Duration {
	dl, ok := probeCtx.Deadline()
	if !ok {
		return minGracePeriod
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
// The session is bounded by ctx, not by the probe deadline.
func relay(ctx context.Context, chosen *candidate, client *bufio.Reader, local net.Conn, errOut io.Writer) error {
	if chosen.banner != "" {
		_, _ = fmt.Fprintf(local, "%s\r\n", chosen.banner)
	}

	// PipeContext copies both directions and hangs up on both when ctx is canceled.
	if err := tunnel.PipeContext(ctx, &tunnel.BufferedConn{R: client, Conn: local}, chosen.conn); err != nil {
		_, _ = fmt.Fprintf(errOut, "[copy error] %s\n", err)
	}
	return nil
}

// reportNoServer names every candidate and why it lost, then closes the session in
// ssh's own words so "Connection closed by UNKNOWN port 65535" has a cause.
func reportNoServer(cfg Config, ready, failed []*candidate, errOut io.Writer) {
	if cfg.Silent {
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %s: no usable server\n", cfg.Name, cfg.Host)
	for _, c := range ready {
		fmt.Fprintf(&b, "  %s %d: %s\n", c.name, c.port, c.mismatch)
	}
	for _, c := range failed {
		fmt.Fprintf(&b, "  %s %d: %v\n", c.name, c.port, c.err)
	}
	close := CloseError{Name: cfg.Name, Reason: cfg.Host, Ports: attemptedPorts(cfg), cause: ErrNoServer}
	fmt.Fprintf(&b, "%s\n", close.Line())
	fmt.Fprint(errOut, b.String())
}

// reportClose is the same report for a failure before any dial: the name did not
// resolve, so there is no host to name and no port that was tried.
func reportClose(errOut io.Writer, cfg Config, err error, ports []int) {
	if cfg.Silent {
		return
	}
	_, _ = fmt.Fprintf(errOut, "%s: %s: no usable server: %s\n", cfg.Name, cfg.Host, strings.ToLower(lookupReason(err)))
	close := CloseError{Name: cfg.Name, Reason: lookupReason(err), Ports: ports, cause: ErrNoServer}
	_, _ = fmt.Fprintln(errOut, close.Line())
}

// attemptedPorts is every port this session was asked to dial: the plain port the
// ProxyCommand passed as %p, and the TLS port on the address.
func attemptedPorts(cfg Config) []int {
	ports := []int{cfg.SSHPort}
	if tryTLS(cfg) {
		ports = append(ports, cfg.TLSPort)
	}
	return ports
}

// lookupReason is the short cause of a failed lookup: "lookup host: no such host"
// becomes "NO SUCH HOST" - the host is in the header already, so the cause is only
// the part that names what went wrong.
func lookupReason(err error) string {
	text := err.Error()
	index := strings.LastIndex(text, ": ")
	if index < 0 {
		return strings.ToUpper(text)
	}
	return strings.ToUpper(text[index+2:])
}

// closeOut lets a client waiting on the pipe see EOF when we give up.
func closeOut(w io.Writer) {
	if c, ok := w.(io.Closer); ok {
		_ = c.Close()
	}
}

// errProbeDeadline marks a cancel that came from the probe deadline - the outer
// timeout or the grace period - rather than from the caller.
var errProbeDeadline = errors.New("probe deadline passed")

// dialError names the reason a dial never connected: a deadline gives a timeout,
// the caller pulling the plug gives a cancellation.
func dialError(err error, elapsed time.Duration, probeCtx context.Context) error {
	timeout := fmt.Errorf("timed out after %s", tunnel.ElapsedText(elapsed))
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return timeout
	case errors.Is(err, context.Canceled):
		if errors.Is(context.Cause(probeCtx), errProbeDeadline) {
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
	_ = conn.SetReadDeadline(time.Now().Add(sniffTimeout))
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
