// Package sshtlsproxy dials a host's plain-SSH and TLS-terminated ports
// at once, runs the RFC 4253 section 4.2 banner exchange against
// whichever answer(s) arrive, prefers the TLS connection, and splices the
// caller's streams onto the winner. The simultaneous probe is the point;
// a try-one-port-then-fallback is a different, weaker tool.
package sshtlsproxy

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
)

// ErrNoServer means neither candidate answered the banner exchange; the
// diagnostic report is already on errOut.
var ErrNoServer = errors.New("no usable server")

// Config for one probe. Zero values take the engine defaults: ports 22/443,
// a 5s connect clock and a 45s handshake clock, ALPN "ssh" (nil = default;
// explicit empty = offer no ALPN and no gate). Dialer nil means one bounded
// by the connect clock with 30s keep-alive; TLS, when non-nil, is used as-is.
type Config struct {
	Name       string // used in diagnostic lines
	Host       string
	ServerName string // the name the connection is *for*; defaults to Host
	SSHPort    int
	TLSPort    int
	ALPN       []string
	TCPTimeout time.Duration // one TCP connect, DNS included (default 5s)
	// TLSTimeout bounds one TLS handshake, measured from the connect. Zero -
	// the default - is auto: twice that candidate's own connect time, floored
	// at 150ms. A number is taken literally, and is for a front known to issue
	// a certificate on first use.
	TLSTimeout time.Duration
	Verbose bool
	Silent  bool
	Dialer  *net.Dialer
	TLS     *tls.Config
}

// maxBannerLen: RFC 4253 section 4.2 caps the identification string at 255
// characters, excluding CRLF.
const maxBannerLen = 255

var errNotSSHBanner = errors.New("not an SSH identification banner")

// readBanner reads one identification line, bounded so a peer that never
// sends a newline cannot buffer forever. Bytes past the terminator (a
// glued KEXINIT) stay in r for the caller to relay.
func readBanner(r *bufio.Reader) (string, error) {
	var sb strings.Builder
	for range maxBannerLen + 2 {
		b, err := r.ReadByte()
		if err != nil {
			return "", fmt.Errorf("read banner: %w", err)
		}
		if b == '\n' {
			banner := strings.TrimRight(sb.String(), "\r")
			if len(banner) > maxBannerLen {
				return "", fmt.Errorf("banner too long: %d bytes", len(banner))
			}
			if !strings.HasPrefix(banner, "SSH-") {
				return "", fmt.Errorf("%w: %q", errNotSSHBanner, banner)
			}
			return banner, nil
		}
		_ = sb.WriteByte(b)
	}
	return "", fmt.Errorf("banner too long: more than %d bytes", maxBannerLen)
}

func writeBanner(w io.Writer, banner string) error {
	_, err := io.WriteString(w, banner+"\r\n")
	return err
}

// A server can name itself in the RFC 4253 section 4.2 comment, e.g.
// "SSH-2.0-OpenSSH_9.6 tlsrouter-v0.9.4 host:vms.example.com". These are the
// fields the engine reads.
var hostFields = []string{"hostname:", "host:"}

// declaredHosts returns the hosts a banner declares, or nil when it declares
// none. The comment is everything after the first space.
func declaredHosts(banner string) []string {
	_, after, ok := strings.Cut(banner, " ")
	if !ok {
		return nil
	}
	var hosts []string
	for field := range strings.FieldsSeq(after) {
		value := hostValue(field)
		if value == "" {
			continue
		}
		for host := range strings.SplitSeq(value, ",") {
			if host = strings.TrimSpace(host); host != "" {
				hosts = append(hosts, host)
			}
		}
	}
	return hosts
}

// hostValue is the value of a "host:" or "hostname:" field, "" otherwise.
// "hostname:" is tried first because "host:" is its prefix.
func hostValue(field string) string {
	for _, prefix := range hostFields {
		if len(field) > len(prefix) && strings.EqualFold(field[:len(prefix)], prefix) {
			return field[len(prefix):]
		}
	}
	return ""
}

// bannerMismatch explains why a banner names a server other than the one we
// asked for; "" means it matches or makes no claim at all. Only a declared
// host list can refuse a candidate. An IP literal is not contradicted by a
// name list: the banner may name any of the box's own names and still be the
// machine we dialled.
func bannerMismatch(want, banner string) string {
	declared := declaredHosts(banner)
	if want == "" || len(declared) == 0 || net.ParseIP(want) != nil {
		return ""
	}
	for _, host := range declared {
		if strings.EqualFold(host, want) {
			return ""
		}
	}
	return fmt.Sprintf("banner %q declares %s, not %q", banner, strings.Join(declared, ", "), want)
}

// minGrace is the floor for the grace a still-pending candidate gets.
const minGrace = 150 * time.Millisecond

// graceFor is half the elapsed time since the dials started, floored at
// minGrace.
func graceFor(elapsed time.Duration) time.Duration {
	return max(elapsed/2, minGrace)
}

// candidate is one attempt to reach the server.
type candidate struct {
	name      string // "ssh" or "tls"
	address   string
	conn      net.Conn
	r         *bufio.Reader // keeps read-ahead (glued KEXINIT) for the splice
	elapsed   time.Duration
	err       error
	banner    string
	bannerErr error
	// mismatch is non-empty when a banner declared hosts (RFC 4253 4.2) and
	// none of them is the name we asked for: this candidate is a different
	// server, so it is not usable.
	mismatch string
	// declared is true when the banner named any host at all. A declared,
	// matching banner is proof of identity on its own: the other port is no
	// longer worth waiting for.
	declared bool
}

// dialCandidateTCP dials one plain port. onTransport fires when the
// transport is up - the grace clock arms on that event, so a blackholed
// sibling port cannot hold the probe to the full timeout.
func dialCandidateTCP(clock context.Context, cfg Config, port int, dialer *net.Dialer, onTransport func(time.Duration)) *candidate {
	start := time.Now()
	c := &candidate{name: "ssh", address: net.JoinHostPort(cfg.Host, strconv.Itoa(port))}
	conn, err := dialer.DialContext(clock, "tcp", c.address)
	if err != nil {
		c.err = dialError(err, time.Since(start), clock)
		return c
	}
	c.ready(start, conn)
	return c
}

// dialCandidateTLS dials the TLS port: the connect runs on the dial clock, the
// handshake on its own - auto, it is twice this candidate's connect time.
// An ALPN list is a requirement, not a hint: a front that terminates TLS but
// will not name a protocol we asked for has no ssh route for this name, so
// that candidate ends at the handshake. `--alpn ""` (empty, non-nil) turns the
// gate off for fronts that do not speak ALPN.
//
// decided is closed as soon as another candidate is confirmed; a handshake we
// no longer need is cut short rather than allowed to run out its clock.
func dialCandidateTLS(ctx, clock context.Context, cfg Config, port int, dialer *net.Dialer, tlsCfg *tls.Config, onTransport func(time.Duration), decided chan struct{}) *candidate {
	start := time.Now()
	c := &candidate{name: "tls", address: net.JoinHostPort(cfg.Host, strconv.Itoa(port))}
	conn, err := dialer.DialContext(clock, "tcp", c.address)
	if err != nil {
		c.err = dialError(err, time.Since(start), clock)
		return c
	}
	// The socket is up: the grace clock arms here, whether the handshake
	// below fails or the ALPN gate closes the candidate.
	connect := time.Since(start)
	onTransport(connect)

	// The handshake gets its own clock, off the caller's context: the sibling
	// grace that closes a blackholed port must not strangle it, and a front
	// that already has a certificate answers in a couple of round trips.
	handshake := handshakeClock(cfg, connect)
	handshakeCtx, cancelHandshake := context.WithTimeout(ctx, handshake)
	defer cancelHandshake()
	if decided != nil {
		go func() {
			select {
			case <-decided:
				cancelHandshake()
			case <-handshakeCtx.Done():
			}
		}()
	}
	tconn := tls.Client(conn, tlsCfg)
	if err := tconn.HandshakeContext(handshakeCtx); err != nil {
		_ = conn.Close()
		switch {
		case errors.Is(err, context.DeadlineExceeded):
			c.err = fmt.Errorf("tls %s: timed out after %s: the TLS handshake did not complete",
				conn.RemoteAddr(), handshake.Round(10*time.Millisecond))
		case errors.Is(err, context.Canceled) && closed(decided):
			c.err = fmt.Errorf("tls %s: handshake skipped, the other side is confirmed",
				conn.RemoteAddr())
		default:
			c.err = dialError(fmt.Errorf("tls %s: %w", conn.RemoteAddr(), err), time.Since(start), clock)
		}
		return c
	}
	proto := tconn.ConnectionState().NegotiatedProtocol
	if len(cfg.ALPN) > 0 && !slices.Contains(cfg.ALPN, proto) {
		_ = conn.Close() // the gate: no banner is sent to a front that is not routing ssh
		negotiated := "(none)"
		if proto != "" {
			negotiated = strconv.Quote(proto)
		}
		c.err = fmt.Errorf("tls %s: negotiated ALPN %s, wanted one of [%s]",
			conn.RemoteAddr(), negotiated, strings.Join(cfg.ALPN, ", "))
		return c
	}
	c.ready(start, tconn)
	return c
}

// ready marks a candidate as usable: transport up and the reader armed.
// onTransport already fired when the socket connected.
func (c *candidate) ready(start time.Time, conn net.Conn) {
	c.conn = conn
	c.r = bufio.NewReaderSize(conn, 32*1024)
	c.elapsed = time.Since(start)
}

// errProbeClock marks a cancel that came from the probe clock - the timeout
// or the grace window - rather than from the caller.
var errProbeClock = errors.New("probe clock ran out")

// closed reports whether a signal channel has been closed, without consuming
// anything (a decided channel is closed, never sent to).
func closed(ch chan struct{}) bool {
	if ch == nil {
		return false
	}
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// dialError names the reason a dial never connected: the clock gives a
// timeout, the caller pulling the plug gives a cancellation.
func dialError(err error, elapsed time.Duration, clock context.Context) error {
	timeout := fmt.Errorf("timed out after %s", elapsed.Round(10*time.Millisecond))
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return timeout
	case errors.Is(err, context.Canceled):
		if errors.Is(context.Cause(clock), errProbeClock) {
			return timeout
		}
		return fmt.Errorf("canceled after %s", elapsed.Round(10*time.Millisecond))
	}
	return err
}

// The engine clocks. A connect that is not quick is dead. A handshake gets
// twice the connect that just happened: measured against public fronts the
// handshake runs 0.5-1.4x the connect, so 2x is roomy without letting the
// probe turn into a 45s wait. The floor keeps a sub-millisecond loopback
// connect from strangling a real handshake.
const (
	defaultTCPTimeout   = 5 * time.Second
	// A handshake never gets a shorter clock than the grace we give a pending
	// connect, so a sub-millisecond loopback connect cannot strangle it.
	minHandshakeClock   = minGrace
	handshakeMultiplier = 2
)

// handshakeClock is the TLS deadline for one candidate. An explicit
// --tls-timeout wins; zero - the default - is auto: twice this candidate's
// own connect time, with a floor.
func handshakeClock(cfg Config, connect time.Duration) time.Duration {
	if cfg.TLSTimeout > 0 {
		return cfg.TLSTimeout
	}
	return max(handshakeMultiplier*connect, minHandshakeClock)
}

// bannerWindow is how long a ready candidate may take to answer the banner:
// a quarter of the connect clock (floor one grace period), never past the
// ceiling.
func bannerWindow(cfg Config, deadline time.Time) time.Duration {
	window := max(2*minGrace, cfg.TCPTimeout/4)
	if remaining := time.Until(deadline); remaining < window {
		window = max(minGrace, remaining)
	}
	return window
}

// resolved fills in the engine defaults. TLSTimeout stays 0 when unset: the
// handshake clock is computed per candidate from its own connect time.
func (cfg Config) resolved() (Config, *net.Dialer, *tls.Config) {
	if cfg.SSHPort == 0 {
		cfg.SSHPort = 22
	}
	if cfg.TLSPort == 0 {
		cfg.TLSPort = 443
	}
	if cfg.TCPTimeout <= 0 {
		cfg.TCPTimeout = defaultTCPTimeout
	}
	if cfg.ALPN == nil {
		cfg.ALPN = []string{"ssh"}
	}
	if cfg.ServerName == "" {
		cfg.ServerName = cfg.Host
	}
	dialer := cfg.Dialer
	if dialer == nil {
		dialer = &net.Dialer{
			Timeout:   cfg.TCPTimeout, // the connect clock bounds each connect too
			KeepAlive: 30 * time.Second,
		}
	}
	tlsCfg := cfg.TLS
	if tlsCfg == nil {
		tlsCfg = &tls.Config{
			ServerName: cfg.Host,
			NextProtos: cfg.ALPN,
			MinVersion: tls.VersionTLS12,
		}
	}
	return cfg, dialer, tlsCfg
}

// Probe returns nil when a session completed through the splice,
// ErrNoServer when neither candidate is usable, or a client-side error.
// ctx bounds the probe and the session: the connect and handshake clocks cap
// the probe, but never bound the session.
func Probe(ctx context.Context, cfg Config, in io.Reader, out io.Writer, errOut io.Writer) error {
	if errOut == nil {
		errOut = io.Discard
	}
	cfg, dialer, tlsCfg := cfg.resolved()
	debugf := func(format string, args ...any) {
		if cfg.Verbose {
			_, _ = fmt.Fprintf(errOut, format+"\n", args...)
		}
	}

	// The ceiling: the connect clock plus the longest handshake a candidate
	// can spend, or the caller's own deadline if that is sooner. Every dial
	// ends on its own clock; this is only the outer bound on the probe. The
	// caller's ctx is kept for the session, which the probe clock must not
	// bound.
	deadline := time.Now().Add(cfg.TCPTimeout + handshakeClock(cfg, cfg.TCPTimeout))
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	clock, cancelClock := context.WithCancelCause(ctx)
	defer cancelClock(nil)
	connectWindow := cfg.TCPTimeout
	if remaining := time.Until(deadline); remaining < connectWindow {
		connectWindow = remaining
	}
	timer := time.AfterFunc(connectWindow, func() { cancelClock(errProbeClock) })

	// Intercepting exactly one client line is safe: the client waits for
	// the server banner before sending anything else (RFC 4253 4.2).
	clientIn := bufio.NewReaderSize(in, 32*1024)
	clientDone := make(chan clientResult, 1)
	go func() {
		banner, err := readBanner(clientIn)
		clientDone <- clientResult{banner, err}
	}()

	// Each candidate runs its own dial -> handshake -> banner pipeline on its
	// own clocks. Nothing waits for the other port past its own deadline.
	res := make(chan *candidate, 2)
	up := make(chan time.Duration, 2)

	// decided is closed the moment a candidate is confirmed; a handshake still
	// in flight watches it and stops.
	decided := make(chan struct{})
	var decideOnce sync.Once
	decide := func() { decideOnce.Do(func() { close(decided) }) }

	var clientBanner string
	var clientErr error
	var bannerOnce sync.Once
	clientBannerOf := func() (string, error) {
		bannerOnce.Do(func() {
			clientBanner, clientErr = takeClientResult(clientDone, clock)
		})
		return clientBanner, clientErr
	}

	go func() {
		c := dialCandidateTCP(clock, cfg, cfg.SSHPort, dialer, func(el time.Duration) { up <- el })
		res <- exchangeBanner(ctx, cfg, c, clientBannerOf, deadline, decided, debugf)
	}()
	go func() {
		c := dialCandidateTLS(ctx, clock, cfg, cfg.TLSPort, dialer, tlsCfg, func(el time.Duration) { up <- el }, decided)
		res <- exchangeBanner(ctx, cfg, c, clientBannerOf, deadline, decided, debugf)
	}()

	ready := make([]*candidate, 0, 2)
	failed := make([]*candidate, 0, 2)
	var chosen *candidate
	graceArmed := false
	settled := 0
	for settled < 2 && chosen == nil {
		select {
		// Arming the grace on transport-up - not on a ready candidate - is
		// what keeps a blackholed sibling from holding the probe to the
		// full timeout when nothing can become ready.
		case el := <-up:
			if !graceArmed {
				graceArmed = true
				d := time.Now().Add(graceFor(el))
				if d.After(deadline) {
					d = deadline
				}
				_ = timer.Reset(time.Until(d))
			}
		case c := <-res:
			settled++
			if c.err != nil {
				failed = append(failed, c)
				debugf("dial: %s %s: %v", c.name, c.address, c.err)
				continue
			}
			ready = append(ready, c)
			// A usable TLS candidate wins outright. A plain banner that
			// declares the name we asked for is proof of identity on its own:
			// take it, and stop the handshake we no longer need. An undeclared
			// banner proves nothing, so the TLS side keeps its chance.
			if c.usable() && (c.name == "tls" || c.declared) {
				chosen = c
				decide()
			}
		}
	}

	timer.Stop() // the dial clock is done; the session is not probe-bounded
	if chosen != nil {
		// Cut off any dial still in flight and close whatever it returns.
		cancelClock(errProbeClock)
		for settled < 2 {
			c := <-res
			settled++
			if c.conn != nil {
				_ = c.conn.Close()
			}
			debugf("dial: %s %s: %v", c.name, c.address, c.err)
		}
	}

	if clientErr != nil {
		for _, c := range ready {
			_ = c.conn.Close()
		}
		closeOut(out)
		if !cfg.Silent {
			_, _ = fmt.Fprintf(errOut, "%s: %s: client: %v\n", cfg.Name, cfg.Host, clientErr)
		}
		return clientErr
	}

	if chosen == nil {
		chosen = pickCandidate(ready)
	}
	if chosen == nil {
		for _, c := range ready {
			_ = c.conn.Close()
		}
		failNoServer(cfg, ready, failed, errOut)
		closeOut(out)
		return ErrNoServer
	}
	debugf("chosen: %s %s", chosen.name, chosen.address)
	for _, c := range ready {
		if c != chosen {
			_ = c.conn.Close()
		}
	}
	if !cfg.Silent {
		_, _ = fmt.Fprintf(errOut, "%s: %s: using %s (%s)\n", cfg.Name, cfg.Host, chosen.name, chosen.address)
	}
	// the session is bounded by the caller's ctx, not the probe clock
	splice(ctx, chosen, clientIn, out)
	return nil
}

// exchangeBanner finishes one candidate: it has a socket, so write the
// client's banner, read the reply, and apply the host gate. The candidate
// comes back usable, refused (its banner names a different server), or failed.
// Each candidate runs this on its own clock, so one slow peer cannot hold the
// probe for another.
func exchangeBanner(ctx context.Context, cfg Config, c *candidate, clientBannerOf func() (string, error), deadline time.Time, decided chan struct{}, debugf func(string, ...any)) *candidate {
	if c.err == nil && closed(decided) {
		c.err = fmt.Errorf("%s %s: not needed, the other side is confirmed", c.name, c.address)
		_ = c.conn.Close()
	}
	if c.err != nil {
		return c
	}
	banner, err := clientBannerOf()
	if err != nil {
		_ = c.conn.Close()
		c.bannerErr = err
		return c
	}
	window := bannerWindow(cfg, deadline)
	bannerDeadline := time.Now().Add(window)
	bannerClock, cancelBanner := context.WithDeadline(ctx, bannerDeadline)
	defer cancelBanner()
	debugf("banner: %s %s window %v", c.name, c.address, window)
	exchangeBanners(bannerClock, bannerDeadline, []*candidate{c}, banner, cfg.ServerName, debugf)
	return c
}

type clientResult struct {
	banner string
	err    error
}

// takeClientResult returns the banner, preferring a result already in the
// buffer over the clock's error.
func takeClientResult(clientDone <-chan clientResult, ctx context.Context) (string, error) {
	select {
	case cr := <-clientDone:
		return cr.banner, cr.err
	default:
	}
	select {
	case cr := <-clientDone:
		return cr.banner, cr.err
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// closeOut lets a client waiting on the pipe see EOF when we give up.
func closeOut(out io.Writer) {
	if c, ok := out.(io.Closer); ok {
		_ = c.Close()
	}
}

// usable: the banner answered, and it did not name a different server.
func (c *candidate) usable() bool {
	return c.bannerErr == nil && c.mismatch == ""
}

// pickCandidate prefers the TLS-terminated connection when both answered.
// A candidate whose banner declares a different server is not usable at all.
func pickCandidate(ready []*candidate) *candidate {
	var plain, tlsC *candidate
	for _, c := range ready {
		if c.name == "tls" {
			tlsC = c
		} else {
			plain = c
		}
	}
	if tlsC != nil && tlsC.usable() {
		return tlsC
	}
	if plain != nil && plain.usable() {
		return plain
	}
	return nil
}

// bannerReadMargin sits inside the exchange window: the read deadline is the
// window minus this, so a peer that never answers times out on the read (the
// report says "read banner: i/o timeout") instead of losing the race with the
// close that ends the window ("use of closed network connection").
const bannerReadMargin = 20 * time.Millisecond

// exchangeBanners writes the client banner to every candidate and reads
// each server banner. Every candidate sends exactly once, so the drain
// below cannot block: the clock (or the caller) cancels ctx, which closes
// the outstanding conns and makes every read return.
func exchangeBanners(ctx context.Context, probeDeadline time.Time, ready []*candidate, clientBanner, want string, debugf func(string, ...any)) {
	readDeadline := probeDeadline.Add(-bannerReadMargin)
	sent := time.Now()
	bch := make(chan *candidate, len(ready))
	for _, c := range ready {
		_ = c.conn.SetReadDeadline(readDeadline)
		go func(c *candidate) {
			if err := writeBanner(c.conn, clientBanner); err != nil {
				c.bannerErr = err
				bch <- c
				return
			}
			banner, err := readBanner(c.r)
			c.banner, c.bannerErr = banner, err
			if err == nil {
				hosts := declaredHosts(banner)
				c.declared = len(hosts) > 0
				c.mismatch = bannerMismatch(want, banner)
			}
			bch <- c
		}(c)
	}

	remaining := append([]*candidate(nil), ready...)
	firstOK := false
	for len(remaining) > 0 {
		select {
		case c := <-bch:
			remaining = removeCandidate(remaining, c)
			if c.bannerErr != nil {
				debugf("banner: %s %s: %v", c.name, c.address, c.bannerErr)
				continue
			}
			debugf("banner: %s %s answered %q", c.name, c.address, c.banner)
			if c.mismatch != "" {
				debugf("banner: %s %s: %s", c.name, c.address, c.mismatch)
				continue
			}
			if !firstOK {
				firstOK = true
				d := time.Now().Add(graceFor(time.Since(sent)))
				if d.After(readDeadline) {
					d = readDeadline
				}
				for _, o := range remaining {
					_ = o.conn.SetReadDeadline(d)
				}
			}
		case <-ctx.Done():
			for _, c := range remaining {
				_ = c.conn.Close()
			}
			for len(remaining) > 0 {
				remaining = removeCandidate(remaining, <-bch)
			}
		}
	}
}

func removeCandidate(list []*candidate, c *candidate) []*candidate {
	if i := slices.Index(list, c); i >= 0 {
		return append(list[:i:i], list[i+1:]...)
	}
	return list
}

// splice pumps both directions until the server closes. The banner and
// any buffered read-ahead are the first bytes the client sees; after this
// the proxy is a dumb pipe. Cancelling ctx closes the server connection and
// the client-facing writer: the client sees EOF, ssh exits, and its closed
// stdin ends the write pump.
func splice(ctx context.Context, c *candidate, clientIn *bufio.Reader, out io.Writer) {
	_ = c.conn.SetDeadline(time.Time{}) // sessions go idle

	var drained sync.WaitGroup
	drained.Go(func() {
		_ = writeBanner(out, c.banner)
		_, _ = io.Copy(out, c.r)
	})

	watch := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			// closing the server conn ends the read pump; closing out gives
			// the client its EOF, and ssh then closes its stdin, which ends
			// the write pump.
			_ = c.conn.Close()
			closeOut(out)
		case <-watch:
		}
	}()
	_, _ = io.Copy(c.conn, clientIn)
	close(watch)
	_ = c.conn.Close()
	drained.Wait() // drain the server->client pump before returning
}

// failNoServer writes the report to errOut and nowhere else; the caller
// picks the destination. ssh can null a ProxyCommand's stderr (ControlPath
// + valued ControlPersist, since 8.0); sshtlsproxy.Stderr() works around that.
func failNoServer(cfg Config, ready, failed []*candidate, errOut io.Writer) {
	if cfg.Silent {
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %s: no usable server\n", cfg.Name, cfg.Host)
	for _, c := range ready {
		switch {
		case c.bannerErr != nil:
			fmt.Fprintf(&b, "  %s %s: %v\n", c.name, c.address, c.bannerErr)
		default:
			// answered the banner, but declared a server that is not the one asked for
			fmt.Fprintf(&b, "  %s %s: %s\n", c.name, c.address, c.mismatch)
		}
	}
	for _, c := range failed {
		fmt.Fprintf(&b, "  %s %s: %v\n", c.name, c.address, c.err)
	}
	fmt.Fprint(errOut, b.String())
}
