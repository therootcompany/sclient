// Package sshtlsproxy is the dual-port SSH proxy engine: it dials a
// host's plain-SSH port and its TLS-terminated port simultaneously, runs
// the RFC 4253 section 4.2 banner exchange against whichever answer(s)
// arrive, prefers the TLS-terminated connection, and splices the caller's
// streams onto the winner. The simultaneous probe with the banner
// exchange is the point of the package; a try-one-port-then-fallback is
// a different (weaker) tool.
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
	"time"
)

// ErrNoServer is returned by Probe when neither candidate answers the
// banner exchange. The diagnostic report is written to errOut before it
// is returned.
var ErrNoServer = errors.New("no usable server")

// Config is the configuration for one probe. Zero values take the
// engine defaults: ports 22/443, a 3s overall clock, ALPN "ssh" (this
// is an SSH proxy). ALPN nil means the default; an explicitly empty
// list means the caller wants no ALPN (nothing offered, no note).
// Dialer nil means the engine's default dialer: each connect bounded by
// the probe clock, 30s TCP keep-alive. TLS is the caller's
// *tls.Config, used as-is when non-nil; when nil the engine builds the
// default: ServerName = Host, NextProtos = ALPN, MinVersion TLS 1.2.
// ALPN is also used for the diagnostic note when the negotiated
// protocol is outside it.
type Config struct {
	// Name is the tool name used in diagnostic lines; the caller sets it.
	Name    string
	Host    string
	SSHPort int
	TLSPort int
	ALPN    []string
	Timeout time.Duration
	Verbose bool
	Silent  bool
	Dialer  *net.Dialer
	TLS     *tls.Config
}

// maxBannerLen is the limit for an SSH protocol identification string
// (RFC 4253 section 4.2: "The maximum length of this string is 255
// characters, not including the location-dependent CR and LF").
const maxBannerLen = 255

var errNotSSHBanner = errors.New("not an SSH identification banner")

// readBanner reads one SSH identification line from r and returns the
// banner text (terminator stripped). It is bounded: at most
// maxBannerLen+2 bytes are consumed, so a peer that never sends a
// newline cannot make it buffer forever. Bytes read beyond the line
// terminator (e.g. a KEXINIT glued to the server banner) remain
// buffered in r for the caller to relay.
func readBanner(r *bufio.Reader) (string, error) {
	var sb strings.Builder
	for i := 0; i <= maxBannerLen+1; i++ { // at most 255 chars + CRLF
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

// writeBanner sends the given identification line, CRLF-terminated.
func writeBanner(w io.Writer, banner string) error {
	_, err := io.WriteString(w, banner+"\r\n")
	return err
}

// minGrace is the floor for the extra time a still-pending candidate
// gets after the first transport comes up.
const minGrace = 150 * time.Millisecond

// graceFor returns the extra time to allow a still-pending candidate
// after the first transport comes up: half the elapsed time since both
// dials started, floored at minGrace. Example: first connects in
// 300ms, the other has an additional 150ms.
func graceFor(elapsed time.Duration) time.Duration {
	return max(elapsed/2, minGrace)
}

// candidate is one attempt to reach the server.
type candidate struct {
	name    string // "ssh" or "tls"
	address string
	conn    net.Conn
	// r reads from conn; it preserves read-ahead (e.g. a KEXINIT
	// glued to the server banner) for the splice.
	r         *bufio.Reader
	elapsed   time.Duration // dial start until settled
	err       error
	banner    string // server banner, once read
	bannerErr error
	// alpnNote is set when TLS completed without an accepted ALPN
	// protocol. The connection is still tried — the banner may be
	// answered — and the note is part of the failure report when it
	// is not.
	alpnNote string
}

// dialCandidate dials one candidate. onTransport reports when the
// transport is up (TCP connected; for TLS, handshake completed) with
// the elapsed time — the grace clock arms on that event, so a
// blackholed sibling port cannot hold the probe out to the full timeout.
// A nil tlsCfg means the plain-SSH candidate.
func dialCandidate(ctx context.Context, cfg Config, port int, kind string, dialer *net.Dialer, tlsCfg *tls.Config, onTransport func(time.Duration)) *candidate {
	start := time.Now()
	c := &candidate{name: kind, address: net.JoinHostPort(cfg.Host, strconv.Itoa(port))}
	conn, err := dialer.DialContext(ctx, "tcp", c.address)
	if err == nil && tlsCfg != nil {
		conn, err = tlsHandshake(ctx, conn, tlsCfg)
	}
	if err == nil {
		onTransport(time.Since(start))
		if tlsCfg != nil {
			tlsConn := conn.(*tls.Conn)
			p := tlsConn.ConnectionState().NegotiatedProtocol
			if len(cfg.ALPN) > 0 && !slices.Contains(cfg.ALPN, p) {
				// The front terminated TLS without the accepted protocol.
				// It may still be forwarding to the sshd (ALPN is a
				// routing hint on this fleet, not a security property),
				// so the connection is kept and the banner sent — there
				// is no loss in trying, and the note is reported if the
				// banner is not answered.
				negotiated := "(none)"
				if p != "" {
					negotiated = strconv.Quote(p)
				}
				c.alpnNote = fmt.Sprintf("TLS negotiated ALPN %s, required one of [%s]",
					negotiated, strings.Join(cfg.ALPN, ", "))
			}
		}
	}
	if err != nil {
		c.err = dialError(err, time.Since(start))
	} else {
		c.conn = conn
		c.r = bufio.NewReaderSize(conn, 32*1024)
	}
	c.elapsed = time.Since(start)
	return c
}

// dialError replaces Go's "operation was canceled" with what actually
// happened. In this program the context is only ever canceled by the probe's
// own clock - the overall --timeout or the grace window - so a canceled dial
// is a timeout, and the elapsed time is worth reporting.
func dialError(err error, elapsed time.Duration) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("timed out after %s", elapsed.Round(10*time.Millisecond))
	}
	return err
}

// tlsHandshake completes the TLS handshake with the caller's config.
// ALPN policy is checked by the caller, after the transport-up report.
func tlsHandshake(ctx context.Context, conn net.Conn, tlsCfg *tls.Config) (*tls.Conn, error) {
	tlsConn := tls.Client(conn, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("tls %s: %w", conn.RemoteAddr(), err)
	}
	return tlsConn, nil
}

// resolved fills in the engine defaults: ports 22/443, a 3s clock,
// ALPN "ssh", a default dialer, and the default tls.Config when the
// caller did not supply one.
func (cfg Config) resolved() (Config, *net.Dialer, *tls.Config) {
	if cfg.SSHPort == 0 {
		cfg.SSHPort = 22
	}
	if cfg.TLSPort == 0 {
		cfg.TLSPort = 443
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 3 * time.Second
	}
	if cfg.ALPN == nil {
		cfg.ALPN = []string{"ssh"}
	}
	dialer := cfg.Dialer
	if dialer == nil {
		dialer = &net.Dialer{
			Timeout:   cfg.Timeout, // the clock bounds each connect too
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

// Probe drives one connection attempt. It returns nil when a session
// completed through the splice, ErrNoServer when neither candidate is
// usable (the diagnostic report is already on errOut), or another error
// for a client-side failure. The caller supplies the root context; Probe
// derives its probe clock from it.
func Probe(ctx context.Context, cfg Config, in io.Reader, out io.Writer, errOut io.Writer) error {
	cfg, dialer, tlsCfg := cfg.resolved()
	debugf := func(format string, args ...any) {
		if cfg.Verbose {
			_, _ = fmt.Fprintf(errOut, format+"\n", args...)
		}
	}

	start := time.Now()
	ctx, cancel := context.WithCancel(ctx)
	timer := time.AfterFunc(cfg.Timeout, cancel)
	defer cancel()

	// Phase 0: client banner. The client MUST wait for the server
	// banner before proceeding (RFC 4253 4.2), so intercepting one
	// line is safe; nothing else is in flight on the client side.
	clientIn := bufio.NewReaderSize(in, 32*1024)
	clientDone := make(chan clientResult, 1)
	go func() {
		banner, err := readBanner(clientIn)
		clientDone <- clientResult{banner, err}
	}()

	// Phase 1: connect to both candidates at once.
	res := make(chan *candidate, 2)
	up := make(chan time.Duration, 2)
	go func() {
		res <- dialCandidate(ctx, cfg, cfg.SSHPort, "ssh", dialer, nil, func(el time.Duration) { up <- el })
	}()
	go func() {
		res <- dialCandidate(ctx, cfg, cfg.TLSPort, "tls", dialer, tlsCfg, func(el time.Duration) { up <- el })
	}()

	ready := make([]*candidate, 0, 2)
	failed := make([]*candidate, 0, 2)
	graceArmed := false
	settled := 0
	for settled < 2 {
		select {
		// First transport up arms the grace: the other side then has
		// max(150ms, half this elapsed time), clamped to the overall
		// deadline. Arming on transport-up — not on a ready candidate
		// — is what keeps a blackholed sibling port from holding the
		// probe out to the full timeout when no candidate can become
		// ready (e.g. TLS front with no route, plain port blackholed).
		case el := <-up:
			if !graceArmed {
				graceArmed = true
				d := time.Now().Add(graceFor(el))
				if dl := start.Add(cfg.Timeout); d.After(dl) {
					d = dl
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
			if c.alpnNote != "" {
				debugf("dial: %s %s: %s", c.name, c.address, c.alpnNote)
			}
			debugf("dial: %s %s ready in %v", c.name, c.address, c.elapsed)
		}
	}

	clientBanner, clientErr := takeClientResult(clientDone, ctx)
	// The probe clock is done; the banner phase below runs on
	// connection deadlines, and the splice runs on none at all.
	timer.Stop()
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
	debugf("banner: client %q", clientBanner)

	if len(ready) == 0 {
		failNoServer(cfg, nil, failed, errOut)
		closeOut(out)
		return ErrNoServer
	}

	// Phase 2: banner exchange. Send the client banner to every ready
	// candidate and read each server banner, with the same grace rule.
	probeDeadline := start.Add(cfg.Timeout)
	exchangeBanners(probeDeadline, ready, clientBanner, debugf)

	chosen := pickCandidate(ready)
	if chosen == nil {
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
	splice(chosen, clientIn, out)
	return nil
}

// clientResult is the outcome of reading the client banner.
type clientResult struct {
	banner string
	err    error
}

// takeClientResult waits for the client banner or context expiration,
// draining the buffered result first so a ready banner is never dropped.
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

// closeOut closes out if it is a Closer, so a client waiting on the
// pipe sees EOF when we give up.
func closeOut(out io.Writer) {
	if c, ok := out.(io.Closer); ok {
		_ = c.Close()
	}
}

// pickCandidate prefers the TLS-terminated connection when both answered.
func pickCandidate(ready []*candidate) *candidate {
	var plain, tlsC *candidate
	for _, c := range ready {
		if c.name == "tls" {
			tlsC = c
		} else {
			plain = c
		}
	}
	if tlsC != nil && tlsC.bannerErr == nil {
		return tlsC
	}
	if plain != nil && plain.bannerErr == nil {
		return plain
	}
	return nil
}

// exchangeBanners writes the client banner to every candidate and reads
// each server banner under the same grace rule as the dials: the first
// answer gives the rest max(150ms, half the elapsed time), clamped to the
// overall deadline. Every candidate comes back with either a banner or a
// bannerErr; a candidate still pending when the deadline passes is drained,
// never waited on.
func exchangeBanners(probeDeadline time.Time, ready []*candidate, clientBanner string, debugf func(string, ...any)) {
	sent := time.Now()
	bch := make(chan *candidate, len(ready))
	for _, c := range ready {
		_ = c.conn.SetReadDeadline(probeDeadline)
		go func(c *candidate) {
			if err := writeBanner(c.conn, clientBanner); err != nil {
				c.bannerErr = err
				bch <- c
				return
			}
			banner, err := readBanner(c.r)
			c.banner, c.bannerErr = banner, err
			bch <- c
		}(c)
	}

	remaining := append([]*candidate(nil), ready...)
	stopAt := time.NewTimer(time.Until(probeDeadline))
	defer stopAt.Stop()
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
			if !firstOK {
				firstOK = true
				d := time.Now().Add(graceFor(time.Since(sent)))
				if d.After(probeDeadline) {
					d = probeDeadline
				}
				for _, o := range remaining {
					_ = o.conn.SetReadDeadline(d)
				}
			}
		case <-stopAt.C:
			// Each goroutine sends exactly once, so this cannot block.
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

// splice hands the client over to c and pumps both directions until the
// server closes. The server banner (already read) plus any buffered
// read-ahead are the first bytes the client sees. The interception
// machinery ends here: from this point on the proxy is a dumb pipe.
func splice(c *candidate, clientIn *bufio.Reader, out io.Writer) {
	// Sessions go idle; no more timers.
	_ = c.conn.SetDeadline(time.Time{})

	pumped := make(chan struct{})
	go func() {
		defer close(pumped)
		_ = writeBanner(out, c.banner)
		_, _ = io.Copy(out, c.r)
	}()
	_, _ = io.Copy(c.conn, clientIn)
	_ = c.conn.Close()
	<-pumped // let the server->client pump drain before we go
}

// failNoServer reports that neither candidate is usable. The message
// goes to errOut and nowhere else: the caller picks the destination.
// A command whose stderr OpenSSH has redirected to /dev/null
// (ControlPath + valued ControlPersist; since 8.0) can pass
// StderrOrTTY so the report also reaches the controlling terminal,
// which is still reachable because the proxy is forked before the
// master daemon()s. Under a client with no terminal the exit status
// (255) is what always propagates; -o ControlPath=none,
// -o ControlPersist=no, or -v keeps the message on plain stderr.
func failNoServer(cfg Config, ready, failed []*candidate, errOut io.Writer) {
	if cfg.Silent {
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %s: no usable server\n", cfg.Name, cfg.Host)
	for _, c := range ready {
		if c.alpnNote != "" {
			fmt.Fprintf(&b, "  %s %s: %s: %v\n", c.name, c.address, c.alpnNote, c.bannerErr)
			continue
		}
		fmt.Fprintf(&b, "  %s %s: %v\n", c.name, c.address, c.bannerErr)
	}
	for _, c := range failed {
		fmt.Fprintf(&b, "  %s %s: %v\n", c.name, c.address, c.err)
	}
	fmt.Fprint(errOut, b.String())
}
