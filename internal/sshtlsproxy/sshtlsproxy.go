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
// a 3s clock, ALPN "ssh" (nil = default; explicit empty = offer no ALPN and
// no note). Dialer nil means one bounded by the clock with 30s keep-alive;
// TLS, when non-nil, is used as-is.
type Config struct {
	Name    string // used in diagnostic lines
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
	// set when TLS completed without an accepted ALPN: the connection is
	// still tried, and the note leads the failure report if unanswered.
	alpnNote string
}

// dialCandidate dials one port. onTransport fires when the transport is
// up (TCP connected; for TLS, handshake done) - the grace clock arms on
// that event, so a blackholed sibling port cannot hold the probe to the
// full timeout. A nil tlsCfg means the plain-SSH candidate.
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
				// ALPN is a routing hint on this fleet, not a security
				// property: a front that terminates without it may still
				// forward to sshd, so the banner is sent anyway and the
				// note is reported only if it is not answered.
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

// dialError renames Go's "operation was canceled": the only cancel here
// is the probe clock, so a canceled dial is a timeout worth reporting.
func dialError(err error, elapsed time.Duration) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("timed out after %s", elapsed.Round(10*time.Millisecond))
	}
	return err
}

// tlsHandshake completes the handshake; ALPN policy is the caller's job.
func tlsHandshake(ctx context.Context, conn net.Conn, tlsCfg *tls.Config) (*tls.Conn, error) {
	tlsConn := tls.Client(conn, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("tls %s: %w", conn.RemoteAddr(), err)
	}
	return tlsConn, nil
}

// resolved fills in the engine defaults.
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

// Probe returns nil when a session completed through the splice,
// ErrNoServer when neither candidate is usable, or a client-side error.
// The caller supplies the root context; Probe derives its own clock.
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

	// Intercepting exactly one client line is safe: the client waits for
	// the server banner before sending anything else (RFC 4253 4.2).
	clientIn := bufio.NewReaderSize(in, 32*1024)
	clientDone := make(chan clientResult, 1)
	go func() {
		banner, err := readBanner(clientIn)
		clientDone <- clientResult{banner, err}
	}()

	// dial both ports at once
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
		// Arming the grace on transport-up - not on a ready candidate - is
		// what keeps a blackholed sibling from holding the probe to the
		// full timeout when nothing can become ready.
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
	timer.Stop() // banner phase uses per-conn deadlines; the splice uses none
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

	// banner exchange with the same grace rule as the dials
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
// each server banner. Every candidate sends exactly once, so the drain
// below cannot block.
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
// the proxy is a dumb pipe.
func splice(c *candidate, clientIn *bufio.Reader, out io.Writer) {
	_ = c.conn.SetDeadline(time.Time{}) // sessions go idle

	var drained sync.WaitGroup
	drained.Go(func() {
		_ = writeBanner(out, c.banner)
		_, _ = io.Copy(out, c.r)
	})
	_, _ = io.Copy(c.conn, clientIn)
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
