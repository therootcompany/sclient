package sclient

import (
	"bufio"
	"context"
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

// SSH mode dials one name on two transports at once - plain SSH on the SSH port,
// SSH wrapped in TLS on the TLS port - and takes the one that is the SSH server
// for that name. Two checks decide a candidate: the ALPN it negotiates, and the
// host its banner declares (RFC 4253 section 4.2). A banner that declares nothing
// is accepted; the rule is opt-in per server.

// ErrNoServer marks an SSH-mode session where neither port was usable. The
// wrapped error carries the report; the command only has to print it.
var ErrNoServer = errors.New("no usable server")

const (
	// minGracePeriod is the floor of the grace period a still-pending dial gets
	// once another transport has connected.
	minGracePeriod = 300 * time.Millisecond
	// bannerReadMargin sits inside the banner timeout, so a peer that never
	// answers times out on the read instead of racing the deadline that ends it.
	bannerReadMargin = 20 * time.Millisecond
	// maxBannerLen: RFC 4253 section 4.2 caps the identification string at 255
	// characters, not counting the CRLF.
	maxBannerLen = 255
	// sniffTimeout bounds the plain-mode peek: ssh writes its banner the instant
	// it connects, so a silent local connection is not an SSH client.
	sniffTimeout = 100 * time.Millisecond
)

// errProbeDeadline marks a cancel that came from the probe deadline - the outer
// timeout or the grace period - rather than from the caller.
var errProbeDeadline = errors.New("probe deadline passed")

// sshCandidate is one attempt to reach the server.
type sshCandidate struct {
	kind    string // "ssh" or "tls"
	address string
	port    int
	conn    net.Conn
	reader  *bufio.Reader // the banner read-ahead, drained before the copy
	banner  string
	err     error
	// declared means the banner named a host; a matching declaration is proof on
	// its own, so the other port is no longer worth waiting for.
	declared bool
	// mismatch is set when a banner declares hosts and none is the name dialled.
	mismatch string
}

func (c *sshCandidate) usable() bool { return c.err == nil && c.mismatch == "" }

// ServeSSH runs one SSH-mode session over an already-connected local side: stdio,
// or a connection the caller accepted. stderr gets the verbose candidate lines;
// progress names the port that won; verbose names every candidate and why it lost.
// All three are the command's decision, not the tunnel's. When neither port is
// usable the failure comes back as an error wrapping ErrNoServer, for the
// command to write.
func (t *Tunnel) ServeSSH(ctx context.Context, local net.Conn, stderr io.Writer, progress, verbose bool) error {
	// Reading one client line is safe: the server waits for the client's banner
	// before sending anything else (RFC 4253 section 4.2).
	client := bufio.NewReaderSize(local, 32*1024)

	// A session canceled while the client is still silent must not hang: closing
	// the local side on ctx.Done is what makes the banner read return.
	stop := context.AfterFunc(ctx, func() { _ = local.Close() })
	defer stop()
	if !isPipe(local) {
		_ = local.SetReadDeadline(time.Now().Add(t.connectTimeout()))
	}

	clientBanner, err := readBanner(client)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("local: %w", err)
	}
	_ = local.SetReadDeadline(time.Time{})

	chosen, err := t.probeSSH(ctx, clientBanner, stderr, verbose, isPipe(local))
	if err != nil {
		_ = local.Close()
		return err
	}

	if progress {
		_, _ = fmt.Fprintf(stderr, "[connect] %s => %s\n", displayAddr(local.RemoteAddr()), chosen.address)
	}

	if chosen.banner != "" {
		_, _ = fmt.Fprintf(local, "%s\r\n", chosen.banner)
	}

	// The banner exchange read more than the banner line. Hand those bytes to the
	// other side, then copy the two conns with no buffer in the relay.
	if err := drainTo(local, chosen.reader); err != nil {
		_ = chosen.conn.Close()
		return fmt.Errorf("relay: %w", err)
	}
	if err := drainTo(chosen.conn, client); err != nil {
		_ = chosen.conn.Close()
		return fmt.Errorf("relay: %w", err)
	}

	if err := pipeContext(ctx, local, chosen.conn); err != nil {
		_, _ = fmt.Fprintf(stderr, "[copy error] %s\n", err)
	}
	return nil
}

// probeSSH dials the SSH port and the TLS port at once, exchanges banners with
// whichever answers, and returns the winner: the TLS connection if it speaks the
// ALPN we asked for, otherwise the plain SSH port.
func (t *Tunnel) probeSSH(ctx context.Context, clientBanner string, stderr io.Writer, verbose, sshClient bool) (*sshCandidate, error) {
	debugf := func(format string, args ...any) {
		if verbose {
			_, _ = fmt.Fprintf(stderr, format+"\n", args...)
		}
	}

	sshPort := t.SSHPort
	sshAddress := net.JoinHostPort(t.RemoteAddress, strconv.Itoa(sshPort))
	tlsAddress := net.JoinHostPort(t.RemoteAddress, strconv.Itoa(t.RemotePort))

	// One lookup: both ports are the same name, so a name that does not resolve
	// is one failure, not two.
	if _, err := net.LookupHost(t.RemoteAddress); err != nil {
		return nil, noServerClosed(t, err, sshClient)
	}

	// The probe bound is the connect timeout plus the longest handshake, or the
	// caller's deadline if sooner. Each dial keeps its own deadline; the grace
	// period only shortens this one.
	connect := t.connectTimeout()
	deadline := time.Now().Add(connect + t.handshakeDeadline(connect))
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	probeCtx, cancelProbe := context.WithCancelCause(ctx)
	defer cancelProbe(nil)
	timer := time.AfterFunc(time.Until(deadline), func() { cancelProbe(errProbeDeadline) })

	candidates := make(chan *sshCandidate, 2)
	connected := make(chan time.Duration, 2)

	// decided closes the moment a candidate is confirmed, so a handshake we no
	// longer need is cut short instead of running to its deadline.
	decided := make(chan struct{})
	var decideOnce sync.Once
	decide := func() { decideOnce.Do(func() { close(decided) }) }

	onConnected := func(elapsed time.Duration) { connected <- elapsed }

	go func() {
		candidates <- t.candidatePlain(probeCtx, sshAddress, sshPort, clientBanner, onConnected, debugf)
	}()
	if t.hasTLSRoute() {
		go func() {
			candidates <- t.candidateTLS(ctx, probeCtx, tlsAddress, t.RemotePort, clientBanner, onConnected, decided, debugf)
		}()
	} else {
		err := errors.New("skipped: an IP address has no name to route on, use --servername")
		candidates <- &sshCandidate{kind: "tls", address: tlsAddress, port: t.RemotePort, err: err}
		debugf("dial: tls %s: %v", tlsAddress, err)
	}

	var ready, failed []*sshCandidate
	var chosen *sshCandidate

	// settle records one finished candidate, and picks it if it is proof enough
	// to stop waiting: TLS wins outright, and a plain banner that declares the
	// name being dialled proves its own identity. An undeclared banner proves
	// nothing, so the TLS side keeps its chance.
	settled := 0
	settle := func(c *sshCandidate) {
		settled++
		if c.err != nil {
			failed = append(failed, c)
			debugf("dial: %s %s: %v", c.kind, c.address, c.err)
			return
		}
		ready = append(ready, c)
		if c.usable() && (c.kind == "tls" || c.declared) {
			chosen = c
			decide()
		}
	}

	shortened := false
	for settled < 2 && chosen == nil {
		select {
		// The grace period starts when a connection is established, not when a
		// candidate is confirmed, so a blackholed port cannot hold the probe to
		// the full timeout.
		case elapsed := <-connected:
			if !shortened {
				shortened = true
				until := time.Now().Add(gracePeriod(elapsed))
				if until.After(deadline) {
					until = deadline
				}
				timer.Reset(time.Until(until))
			}
		case c := <-candidates:
			settle(c)
		}
	}

	timer.Stop() // the probe deadline is done; the session is not probe-bounded

	// Collect whatever is still in flight so the report names every candidate.
	for settled < 2 {
		settle(<-candidates)
	}

	if chosen == nil {
		chosen = pickCandidate(ready)
	}
	if chosen == nil {
		return nil, noServer(t, ready, failed, sshClient)
	}

	debugf("chosen: %s %s", chosen.kind, chosen.address)
	for _, c := range ready {
		if c != chosen {
			_ = c.conn.Close()
		}
	}
	_ = chosen.conn.SetDeadline(time.Time{}) // sessions may sit idle
	return chosen, nil
}

// hasTLSRoute: an IP address carries no name, and a proxy that routes by name has
// nothing to route on, so an IP remote is probed over TLS only when it is named.
func (t *Tunnel) hasTLSRoute() bool {
	return net.ParseIP(t.RemoteAddress) == nil || t.ServerName != ""
}

// candidatePlain connects to the SSH port without TLS, then exchanges banners.
func (t *Tunnel) candidatePlain(ctx context.Context, address string, port int, clientBanner string, onConnected func(time.Duration), debugf func(string, ...any)) *sshCandidate {
	start := time.Now()
	c := &sshCandidate{kind: "ssh", address: address, port: port}

	connectCtx, cancelConnect := context.WithTimeout(ctx, t.connectTimeout())
	defer cancelConnect()
	conn, err := t.connect(connectCtx, address)
	if err != nil {
		c.err = dialError(err, time.Since(start), connectCtx)
		return c
	}
	if onConnected != nil {
		onConnected(time.Since(start))
	}

	c.conn = conn
	c.reader = bufio.NewReaderSize(conn, 32*1024)
	return exchangeBanner(c, t.serverName(), clientBanner, t.connectTimeout(), timeLeft(ctx), debugf)
}

// candidateTLS connects to the TLS port and checks the ALPN before the banner is
// sent: a server that will not name a protocol we asked for is not
// routing ssh for this name, so it never sees the banner.
func (t *Tunnel) candidateTLS(ctx context.Context, probeCtx context.Context, address string, port int, clientBanner string, onConnected func(time.Duration), decided chan struct{}, debugf func(string, ...any)) *sshCandidate {
	start := time.Now()
	c := &sshCandidate{kind: "tls", address: address, port: port}

	connectCtx, cancelConnect := context.WithTimeout(probeCtx, t.connectTimeout())
	defer cancelConnect()
	conn, err := t.connect(connectCtx, address)
	if err != nil {
		c.err = dialError(err, time.Since(start), connectCtx)
		return c
	}
	if onConnected != nil {
		onConnected(time.Since(start))
	}

	// The handshake is off the probe deadline: the grace period that closes a
	// blackholed port must not cut it short.
	handshake, cancelHandshake := context.WithTimeout(ctx, t.handshakeDeadline(time.Since(start)))
	defer cancelHandshake()
	go func() {
		select {
		case <-decided:
			cancelHandshake()
		case <-handshake.Done():
		}
	}()

	remote, err := t.handshake(handshake, conn, t.NextProtos)
	if err != nil {
		c.err = dialError(err, time.Since(start), handshake)
		return c
	}

	// The ALPN check: no banner for a server that is not routing ssh.
	negotiated := remote.ConnectionState().NegotiatedProtocol
	if len(t.NextProtos) > 0 && !slices.Contains(t.NextProtos, negotiated) {
		_ = remote.Close()
		name := "(none)"
		if negotiated != "" {
			name = strconv.Quote(negotiated)
		}
		c.err = fmt.Errorf("negotiated ALPN %s in %s, wanted one of [%s]",
			name, elapsedText(time.Since(start)), strings.Join(t.NextProtos, ", "))
		return c
	}

	c.conn = remote
	c.reader = bufio.NewReaderSize(remote, 32*1024)
	return exchangeBanner(c, t.serverName(), clientBanner, t.connectTimeout(), timeLeft(probeCtx), debugf)
}

// exchangeBanner writes the client banner, reads the reply, and applies the host
// check. A candidate that comes back with err set is not usable.
func exchangeBanner(c *sshCandidate, want, clientBanner string, connect, remaining time.Duration, debugf func(string, ...any)) *sshCandidate {
	timeout := bannerTimeout(connect, remaining)
	_ = c.conn.SetReadDeadline(time.Now().Add(timeout - bannerReadMargin))
	defer c.conn.SetReadDeadline(time.Time{})

	if err := writeBanner(c.conn, clientBanner); err != nil {
		c.err = fmt.Errorf("write banner: %w", err)
		_ = c.conn.Close()
		return c
	}

	banner, err := readBanner(c.reader)
	if err != nil {
		c.err = err
		_ = c.conn.Close()
		return c
	}

	c.banner = banner
	c.declared = len(declaredHosts(banner)) > 0
	debugf("banner: %s %s answered %q", c.kind, c.address, banner)

	if mismatch := bannerMismatch(want, banner); mismatch != "" {
		debugf("banner: %s %s: %s", c.kind, c.address, mismatch)
		c.mismatch = mismatch
		_ = c.conn.Close()
	}
	return c
}

func timeLeft(ctx context.Context) time.Duration {
	dl, ok := ctx.Deadline()
	if !ok {
		return minGracePeriod
	}
	return time.Until(dl)
}

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

// pickCandidate prefers the TLS connection, but only when it is usable: a
// candidate contradicted by its own banner is not a server, it is a different one.
func pickCandidate(ready []*sshCandidate) *sshCandidate {
	for _, c := range ready {
		if c.kind == "tls" && c.usable() {
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

// noServer is the failure of a session where every candidate lost. The header
// names the remote; each candidate that lost is indented under it. ssh's closing
// line is added only for a session piped to ssh - a forwarded port has no ssh
// listening for "Connection closed by UNKNOWN port 65535".
func noServer(t *Tunnel, ready, failed []*sshCandidate, sshClient bool) error {
	lines := make([]string, 0, len(ready)+len(failed))
	for _, c := range ready {
		lines = append(lines, fmt.Sprintf("  %s %d: %s", c.kind, c.port, c.mismatch))
	}
	for _, c := range failed {
		lines = append(lines, fmt.Sprintf("  %s %d: %v", c.kind, c.port, c.err))
	}

	report := fmt.Errorf("%s: %w\n%s", t.RemoteAddress, ErrNoServer, strings.Join(lines, "\n"))
	if !sshClient {
		return report
	}
	return fmt.Errorf("%w\n%s", report, closedLine(t.RemoteAddress, attemptedPorts(t)))
}

// noServerClosed is the failure before any dial: the name never resolved, so no
// port was tried.
func noServerClosed(t *Tunnel, err error, sshClient bool) error {
	reason := lookupReason(err)
	report := fmt.Errorf("%s: %w: %s", t.RemoteAddress, ErrNoServer, strings.ToLower(reason))
	if !sshClient {
		return report
	}
	return fmt.Errorf("%w\n%s", report, closedLine(reason, nil))
}

// closedLine is the line ssh would have printed for a ProxyCommand that died:
// Connection closed by "example.com" ports [22, 443]. It stands on its own, the
// way ssh prints it, so it carries no name and no indent.
func closedLine(reason string, ports []int) string {
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
	return fmt.Sprintf("Connection closed by %q %s [%s]", reason, word, strings.Join(parts, ", "))
}

func attemptedPorts(t *Tunnel) []int {
	ports := []int{t.SSHPort}
	if t.hasTLSRoute() {
		ports = append(ports, t.RemotePort)
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

// dialError: a dial cut by the probe deadline reads as a timeout, not a
// cancellation.
func dialError(err error, elapsed time.Duration, probeCtx context.Context) error {
	timeout := fmt.Errorf("timed out after %s", elapsedText(elapsed))
	switch probeCtx.Err() {
	case context.DeadlineExceeded:
		return timeout
	case context.Canceled:
		if errors.Is(context.Cause(probeCtx), errProbeDeadline) {
			return timeout
		}
		return fmt.Errorf("canceled after %s", elapsedText(elapsed))
	}
	return err
}

// elapsedText renders how long a dial took: 1.2s or 40ms.
func elapsedText(d time.Duration) string {
	if d >= time.Second {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	return fmt.Sprintf("%dms", d.Round(time.Millisecond)/time.Millisecond)
}

// sniffALPN offers "ssh" when the local side opens with an SSH banner and the
// operator named no protocol list. The peek does not consume the banner: the relay
// still sees it. Stdio has no read deadline, so it is not sniffed - an SSH client
// on stdio names its protocol with --ssh-port or --alpn.
func sniffALPN(ctx context.Context, nextProtos []string, client *bufio.Reader, conn net.Conn) []string {
	if nextProtos != nil || ctx.Err() != nil {
		return nextProtos
	}
	if isPipe(conn) {
		return nextProtos
	}

	window := sniffTimeout
	if dl, ok := ctx.Deadline(); ok && time.Until(dl) < window {
		window = time.Until(dl)
	}
	if window <= 0 {
		return nil
	}

	_ = conn.SetReadDeadline(time.Now().Add(window))
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

// readBanner reads one identification line, bounded so a peer that never sends a
// newline cannot buffer forever. Bytes past the terminator (a glued KEXINIT) stay
// in r for the caller to relay.
func readBanner(r *bufio.Reader) (string, error) {
	var banner strings.Builder
	for range maxBannerLen + 2 {
		b, err := r.ReadByte()
		if err != nil {
			return "", fmt.Errorf("read banner: %w", err)
		}
		if b == '\n' {
			line := strings.TrimRight(banner.String(), "\r")
			if len(line) > maxBannerLen {
				return "", fmt.Errorf("banner too long: %d bytes", len(line))
			}
			if !strings.HasPrefix(line, "SSH-") {
				return "", fmt.Errorf("not an SSH identification banner: %q", line)
			}
			return line, nil
		}
		_ = banner.WriteByte(b)
	}
	return "", fmt.Errorf("banner too long: more than %d bytes", maxBannerLen)
}

func writeBanner(w io.Writer, banner string) error {
	_, err := io.WriteString(w, banner+"\r\n")
	return err
}

// A server can name itself in the RFC 4253 section 4.2 comment, ex:
// "SSH-2.0-OpenSSH_9.6 tlsrouter-v0.9.4 host:example.com". These are the fields
// the probe reads.
var hostFields = []string{"hostname:", "host:"}

// declaredHosts returns the hosts a banner declares, or nil when it declares none.
// The comment is everything after the first space.
func declaredHosts(banner string) []string {
	_, comment, ok := strings.Cut(banner, " ")
	if !ok {
		return nil
	}

	var hosts []string
	for field := range strings.FieldsSeq(comment) {
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
// dialled; "" means it matches or makes no claim at all. Only a declared host list
// can refuse a candidate. An IP address is not contradicted by a name list: the
// server may name any of its own names and still be the machine we dialled. The
// banner is quoted in the line, so the reason names only the host it excludes.
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
	return fmt.Sprintf("banner %q excludes %q", banner, want)
}
