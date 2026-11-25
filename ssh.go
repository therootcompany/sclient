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
// host its version string declares (RFC 4253 section 4.2). A version string that
// declares nothing is accepted; the rule is opt-in per server.

// ErrNoServer marks an SSH-mode session where neither port was usable. The
// wrapped error carries the report; the command only has to print it.
var ErrNoServer = errors.New("no usable server")

const (
	// minGracePeriod is the floor of the grace period a still-pending dial gets
	// once another transport has connected.
	minGracePeriod = 300 * time.Millisecond
	// versionStringReadMargin sits inside the version-string timeout, so a peer that
	// never answers times out on the read instead of racing the deadline that ends it.
	versionStringReadMargin = 20 * time.Millisecond
	// maxVersionStringLength is RFC 4253 section 4.2's cap: 255 characters, the CR
	// and the LF included.
	maxVersionStringLength = 255
	// sniffTimeout bounds the plain-mode peek: ssh sends its version string the
	// instant it connects, so a silent local connection is not an SSH client.
	sniffTimeout = 100 * time.Millisecond
)

// errProbeDeadline marks a cancel that came from the probe deadline - the outer
// timeout or the grace period - rather than from the caller.
var errProbeDeadline = errors.New("probe deadline passed")

// sshCandidate is one attempt to reach the server.
type sshCandidate struct {
	kind          string // "ssh" or "tls"
	address       string
	port          int
	conn          net.Conn
	reader        *bufio.Reader // read-ahead, drained before the copy
	versionString string
	err           error
	// declared means the version string named a host; a matching declaration is proof
	// on its own, so the other port is no longer worth waiting for.
	declared bool
	// mismatch is set when a version string declares hosts and none is the name dialled.
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
	// Reading one client line is safe: the server waits for the client's version
	// string before sending anything else (RFC 4253 section 4.2).
	client := bufio.NewReaderSize(local, 32*1024)

	// A session canceled while the client is still silent must not hang: closing
	// the local side on ctx.Done is what makes the version-string read return.
	stop := context.AfterFunc(ctx, func() { _ = local.Close() })
	defer stop()
	if !isStdio(local) {
		_ = local.SetReadDeadline(time.Now().Add(t.connectTimeout()))
	}

	clientVersionString, err := readVersionString(client)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("local: %w", err)
	}
	_ = local.SetReadDeadline(time.Time{})

	chosen, err := t.probeSSH(ctx, clientVersionString, stderr, verbose, isStdio(local))
	if err != nil {
		_ = local.Close()
		return err
	}

	if progress {
		_, _ = fmt.Fprintf(stderr, "[connect] %s => %s\n", displayAddr(local.RemoteAddr()), chosen.address)
	}

	if chosen.versionString != "" {
		_, _ = fmt.Fprintf(local, "%s\r\n", chosen.versionString)
	}

	// The version exchange read more than the version string. Hand those bytes to
	// the other side, then copy the two conns with no buffer in the relay.
	if err := drainTo(local, chosen.reader); err != nil {
		_ = chosen.conn.Close()
		return fmt.Errorf("relay: %w", err)
	}
	if err := drainTo(chosen.conn, client); err != nil {
		_ = chosen.conn.Close()
		return fmt.Errorf("relay: %w", err)
	}

	if err := pipeContext(ctx, local, chosen.conn); err != nil && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("copy: %w", err)
	}
	return nil
}

// probeSSH dials the SSH port and the TLS port at once, exchanges version strings
// with whichever answers, and returns the winner: the TLS connection if it speaks
// the ALPN we asked for, otherwise the plain SSH port.
func (t *Tunnel) probeSSH(ctx context.Context, clientVersionString string, stderr io.Writer, verbose, pipedToSSH bool) (*sshCandidate, error) {
	say := func(format string, args ...any) {
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
		return nil, noServerClosed(t, err, pipedToSSH)
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
		candidates <- t.candidateSSH(probeCtx, sshAddress, sshPort, clientVersionString, onConnected, say)
	}()
	if t.hasTLSRoute() {
		go func() {
			candidates <- t.candidateTLS(ctx, probeCtx, tlsAddress, t.RemotePort, clientVersionString, onConnected, decided, say)
		}()
	} else {
		err := errors.New("skipped: an IP address has no name to route on, use --servername")
		candidates <- &sshCandidate{kind: "tls", address: tlsAddress, port: t.RemotePort, err: err}
		say("dial: tls %s: %v", tlsAddress, err)
	}

	var ready, failed []*sshCandidate
	var chosen *sshCandidate

	// finish records one candidate that has returned, and picks it if it is proof
	// enough to stop waiting: TLS wins outright, and a plain SSH version string that
	// declares the name being dialled proves its own identity. An undeclared version
	// string proves nothing, so the TLS side keeps its chance.
	finished := 0
	finish := func(c *sshCandidate) {
		finished++
		if c.err != nil {
			failed = append(failed, c)
			say("dial: %s %s: %v", c.kind, c.address, c.err)
			return
		}
		ready = append(ready, c)
		if c.usable() && (c.kind == "tls" || c.declared) {
			chosen = c
			decide()
		}
	}

	shortened := false
	for finished < 2 && chosen == nil {
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
			finish(c)
		}
	}

	timer.Stop() // the probe deadline is done; the session is not probe-bounded

	// Collect whatever is still in flight so the report names every candidate.
	for finished < 2 {
		finish(<-candidates)
	}

	if chosen == nil {
		chosen = pickCandidate(ready)
	}
	if chosen == nil {
		return nil, noServer(t, ready, failed, pipedToSSH)
	}

	say("chosen: %s %s", chosen.kind, chosen.address)
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

// candidateSSH connects to the plain SSH port, then exchanges version strings.
func (t *Tunnel) candidateSSH(ctx context.Context, address string, port int, clientVersionString string, onConnected func(time.Duration), say func(string, ...any)) *sshCandidate {
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
	return exchangeVersionStrings(c, t.serverName(), clientVersionString, t.connectTimeout(), timeLeft(ctx), say)
}

// candidateTLS connects to the TLS port and checks the ALPN before the version
// string is sent: a server that will not name a protocol we asked for is not
// routing ssh for this name, so it never sees the version string.
func (t *Tunnel) candidateTLS(sessionCtx context.Context, probeCtx context.Context, address string, port int, clientVersionString string, onConnected func(time.Duration), decided chan struct{}, say func(string, ...any)) *sshCandidate {
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
	handshake, cancelHandshake := context.WithTimeout(sessionCtx, t.handshakeDeadline(time.Since(start)))
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
	return exchangeVersionStrings(c, t.serverName(), clientVersionString, t.connectTimeout(), timeLeft(probeCtx), say)
}

// exchangeVersionStrings writes the client's version string, reads the reply, and
// applies the host check. A candidate that comes back with err set is not usable.
func exchangeVersionStrings(c *sshCandidate, want, clientVersionString string, connect, remaining time.Duration, say func(string, ...any)) *sshCandidate {
	timeout := versionStringTimeout(connect, remaining)
	_ = c.conn.SetReadDeadline(time.Now().Add(timeout - versionStringReadMargin))
	defer c.conn.SetReadDeadline(time.Time{})

	if err := writeVersionString(c.conn, clientVersionString); err != nil {
		c.err = fmt.Errorf("write version string: %w", err)
		_ = c.conn.Close()
		return c
	}

	line, err := readVersionString(c.reader)
	if err != nil {
		c.err = err
		_ = c.conn.Close()
		return c
	}

	c.versionString = line
	c.declared = len(declaredHosts(line)) > 0
	say("version string: %s %s answered %q", c.kind, c.address, line)

	if mismatch := versionStringMismatch(want, line); mismatch != "" {
		say("version string: %s %s: %s", c.kind, c.address, mismatch)
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

// versionStringTimeout is how long a connected candidate may take to answer the
// version exchange: a quarter of the connect timeout, floored at one grace period,
// never past the time left in the probe.
func versionStringTimeout(connect, remaining time.Duration) time.Duration {
	timeout := max(2*minGracePeriod, connect/4)
	if remaining < timeout {
		timeout = max(minGracePeriod, remaining)
	}
	return timeout
}

// pickCandidate prefers the TLS connection, when it is usable.
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
func noServer(t *Tunnel, ready, failed []*sshCandidate, pipedToSSH bool) error {
	lines := make([]string, 0, len(ready)+len(failed))
	for _, c := range ready {
		lines = append(lines, fmt.Sprintf("  %s %d: %s", c.kind, c.port, c.mismatch))
	}
	for _, c := range failed {
		lines = append(lines, fmt.Sprintf("  %s %d: %v", c.kind, c.port, c.err))
	}

	report := fmt.Errorf("%s: %w\n%s", t.RemoteAddress, ErrNoServer, strings.Join(lines, "\n"))
	if !pipedToSSH {
		return report
	}
	return fmt.Errorf("%w\n%s", report, closedLine(t.RemoteAddress, attemptedPorts(t)))
}

// noServerClosed is the failure before any dial: the name never resolved, so no
// port was tried.
func noServerClosed(t *Tunnel, err error, pipedToSSH bool) error {
	reason := lookupReason(err)
	report := fmt.Errorf("%s: %w: %s", t.RemoteAddress, ErrNoServer, strings.ToLower(reason))
	if !pipedToSSH {
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

// dialError: a dial cut by its deadline reads as a timeout, not a cancellation.
func dialError(err error, elapsed time.Duration, ctx context.Context) error {
	timeout := fmt.Errorf("timed out after %s", elapsedText(elapsed))
	switch ctx.Err() {
	case context.DeadlineExceeded:
		return timeout
	case context.Canceled:
		if errors.Is(context.Cause(ctx), errProbeDeadline) {
			return timeout
		}
		return fmt.Errorf("canceled after %s", elapsedText(elapsed))
	}
	return err
}

func elapsedText(d time.Duration) string {
	if d >= time.Second {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	return fmt.Sprintf("%dms", d.Round(time.Millisecond)/time.Millisecond)
}

// sniffALPN offers "ssh" when the local side opens with an SSH version string and
// the operator named no protocol list. The peek does not consume it: the relay
// still sees it. Stdio has no read deadline, so it is not sniffed - an SSH client
// on stdio names its protocol with --ssh-port or --alpn.
func sniffALPN(ctx context.Context, nextProtos []string, client *bufio.Reader, conn net.Conn) []string {
	if nextProtos != nil || ctx.Err() != nil {
		return nextProtos
	}
	if isStdio(conn) {
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

// readVersionString reads the first line that starts with "SSH-", skipping the
// pre-version lines RFC 4253 section 4.2 allows a server to send. It is bounded
// so a peer that never sends a newline cannot buffer forever. Bytes past the
// terminator (a glued KEXINIT) stay in r for the caller to relay.
func readVersionString(r *bufio.Reader) (string, error) {
	for {
		var line strings.Builder
		complete := false
		for range maxVersionStringLength {
			b, err := r.ReadByte()
			if err != nil {
				return "", fmt.Errorf("read version string: %w", err)
			}
			if b == '\n' {
				complete = true
				break
			}
			_ = line.WriteByte(b)
		}
		if !complete {
			return "", fmt.Errorf("version string too long: more than %d characters", maxVersionStringLength)
		}

		// The 255-character cap includes the CR and the LF.
		version := strings.TrimRight(line.String(), "\r")
		if !strings.HasPrefix(version, "SSH-") {
			continue
		}
		if len(version)+2 > maxVersionStringLength {
			return "", fmt.Errorf("version string too long: %d characters", len(version)+2)
		}
		return version, nil
	}
}

func writeVersionString(w io.Writer, version string) error {
	_, err := io.WriteString(w, version+"\r\n")
	return err
}

// A server can name itself in the RFC 4253 section 4.2 comment, ex:
// "SSH-2.0-OpenSSH_9.6 tlsrouter-v0.9.4 host:example.com". These are the fields
// the probe reads.
var hostFields = []string{"hostname:", "host:"}

// declaredHosts returns the hosts a version string declares, or nil when it
// declares none. The comment is everything after the first space.
func declaredHosts(version string) []string {
	_, comment, ok := strings.Cut(version, " ")
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

// versionStringMismatch explains why a version string names a server other than
// the one we dialled; "" means it matches or makes no claim at all. Only a declared
// host list can refuse a candidate. An IP address is not contradicted by a name
// list: the server may name any of its own names and still be the machine we
// dialled. The version string is quoted in the line, so the reason names only the
// host it excludes.
func versionStringMismatch(want, version string) string {
	declared := declaredHosts(version)
	if want == "" || len(declared) == 0 || net.ParseIP(want) != nil {
		return ""
	}
	for _, host := range declared {
		if strings.EqualFold(host, want) {
			return ""
		}
	}
	return fmt.Sprintf("version string %q excludes %q", version, want)
}
