package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/therootcompany/sclient"
)

const (
	name         = "sclient"
	licenseYear  = 2018
	licenseOwner = "AJ ONeal"
	licenseType  = "MIT or Apache-2.0"
)

const (
	defaultRemotePort = 443
	defaultLocalHost  = "localhost"
	defaultSSHPort    = 22
)

// GoReleaser sets these at release time with -X main.version, -X main.commit,
// and -X main.date; init() fills in what is left unset for go run and go build.
var (
	version = ""
	commit  = ""
	date    = ""
)

// buildTimeLayout is how the build date is printed: date, time, and the
// offset the build carried - no T, and no invented zone.
const buildTimeLayout = "2006-01-02 15:04:05-07:00"

// displayBuildDate turns the build date (RFC3339, as goreleaser, git, and
// debug.ReadBuildInfo write it) into the display form. A date with no time is
// left alone rather than padded out with a zone the build never had.
func displayBuildDate(raw string) string {
	when, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return raw
	}
	return when.Format(buildTimeLayout)
}

// parseBuildDate reads either form: the build date or the display form.
func parseBuildDate(raw string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339, buildTimeLayout, time.DateOnly} {
		if when, err := time.Parse(layout, raw); err == nil {
			return when, nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognized build date %q", raw)
}

// MainConfig is the command: the flags the operator gave, and the writer the
// command speaks through. The tunnel holds only connection state.
type MainConfig struct {
	alpn       string
	insecure   bool
	servername string
	silent     bool
	verbose    bool
	ssh        bool
	sshPort    int
	stderrPath string
	tcpTimeout float64
	tlsTimeout float64
	remote     string
	local      string
	stderr     io.Writer
}

func shortCommit(c string) string {
	return c[:min(len(c), 7)]
}

// copyrightYears prints a date like 2018-2026 or 2018-present, depending on available build info.
func copyrightYears(buildDate string) string {
	first := strconv.Itoa(licenseYear)

	build, err := parseBuildDate(buildDate)
	if err != nil || build.Year() < 1000 {
		return first + "-present"
	}
	return first + "-" + strconv.Itoa(build.Year())
}

func printVersion(w io.Writer) {
	_, _ = fmt.Fprintf(w, "%s v%s %s (%s)\n", name, version, commit, date)
	_, _ = fmt.Fprintf(w, "Copyright (C) %s %s\n", copyrightYears(date), licenseOwner)
	_, _ = fmt.Fprintf(w, "Licensed under %s\n", licenseType)
}

// buildSetting returns one VCS setting, or "" when the binary has none.
func buildSetting(settings []debug.BuildSetting, key string) string {
	for _, setting := range settings {
		if setting.Key == key {
			return setting.Value
		}
	}
	return ""
}

func init() {
	// ldflags win; ReadBuildInfo is the fallback for go run and plain go build.
	if version == "" || commit == "" || date == "" {
		if bi, ok := debug.ReadBuildInfo(); ok {
			if version == "" && bi.Main.Version != "devel" {
				version = bi.Main.Version
			}
			if commit == "" {
				commit = buildSetting(bi.Settings, "vcs.revision")
			}
			if date == "" {
				date = buildSetting(bi.Settings, "vcs.time")
			}
		}
	}

	version = strings.TrimPrefix(version, "v")
	if version == "" {
		version = "dev"
	}
	if commit == "" {
		commit = "0000000"
	}
	if date == "" {
		date = "0001-01-01"
	}
	commit = shortCommit(commit)
	date = displayBuildDate(date)
}

func usage(fs *flag.FlagSet) {
	w := fs.Output()
	printVersion(w)
	_, _ = fmt.Fprintf(w, "\nUSAGE: %s [flags] <remote> <local>\n", name)
	_, _ = fmt.Fprintf(w, "\n   ex: %s example.com 3000\n", name)
	_, _ = fmt.Fprintf(w, "      (example.com:443 <= localhost:3000)\n")
	_, _ = fmt.Fprintf(w, "\n   ex: %s example.com:8443 0.0.0.0:4080\n", name)
	_, _ = fmt.Fprintf(w, "\n   ex: %s example.com:443 -\n", name)
	_, _ = fmt.Fprintf(w, "\n   ex: %s --ssh-port 22 example.com:443 localhost:3000\n", name)
	_, _ = fmt.Fprintf(w, "      (SSH mode: the plain SSH port and the TLS port are probed at once)\n")
	_, _ = fmt.Fprintf(w, "\n   ex: ssh -o ProxyCommand='%s --ssh-port %%p %%h:443' example.com\n", name)
	_, _ = fmt.Fprintf(w, "\nFLAGS\n")
	fs.PrintDefaults()
	_, _ = fmt.Fprintln(w)
}

// failUsage reports a usage error and exits 2.
func failUsage(fs *flag.FlagSet, msg string) {
	_, _ = fmt.Fprintf(os.Stderr, "%s: %s\n", name, msg)
	fs.Usage()
	os.Exit(2)
}

func main() {
	cfg := MainConfig{}

	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.StringVar(&cfg.alpn, "alpn", "", "acceptable protocols, ex: 'h2,http/1.1' 'http/1.1' 'ssh'")
	fs.BoolVar(&cfg.insecure, "k", false, "alias for --insecure")
	fs.BoolVar(&cfg.silent, "s", false, "alias of --silent")
	fs.BoolVar(&cfg.verbose, "v", false, "alias of --verbose")
	fs.BoolVar(&cfg.verbose, "verbose", false, "name every probe candidate, its banner, and why it lost (SSH mode)")
	fs.BoolVar(&cfg.ssh, "ssh", false, "SSH mode shorthand for --ssh-port 22")
	fs.IntVar(&cfg.sshPort, "ssh-port", 0, "plain SSH port to probe alongside <remote>; turns on SSH mode (0 = plain TLS tunnel)")
	fs.StringVar(&cfg.servername, "servername", "", "specify a servername different from <remote> (to disable SNI use an IP as <remote> and do not use this option)")
	fs.BoolVar(&cfg.insecure, "insecure", false, "ignore bad TLS (SSL/HTTPS) certificates")
	fs.BoolVar(&cfg.silent, "silent", false, "less verbose output")
	fs.StringVar(&cfg.stderrPath, "stderr", "", "where diagnostics go, ex sclient.log or /dev/null")
	fs.Float64Var(&cfg.tcpTimeout, "tcp-timeout", 0, "seconds for the TCP connect, DNS included (0 = default, 5s)")
	fs.Float64Var(&cfg.tlsTimeout, "tls-timeout", 0, "seconds for the TLS handshake (0 = auto, 3x the connect)")
	_ = fs.Bool("V", false, "print the version and exit")
	_ = fs.Bool("version", false, "alias of -V")
	fs.Usage = func() { usage(fs) }

	// Before parsing: -V and help survive junk arguments.
	for _, arg := range os.Args[1:] {
		switch arg {
		case "-V", "-version", "--version", "version":
			printVersion(os.Stdout)
			os.Exit(0)
		case "help", "-help", "--help":
			fs.SetOutput(os.Stdout)
			fs.Usage()
			os.Exit(0)
		}
	}

	if err := fs.Parse(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		os.Exit(2) // flag printed the error and the usage
	}

	// stdout is the payload; --stderr says where the rest goes.
	os.Stderr = stderrTarget(cfg.stderrPath)
	cfg.stderr = os.Stderr

	// Visit sees only the flags the operator gave, so it runs after Parse.
	named := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { named[f.Name] = true })

	sshPort, err := sshMode(cfg.ssh, cfg.sshPort, named["ssh-port"])
	if err != nil {
		failUsage(fs, err.Error())
	}

	switch args := fs.Args(); len(args) {
	case 2:
		cfg.remote = args[0]
		cfg.local = args[1]
	case 1:
		// We may omit the second argument if we're going straight to stdin
		if stat, _ := os.Stdin.Stat(); stat.Mode()&os.ModeCharDevice == 0 {
			cfg.remote = args[0]
			cfg.local = "|"
		} else {
			failUsage(fs, "want <remote> <local>")
		}
	default:
		failUsage(fs, "want <remote> <local>")
	}

	tun := &sclient.Tunnel{
		InsecureSkipVerify: cfg.insecure,
		ServerName:         cfg.servername,
		NextProtos:         alpnList(cfg.alpn, named["alpn"], sshPort > 0),
		TCPTimeout:         toSeconds(cfg.tcpTimeout),
		TLSTimeout:         toSeconds(cfg.tlsTimeout),
		SSHPort:            sshPort,
	}

	remoteHost, remotePort, err := remoteAddr(cfg.remote)
	if err != nil {
		failUsage(fs, "remote: "+err.Error())
	}
	tun.RemoteAddress = remoteHost
	tun.RemotePort = remotePort

	if cfg.local == "-" || cfg.local == "|" {
		// User may specify stdin/stdout instead of net
		tun.LocalAddress = cfg.local
		tun.LocalPort = -1
	} else {
		localHost, localPort, err := localAddr(cfg.local)
		if err != nil {
			failUsage(fs, "local: "+err.Error())
		}
		tun.LocalAddress = localHost
		tun.LocalPort = localPort
	}

	// SIGINT or SIGTERM cancels ctx, which stops the tunnel.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := cfg.run(ctx, tun); err != nil {
		// SSH mode already named every candidate that lost.
		if !errors.Is(err, sclient.ErrNoServer) {
			_, _ = fmt.Fprintf(cfg.stderr, "%s\n", err)
		}
		os.Exit(1)
	}
}

// sshMode resolves --ssh against --ssh-port. Naming the port is the mode; --ssh
// is the shorthand for 22, and an explicit port always wins. A named zero is a
// mistake, not "off".
func sshMode(ssh bool, sshPort int, named bool) (int, error) {
	if sshPort < 0 || sshPort > 65535 {
		return 0, errors.New("--ssh-port must be 1-65535")
	}
	if sshPort > 0 {
		return sshPort, nil
	}
	if named {
		return 0, errors.New("--ssh-port must be 1-65535 (omit it for a plain TLS tunnel)")
	}
	if ssh {
		return defaultSSHPort, nil
	}
	return 0, nil
}

// alpnList is --alpn as offered. In SSH mode an unset list takes "ssh"; an
// explicit empty one offers nothing, which turns the ALPN check off. In plain mode
// an unset list is left unset so the tunnel can sniff the local side.
func alpnList(raw string, explicit bool, sshMode bool) []string {
	if list := parseOptionList(raw); list != nil {
		return list
	}
	if explicit {
		return []string{}
	}
	if sshMode {
		return []string{"ssh"}
	}
	return nil
}

// sshProgress is whether an SSH-mode session may say which port won. A pipe's
// stderr is ssh's own terminal, so a piped session speaks only when asked.
func sshProgress(c MainConfig, tun *sclient.Tunnel) bool {
	if c.silent {
		return false
	}
	if tun.LocalAddress == "-" || tun.LocalAddress == "|" {
		return c.verbose
	}
	return true
}

// run drives one tunnel: stdio for a pipe, a listener for a forwarded port. SSH
// mode replaces the pre-flight probe with the two-port probe and the session with
// the banner exchange. What the command says is the command's business.
func (c MainConfig) run(ctx context.Context, tun *sclient.Tunnel) error {
	// stdio is one session, one dial: nothing to bind, nothing to probe.
	if tun.LocalAddress == "-" || tun.LocalAddress == "|" {
		local := sclient.StdioConn(tun.LocalAddress)
		if tun.SSHPort > 0 {
			return tun.ServeSSH(ctx, local, c.stderr, c.verbose && !c.silent, c.verbose)
		}
		if !c.silent {
			_, _ = fmt.Fprintf(c.stderr, "(connected to %s and reading from %s)\n",
				tun.Remote(), local.RemoteAddr())
		}
		if err := tun.Serve(ctx, local); err != nil {
			return fmt.Errorf("session: %w", err)
		}
		return nil
	}

	// The probe is the operator's early warning; each local connection dials on
	// its own. SSH mode probes per session instead.
	if tun.SSHPort == 0 {
		if err := tun.Probe(ctx); err != nil {
			_, _ = fmt.Fprintf(c.stderr, "[warn] '%s' may not be accepting connections: %s\n",
				tun.Remote(), err)
		}
	}

	ln, err := tun.Listen()
	if err != nil {
		return fmt.Errorf("local listener: %w", err)
	}
	defer func() { _ = ln.Close() }()

	// Closing the listener is the shutdown: it is what makes Accept return.
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	if !c.silent {
		_, _ = fmt.Fprintf(c.stderr, "[listening] %s <= %s\n", tun.Remote(), tun.Local())
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("local listener: %w", err)
		}
		go c.serve(ctx, tun, conn)
	}
}

// serve runs one session. A failed session is reported; the listener keeps going.
func (c MainConfig) serve(ctx context.Context, tun *sclient.Tunnel, local net.Conn) {
	if tun.SSHPort > 0 {
		// ServeSSH names the port that won and reports every candidate that lost;
		// a second "no usable server" line says nothing new.
		if err := tun.ServeSSH(ctx, local, c.stderr, c.verbose && !c.silent, c.verbose); err != nil && !errors.Is(err, sclient.ErrNoServer) {
			_, _ = fmt.Fprintf(c.stderr, "[error] %s: %s\n", displayAddr(local.RemoteAddr()), err)
		}
		return
	}

	if !c.silent {
		_, _ = fmt.Fprintf(c.stderr, "[connect] %s => %s\n", displayAddr(local.RemoteAddr()), tun.Remote())
	}

	err := tun.Serve(ctx, local)
	if err != nil && !errors.Is(err, context.Canceled) {
		_, _ = fmt.Fprintf(c.stderr, "[error] %s: %s\n", displayAddr(local.RemoteAddr()), err)
	}
}

func displayAddr(addr net.Addr) string {
	host, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return net.JoinHostPort("localhost", port)
	}
	return addr.String()
}

// remoteAddr parses <host> or <host>:<port>; a bare host gets port 443.
func remoteAddr(s string) (string, int, error) {
	host, rawPort, hasPort, err := splitHostPort(s)
	if err != nil {
		return "", 0, err
	}
	if !hasPort {
		return host, defaultRemotePort, nil
	}
	port, err := parsePort(rawPort)
	if err != nil {
		return "", 0, fmt.Errorf("remote %q: %w", s, err)
	}
	return host, port, nil
}

// localAddr parses <port> or <host>:<port>; a bare port listens on localhost.
func localAddr(s string) (string, int, error) {
	host, rawPort, hasPort, err := splitHostPort(s)
	if err != nil {
		return "", 0, err
	}
	if !hasPort {
		port, err := parsePort(s)
		if err != nil {
			return "", 0, fmt.Errorf("local %q: want <port> or <host>:<port>", s)
		}
		return defaultLocalHost, port, nil
	}
	port, err := parsePort(rawPort)
	if err != nil {
		return "", 0, fmt.Errorf("local %q: %w", s, err)
	}
	return host, port, nil
}

// splitHostPort splits an address, reporting whether it had a port.
// "::1:443" is itself a valid IPv6 address, so an unbracketed one is refused.
func splitHostPort(s string) (string, string, bool, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", "", false, errors.New("empty address")
	}

	host, port, err := net.SplitHostPort(s)
	if err == nil {
		return host, port, true, nil
	}
	if !strings.Contains(s, ":") {
		return s, "", false, nil
	}
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		return s[1 : len(s)-1], "", false, nil
	}
	return "", "", false, fmt.Errorf("%q: want <host>:<port>, or an IPv6 address in brackets", s)
}

// parsePort accepts a decimal port in 1..65535.
func parsePort(raw string) (int, error) {
	port, err := strconv.Atoi(raw)
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("%q is not a port (1-65535)", raw)
	}
	return port, nil
}

func toSeconds(raw float64) time.Duration {
	if raw <= 0 {
		return 0
	}
	return time.Duration(raw * float64(time.Second))
}

// parsers "a,b,c" "a b c" and "a, b, c" all the same
func parseOptionList(optionList string) []string {
	optionList = strings.TrimSpace(optionList)

	if len(optionList) == 0 {
		return nil
	}

	optionList = strings.ReplaceAll(optionList, ",", " ")
	options := strings.Fields(optionList)

	return options
}
