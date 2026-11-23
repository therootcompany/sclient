// ssh-tls-proxy is the SSH-specific tool: it puts an SSH client onto a server
// that speaks SSH through TLS, probing the plain SSH port and the TLS port at the
// same time and relaying the client onto whichever answers.
//
//	go get github.com/therootcompany/sclient/cmd/ssh-tls-proxy
//	ssh -o ProxyCommand='ssh-tls-proxy --ssh-port %p %h:443' example.com
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
	"syscall"

	"github.com/therootcompany/sclient"
)

const (
	name           = "ssh-tls-proxy"
	defaultSSHPort = 22
	defaultTLSPort = 443
)

// MainConfig is the command: the flags the operator gave, and the writer the
// command speaks through. The tunnel holds only connection state.
type MainConfig struct {
	servername string
	listen     string
	stderrPath string
	alpn       string
	sshPort    int
	tlsPort    int
	tcpTimeout float64
	tlsTimeout float64
	insecure   bool
	silent     bool
	verbose    bool
	stderr     io.Writer
}

func usage(fs *flag.FlagSet) {
	w := fs.Output()
	printVersion(w)
	_, _ = fmt.Fprintf(w, "\nUSAGE: %s [flags] <host>[:tls-port]\n", name)
	_, _ = fmt.Fprintf(w, "\n   ex: ssh -o ProxyCommand='%s --ssh-port %%p %%h:443' example.com\n", name)
	_, _ = fmt.Fprintf(w, "      (stdio: the SSH client is stdin and stdout)\n")
	_, _ = fmt.Fprintf(w, "\n   ex: %s --listen localhost:2222 example.com:443\n", name)
	_, _ = fmt.Fprintf(w, "      (stunnel-style: SSH clients connect to a local port)\n")
	_, _ = fmt.Fprintf(w, "\nFLAGS\n")
	fs.PrintDefaults()
	_, _ = fmt.Fprintln(w)
}

func main() {
	cfg := MainConfig{}

	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.IntVar(&cfg.sshPort, "ssh-port", defaultSSHPort, "plain SSH port to probe alongside the TLS port")
	fs.IntVar(&cfg.tlsPort, "tls-port", defaultTLSPort, "TLS port the SSH server is wrapped in")
	fs.StringVar(&cfg.alpn, "alpn", "ssh", "protocols the TLS connection must negotiate; '' turns the check off")
	fs.StringVar(&cfg.servername, "servername", "", "SNI name, and the host the banner must declare (default: <host>)")
	fs.StringVar(&cfg.listen, "listen", "", "bind a local port instead of relaying stdin/stdout, ex localhost:2222")
	fs.StringVar(&cfg.stderrPath, "stderr", "", "where diagnostics go, ex ssh-tls-proxy.log or /dev/null")
	fs.Float64Var(&cfg.tcpTimeout, "tcp-timeout", 0, "seconds for the TCP connect, DNS included (0 = default, 5s)")
	fs.Float64Var(&cfg.tlsTimeout, "tls-timeout", 0, "seconds for the TLS handshake (0 = auto, 3x the connect)")
	fs.BoolVar(&cfg.insecure, "k", false, "alias for --insecure")
	fs.BoolVar(&cfg.insecure, "insecure", false, "ignore bad TLS (SSL/HTTPS) certificates")
	fs.BoolVar(&cfg.silent, "s", false, "alias of --silent")
	fs.BoolVar(&cfg.silent, "silent", false, "less verbose output")
	fs.BoolVar(&cfg.verbose, "v", false, "alias of --verbose")
	fs.BoolVar(&cfg.verbose, "verbose", false, "name every candidate, its banner, and why it lost")
	_ = fs.Bool("V", false, "print the version and exit")
	_ = fs.Bool("version", false, "alias of -V")
	fs.Usage = func() { usage(fs) }

	// Before parsing: -V and help survive junk arguments.
	preParse(fs, os.Args[1:])

	if err := fs.Parse(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		os.Exit(2) // flag printed the error and the usage
	}

	// stdout is the payload; --stderr says where the rest goes.
	os.Stderr = stderrTarget(cfg.stderrPath)
	cfg.stderr = os.Stderr

	args := fs.Args()
	if len(args) != 1 {
		failUsage(fs, "want <host>[:tls-port]")
	}

	host, tlsPort, err := hostAndPort(args[0])
	if err != nil {
		failUsage(fs, "host: "+err.Error())
	}
	if tlsPort != 0 {
		cfg.tlsPort = tlsPort // a port on the address names the TLS side
	}
	if err := portOf("ssh-port", cfg.sshPort); err != nil {
		failUsage(fs, err.Error())
	}
	if err := portOf("tls-port", cfg.tlsPort); err != nil {
		failUsage(fs, err.Error())
	}

	tun := &sclient.Tunnel{
		RemoteAddress:      host,
		RemotePort:         cfg.tlsPort,
		SSHPort:            cfg.sshPort,
		ServerName:         cfg.servername,
		NextProtos:         alpnList(cfg.alpn),
		TCPTimeout:         toSeconds(cfg.tcpTimeout),
		TLSTimeout:         toSeconds(cfg.tlsTimeout),
		InsecureSkipVerify: cfg.insecure,
	}

	if cfg.listen == "" {
		// The SSH client is stdin and stdout.
		tun.LocalAddress = "-"
		tun.LocalPort = -1
	} else {
		localHost, localPort, err := listenAddr(cfg.listen)
		if err != nil {
			failUsage(fs, "--listen: "+err.Error())
		}
		tun.LocalAddress = localHost
		tun.LocalPort = localPort
	}

	// SIGINT or SIGTERM cancels ctx, which ends the session.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := cfg.run(ctx, tun); err != nil {
		_, _ = fmt.Fprint(cfg.stderr, report(err))
		os.Exit(1)
	}
}

// report speaks for this command: the name goes in front of the header line, and
// the detail inside the error is already indented under it.
func report(err error) string {
	return fmt.Sprintf("%s: %s\n", name, err)
}

// run owns the lifecycle: bind, accept, serve one SSH session per connection.
// With no --listen there is nothing to bind - the SSH client is stdio. What the
// command says is the command's business: stdio speaks only when asked, a bound
// port reports every connection unless --silent is set.
func (c MainConfig) run(ctx context.Context, tun *sclient.Tunnel) error {
	if tun.LocalAddress == "-" || tun.LocalAddress == "|" {
		return tun.ServeSSH(ctx, sclient.StdioConn(tun.LocalAddress), c.stderr, c.verbose, c.verbose)
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
		_, _ = fmt.Fprintf(c.stderr, "[listening] %s (ssh) <= %s\n", tun.Remote(), tun.Local())
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
	// A session on a bound port may say which candidate won; --silent quiets it.
	err := tun.ServeSSH(ctx, local, c.stderr, !c.silent, c.verbose)
	if err != nil {
		if errors.Is(err, sclient.ErrNoServer) {
			_, _ = fmt.Fprint(c.stderr, report(err))
			return
		}
		_, _ = fmt.Fprintf(c.stderr, "[error] %s: %s\n", displayAddr(local.RemoteAddr()), err)
	}
}

// displayAddr prints loopback as localhost.
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
