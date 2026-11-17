// demo serves an SSH-banner echo server over TLS and over plain TCP, for
// CLI smoke tests of SSH mode. It is not part of the shipped binary.
//
//	go build -o ./agents/tmp/ssh-demo ./tests/demo
//	./agents/tmp/ssh-demo -tls 4430 -plain 2200 -tls-host demo.local -plain-host demo.local
package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	tlsPort, plainPort := 4430, 2200
	tlsAlpn, tlsHost, plainHost := "ssh", "demo.local", "demo.local"
	var tlsDelay time.Duration
	flag.IntVar(&tlsPort, "tls", tlsPort, "TLS port (0 = no TLS server)")
	flag.IntVar(&plainPort, "plain", plainPort, "plain TCP port (0 = no plain server)")
	flag.StringVar(&tlsAlpn, "tls-alpn", tlsAlpn, "ALPN the TLS server offers ('' = none)")
	flag.StringVar(&tlsHost, "tls-host", tlsHost, "host the TLS banner declares ('' = none)")
	flag.StringVar(&plainHost, "plain-host", plainHost, "host the plain banner declares ('' = none)")
	flag.DurationVar(&tlsDelay, "tls-delay", 0, "hold the TLS handshake this long before answering")
	flag.Parse()

	if tlsPort > 0 {
		go serve(echo("SSH-2.0-DemoTLS_1.0", tlsHost), tlsPort, cert(), splitList(tlsAlpn), tlsDelay)
	}
	if plainPort > 0 {
		go serve(echo("SSH-2.0-DemoPlain_1.0", plainHost), plainPort, tls.Certificate{}, nil, 0)
	}

	_, _ = fmt.Fprintf(os.Stderr, "demo ready: tls %d (alpn %q, host %q) plain %d (host %q)\n",
		tlsPort, tlsAlpn, tlsHost, plainPort, plainHost)
	select {}
}

func echo(banner, host string) string {
	if host != "" {
		banner += " host:" + host
	}
	return banner
}

func splitList(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

// serve answers the banner exchange on a port. cert is empty for a plain port; a
// delay holds the TLS handshake long enough to show a probe giving up on it.
func serve(banner string, port int, cert tls.Certificate, alpn []string, delay time.Duration) {
	inner, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "listen %d: %v\n", port, err)
		os.Exit(1)
	}

	for {
		conn, err := inner.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			if cert.PrivateKey != nil {
				cfg := &tls.Config{Certificates: []tls.Certificate{cert}}
				if len(alpn) > 0 {
					cfg.NextProtos = alpn
				}
				if delay > 0 {
					time.Sleep(delay)
				}
				c = tls.Server(c, cfg)
			}
			r := bufio.NewReader(c)
			if _, err := readBanner(r); err != nil {
				return
			}
			if _, err := io.WriteString(c, banner+"\r\n"+"KEXINIT-glued-bytes\r\n"); err != nil {
				return
			}
			for {
				line, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if strings.TrimRight(line, "\r\n") == "BYE" {
					_, _ = io.WriteString(c, "GOODBYE\r\n")
					return
				}
				if _, err := io.WriteString(c, "echo: "+strings.TrimRight(line, "\r\n")+"\r\n"); err != nil {
					return
				}
			}
		}(conn)
	}
}

func readBanner(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func cert() tls.Certificate {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{{127, 0, 0, 1}},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, key.Public(), key)
	if err != nil {
		panic(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
