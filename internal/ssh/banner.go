package ssh

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
)

// maxBannerLen: RFC 4253 section 4.2 caps the identification string at 255
// characters, not counting the CRLF.
const maxBannerLen = 255

var errNotSSHBanner = errors.New("not an SSH identification banner")

// readBanner reads one identification line, bounded so a peer that never sends
// a newline cannot buffer forever. Bytes past the terminator (a glued KEXINIT)
// stay in r for the caller to relay.
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

// A server can name itself in the RFC 4253 section 4.2 comment, ex:
// "SSH-2.0-OpenSSH_9.6 tlsrouter-v0.9.4 host:example.com". These are the fields
// the probe reads.
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
// dialled; "" means it matches or makes no claim at all. Only a declared host
// list can refuse a candidate. An IP address is not contradicted by a name list:
// the server may name any of its own names and still be the machine we dialled.
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
