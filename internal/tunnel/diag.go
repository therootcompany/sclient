package tunnel

import (
	"fmt"
	"net"
	"time"
)

// DisplayAddr prints loopback as localhost.
func DisplayAddr(addr net.Addr) string {
	host, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return net.JoinHostPort("localhost", port)
	}
	return addr.String()
}

// ElapsedText renders how long a dial took: 1.2s or 40ms. Rounding to 10ms
// reported a fast connect as "0s", which says nothing.
func ElapsedText(d time.Duration) string {
	if d >= time.Second {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	return fmt.Sprintf("%dms", d.Round(time.Millisecond)/time.Millisecond)
}
