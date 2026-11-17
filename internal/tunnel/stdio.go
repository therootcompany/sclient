package tunnel

import (
	"net"
	"os"
	"time"
)

// StdioConn makes stdin and stdout look like a net.Conn. local is "-" or "|";
// the name is only used for the diagnostic line.
func StdioConn(local string) *StdNet {
	name := "stdin"
	if local == "|" {
		name = "pipe"
	}
	return &StdNet{in: os.Stdin, out: os.Stdout, addr: &stdaddr{net.UnixAddr{Name: name, Net: "stdio"}}}
}

// StdNet is stdin plus stdout as one connection.
type StdNet struct {
	in   *os.File // os.Stdin
	out  *os.File // os.Stdout
	addr *stdaddr
}

func (rw *StdNet) Read(buf []byte) (n int, err error)  { return rw.in.Read(buf) }
func (rw *StdNet) Write(buf []byte) (n int, err error) { return rw.out.Write(buf) }
func (rw *StdNet) Close() error                        { return rw.in.Close() }
func (rw *StdNet) RemoteAddr() net.Addr                { return rw.addr }
func (rw *StdNet) LocalAddr() net.Addr                 { return rw.addr }

// SetDeadline does nothing: stdio cannot be timed. A pipe fed by an SSH client
// writes its banner at once, so the sniff never waits.
func (rw *StdNet) SetDeadline(_ time.Time) error { return nil }

// SetReadDeadline does nothing; see SetDeadline.
func (rw *StdNet) SetReadDeadline(_ time.Time) error { return nil }

// SetWriteDeadline does nothing; see SetDeadline.
func (rw *StdNet) SetWriteDeadline(_ time.Time) error { return nil }

type stdaddr struct {
	net.UnixAddr
}
