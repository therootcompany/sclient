package main

import (
	"os"
	"slices"
	"testing"
)

func TestStderrTarget(t *testing.T) {
	path := t.TempDir() + "/ssh-tls-proxy.log"

	for _, want := range []string{"", "/dev/null", path} {
		if got := stderrTarget(want); got == nil {
			t.Errorf("stderrTarget(%q): nil", want)
		}
	}

	if _, err := os.ReadFile(path); err != nil {
		t.Errorf("log file was not created: %v", err)
	}

	if got := stderrTarget(path + "/missing.log"); got != os.Stderr {
		t.Errorf("stderrTarget of an unopenable path: got %q, want os.Stderr", got.Name())
	}
}

func TestMaybeSSHControlMasterNull(t *testing.T) {
	if maybeSSHControlMasterNull(os.Stdin, os.Stdout, os.Stderr) {
		t.Error("a unit test is not a ProxyCommand")
	}

	devnull, err := os.Open("/dev/null")
	if err != nil {
		t.Skip("/dev/null: ", err) // Windows: the probe answers false
	}
	defer devnull.Close()

	read, write, err := os.Pipe()
	if err != nil {
		t.Skip("pipe: ", err)
	}
	defer read.Close()
	defer write.Close()

	if !maybeSSHControlMasterNull(write, write, devnull) {
		t.Error("fd 0 and fd 1 on pipes with /dev/null on fd 2 is a ProxyCommand")
	}
}

// <host>[:tls-port] - without a port the caller keeps the TLS default.
func TestHostAndPort(t *testing.T) {
	cases := []struct {
		in   string
		host string
		port int
		err  bool
	}{
		{"example.com", "example.com", 0, false},
		{"example.com:8443", "example.com", 8443, false},
		{"[::1]", "::1", 0, false},
		{"example.com:99999", "", 0, true},
		{"", "", 0, true},
	}
	for _, c := range cases {
		host, port, err := hostAndPort(c.in)
		if c.err {
			if err == nil {
				t.Errorf("hostAndPort(%q): got %q:%d, want an error", c.in, host, port)
			}
			continue
		}
		if err != nil {
			t.Errorf("hostAndPort(%q): %v", c.in, err)
			continue
		}
		if host != c.host || port != c.port {
			t.Errorf("hostAndPort(%q) = %q:%d, want %q:%d", c.in, host, port, c.host, c.port)
		}
	}
}

// --listen needs a port; a bare name is not a listener.
func TestListenAddr(t *testing.T) {
	host, port, err := listenAddr("localhost:2222")
	if err != nil || host != "localhost" || port != 2222 {
		t.Errorf("listenAddr(\"localhost:2222\") = %q:%d, %v", host, port, err)
	}
	if _, _, err := listenAddr("localhost"); err == nil {
		t.Error("listenAddr(\"localhost\"): want an error, a listener needs a port")
	}
}

// The default is the gate; an explicit empty list turns it off.
func TestAlpnList(t *testing.T) {
	if got := alpnList(""); !slices.Equal(got, []string{}) {
		t.Errorf("alpnList(\"\") = %q, want an empty list", got)
	}
	if got := alpnList("h2, ssh"); !slices.Equal(got, []string{"h2", "ssh"}) {
		t.Errorf("alpnList(\"h2, ssh\") = %q", got)
	}
}
