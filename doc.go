/*
Package sclient unwraps SSL.

It makes secure remote connections (such as HTTPS) available locally as plain-text connections -
similar to `stunnel` or `openssl s_client`.

There are a variety of reasons that you might want to do that,
but we created it specifically to be able to upgrade applications with legacy
security protocols - like SSH, OpenVPN, and Postgres - to be able to take
advantage of the features modern TLS, such as ALPN and SNI
(which makes them routable through almost every type of firewall).

See https://telebit.cloud/sclient for more info.

Try the CLI

	go get git.rootprojects.org/root/sclient.go/cmd/sclient
	go run git.rootprojects.org/root/sclient.go/cmd/sclient example.com:443 localhost:3000

Package Basics

	servername := "example.com"

	sclient := &sclient.Tunnel{
		ServerName:         servername,
		RemoteAddress:      servername,
		RemotePort:         443,
		LocalAddress:       "localhost",
		LocalPort:          3000,
	}

	err := sclient.DialAndListen()

Pre-built versions for various platforms are also available at
https://telebit.cloud/sclient

*/
package sclient
