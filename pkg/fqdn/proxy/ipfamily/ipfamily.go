// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipfamily

type IPFamily struct {
	Name        string
	IPv4Enabled bool
	IPv6Enabled bool
	UDPAddress  string
	TCPAddress  string
	Localhost   string
}

func IPv4() IPFamily {
	return IPFamily{
		Name:        "ipv4",
		IPv4Enabled: true,
		IPv6Enabled: false,
		UDPAddress:  "udp4",
		TCPAddress:  "tcp4",
		Localhost:   "127.0.0.1",
	}
}

func IPv6() IPFamily {
	return IPFamily{
		Name:        "ipv6",
		IPv4Enabled: false,
		IPv6Enabled: true,
		UDPAddress:  "udp6",
		TCPAddress:  "tcp6",
		Localhost:   "::1",
	}
}
