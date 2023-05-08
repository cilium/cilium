// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dnsproxy

type ipFamily struct {
	Name        string
	IPv4Enabled bool
	IPv6Enabled bool
	UDPAddress  string
	TCPAddress  string
	Localhost   string
}

func ipv4Family() ipFamily {
	return ipFamily{
		Name:        "ipv4",
		IPv4Enabled: true,
		IPv6Enabled: false,
		UDPAddress:  "udp4",
		TCPAddress:  "tcp4",
		Localhost:   "127.0.0.1",
	}
}

func ipv6Family() ipFamily {
	return ipFamily{
		Name:        "ipv6",
		IPv4Enabled: false,
		IPv6Enabled: true,
		UDPAddress:  "udp6",
		TCPAddress:  "tcp6",
		Localhost:   "::1",
	}
}
