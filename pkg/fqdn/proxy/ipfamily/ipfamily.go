// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipfamily

type IPFamily struct {
	Name       string
	UDPAddress string
	TCPAddress string
	Localhost  string
}

func IPv4() IPFamily {
	return IPFamily{
		Name:       "ipv4",
		UDPAddress: "udp4",
		TCPAddress: "tcp4",
		Localhost:  "127.0.0.1",
	}
}

func IPv6() IPFamily {
	return IPFamily{
		Name:       "ipv6",
		UDPAddress: "udp6",
		TCPAddress: "tcp6",
		Localhost:  "::1",
	}
}
