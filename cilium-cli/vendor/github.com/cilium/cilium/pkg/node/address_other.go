// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package node

import "net"

func firstGlobalAddr(intf string, preferredIP net.IP, family int, preferPublic bool) (net.IP, error) {
	return net.IP{}, nil
}

func firstGlobalV4Addr(intf string, preferredIP net.IP, preferPublic bool) (net.IP, error) {
	return net.IP{}, nil
}

func firstGlobalV6Addr(intf string, preferredIP net.IP, preferPublic bool) (net.IP, error) {
	return net.IP{}, nil
}

func initMasqueradeV4Addrs(masqAddrs map[string]net.IP, masqIPFromDevice string, devices []string, logfield string) error {
	return nil
}

func initMasqueradeV6Addrs(masqAddrs map[string]net.IP, masqIPFromDevice string, devices []string, logfield string) error {
	return nil
}

// getCiliumHostIPsFromNetDev returns the first IPv4 link local and returns
// it
func getCiliumHostIPsFromNetDev(devName string) (ipv4GW, ipv6Router net.IP) {
	return net.IP{}, net.IP{}
}
