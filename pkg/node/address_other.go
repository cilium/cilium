// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package node

import (
	"net"
)

func firstGlobalAddr(intf string, preferredIP net.IP, family int) (net.IP, error) {
	return net.IP{}, nil
}

func FirstGlobalV4Addr(intf string, preferredIP net.IP) (net.IP, error) {
	return net.IP{}, nil
}

func FirstGlobalV6Addr(intf string, preferredIP net.IP) (net.IP, error) {
	return net.IP{}, nil
}
