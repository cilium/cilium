// SPDX-License-Identifier: Apache-2.0
// Copyright 2018 Authors of Cilium

//go:build darwin
// +build darwin

package mtu

import "net"

func autoDetect() (int, error) {
	return EthernetMTU, nil
}

func getMTUFromIf(net.IP) (int, error) {
	return EthernetMTU, nil
}
