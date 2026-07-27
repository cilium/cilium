// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dnsproxy

import (
	"net"

	"github.com/cilium/dns"
)

type noopSessionUDPFactory struct{}

var _ dns.SessionUDPFactory = &noopSessionUDPFactory{}

func (*noopSessionUDPFactory) InitPool(msgSize int) {}

func (*noopSessionUDPFactory) ReadRequest(conn *net.UDPConn) ([]byte, dns.SessionUDP, error) {
	return nil, nil, nil
}

func (*noopSessionUDPFactory) ReadRequestConn(conn net.PacketConn) ([]byte, net.Addr, error) {
	return nil, nil, nil
}

func (*noopSessionUDPFactory) SetSocketOptions(conn *net.UDPConn) error {
	return nil
}
