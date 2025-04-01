// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package socktermfilter

import (
	"net"

	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/types"

	"github.com/cilium/ebpf"
)

var key uint32 = 0

type SockTermFilterValue struct {
	Address       types.IPv6 `align:"address"`
	Port          uint16     `align:"port"`
	AddressFamily uint8      `align:"address_family"`
	_             uint8
}

type Map struct {
	*ebpf.Map
}

func (m *Map) SetFilter(af uint8, addr net.IP, port uint16) error {
	var value SockTermFilterValue
	value.AddressFamily = af
	value.Port = byteorder.NetworkToHost16(port)
	copy(value.Address[:], addr.To16())

	return m.Update(&key, &value, ebpf.UpdateAny)
}
