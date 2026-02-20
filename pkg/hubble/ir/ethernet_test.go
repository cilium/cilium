// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ir

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/api/v1/flow"
)

func TestEthernet_toProto(t *testing.T) {
	m1, _ := net.ParseMAC("00:11:22:33:44:55")
	m2, _ := net.ParseMAC("66:77:88:99:aa:bb")

	uu := map[string]struct {
		ether Ethernet
		out   *flow.Ethernet
	}{
		"empty": {
			out: nil,
		},

		"partial": {
			ether: Ethernet{
				Source: m1,
			},
			out: &flow.Ethernet{
				Source: "00:11:22:33:44:55",
			},
		},

		"full": {
			ether: Ethernet{
				Source:      m1,
				Destination: m2,
			},
			out: &flow.Ethernet{
				Source:      "00:11:22:33:44:55",
				Destination: "66:77:88:99:aa:bb",
			},
		},
	}

	for name, u := range uu {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, u.out, u.ether.toProto())
		})
	}
}

func Test_protoToEther(t *testing.T) {
	m1, _ := net.ParseMAC("00:11:22:33:44:55")
	m2, _ := net.ParseMAC("66:77:88:99:aa:bb")

	uu := map[string]struct {
		in *flow.Ethernet
		e  Ethernet
	}{
		"empty": {
			in: nil,
		},

		"partial": {
			in: &flow.Ethernet{
				Source: "00:11:22:33:44:55",
			},
			e: Ethernet{
				Source: m1,
			},
		},

		"full": {
			in: &flow.Ethernet{
				Source:      "00:11:22:33:44:55",
				Destination: "66:77:88:99:aa:bb",
			},
			e: Ethernet{
				Source:      m1,
				Destination: m2,
			},
		},
	}

	for name, u := range uu {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, u.e, protoToEther(u.in))
		})
	}
}

func TestEthernet_isEmpty(t *testing.T) {
	uu := map[string]struct {
		ether Ethernet
		e     bool
	}{
		"empty": {
			e: true,
		},

		"partial": {
			ether: Ethernet{
				Source: net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			},
		},

		"full": {
			ether: Ethernet{
				Source:      net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
				Destination: net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
			},
		},
	}

	for name, u := range uu {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, u.e, u.ether.isEmpty())
		})
	}
}
