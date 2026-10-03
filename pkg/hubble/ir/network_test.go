// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package ir

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/api/v1/flow"
)

func TestProtoToNetworkInterface(t *testing.T) {
	uu := map[string]struct {
		in *flow.NetworkInterface
		e  NetworkInterface
	}{
		"empty": {},

		"full": {
			in: &flow.NetworkInterface{
				Name:  "eth0",
				Index: 3,
			},
			e: NetworkInterface{
				Name:  "eth0",
				Index: 3,
			},
		},
	}

	for name, u := range uu {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, u.e, ProtoToNetworkInterface(u.in))
		})
	}
}

func TestNetworkInterface_toProto(t *testing.T) {
	uu := map[string]struct {
		in NetworkInterface
		e  *flow.NetworkInterface
	}{
		"empty": {},

		"full": {
			in: NetworkInterface{
				Name:  "eth0",
				Index: 3,
			},
			e: &flow.NetworkInterface{
				Name:  "eth0",
				Index: 3,
			},
		},
	}

	for name, u := range uu {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, u.e, u.in.toProto())
		})
	}
}

func TestNetworkInterfaceIsEmpty(t *testing.T) {
	uu := map[string]struct {
		in NetworkInterface
		e  bool
	}{
		"empty": {
			e: true,
		},

		"full": {
			in: NetworkInterface{Name: "eth0", Index: 2},
		},
	}

	for name, u := range uu {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, u.e, u.in.IsEmpty())
		})
	}
}
