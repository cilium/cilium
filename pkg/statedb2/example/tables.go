// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"net/netip"

	"github.com/cilium/cilium/pkg/statedb2"
	"github.com/cilium/cilium/pkg/statedb2/index"
)

type BackendID string

type Backend struct {
	ID   BackendID
	IP   netip.Addr
	Port uint16
}

var (
	BackendIDIndex = statedb2.Index[Backend, BackendID]{
		Name: "id",
		FromObject: func(b Backend) index.KeySet {
			return index.NewKeySet(index.String(string(b.ID)))
		},
		FromKey: func(id BackendID) []byte {
			return index.String(string(id))
		},
		Unique: true,
	}

	BackendIPIndex = statedb2.Index[Backend, netip.Addr]{
		Name: "ip",
		FromObject: func(b Backend) index.KeySet {
			return index.NewKeySet(index.NetIPAddr(b.IP))
		},
		FromKey: func(ip netip.Addr) index.Key {
			return index.NetIPAddr(ip)
		},
		Unique: false,
	}

	BackendPortIndex = statedb2.Index[Backend, uint16]{
		Name: "port",
		FromObject: func(b Backend) index.KeySet {
			return index.NewKeySet(index.Uint16(b.Port))
		},
		FromKey: func(port uint16) index.Key {
			return index.Uint16(port)
		},
		Unique: true,
	}

	BackendTableCell = statedb2.NewTableCell[Backend](
		"backends",
		BackendIDIndex,
		BackendIPIndex,
		BackendPortIndex,
	)
)
