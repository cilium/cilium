// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package l2v6respondermap

import (
	"net/netip"

	"github.com/cilium/cilium/pkg/maps/l2respondermap"
)

func NewFakeMap() Map {
	return &fakeMap{entries: make(map[L2V6ResponderKey]l2respondermap.L2ResponderStats)}
}

type fakeMap struct {
	entries map[L2V6ResponderKey]l2respondermap.L2ResponderStats
}

func (fm *fakeMap) Create(ip netip.Addr, ifIndex uint32) error {
	fm.entries[newL2V6ResponderKey(ip, ifIndex)] = l2respondermap.L2ResponderStats{}
	return nil
}

func (fm *fakeMap) Lookup(ip netip.Addr, ifIndex uint32) (*l2respondermap.L2ResponderStats, error) {
	entry, found := fm.entries[newL2V6ResponderKey(ip, ifIndex)]
	if found {
		return &entry, nil
	}

	return nil, nil
}

func (fm *fakeMap) Delete(ip netip.Addr, ifIndex uint32) error {
	delete(fm.entries, newL2V6ResponderKey(ip, ifIndex))
	return nil
}

func (fm *fakeMap) IterateWithCallback(cb IterateCallback) error {
	for k, v := range fm.entries {
		cb(&k, &v)
	}

	return nil
}
