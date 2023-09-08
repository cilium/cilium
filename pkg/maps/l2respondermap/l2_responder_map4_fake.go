// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package l2respondermap

import (
	"net/netip"
)

func NewFakeMap() Map {
	return &fakeMap{entries: make(map[L2ResponderKey]L2ResponderStats)}
}

type fakeMap struct {
	entries map[L2ResponderKey]L2ResponderStats
}

func (fm *fakeMap) Create(ip netip.Addr, ifIndex uint32) error {
	fm.entries[newL2ResponderKey(ip, ifIndex)] = L2ResponderStats{}
	return nil
}

func (fm *fakeMap) Lookup(ip netip.Addr, ifIndex uint32) (*L2ResponderStats, error) {
	entry, found := fm.entries[newL2ResponderKey(ip, ifIndex)]
	if found {
		return &entry, nil
	}

	return nil, nil
}

func (fm *fakeMap) Delete(ip netip.Addr, ifIndex uint32) error {
	delete(fm.entries, newL2ResponderKey(ip, ifIndex))
	return nil
}

func (fm *fakeMap) IterateWithCallback(cb IterateCallback) error {
	for k, v := range fm.entries {
		cb(&k, &v)
	}

	return nil
}
