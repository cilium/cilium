// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package namemanager

import (
	"net/netip"

	"github.com/cilium/cilium/pkg/container/set"
)

// nameIPSet accumulates unique name/IP pairs, including live zombies.
// It has no expiration times or secondary indexes.
// The caller must synchronize access.
type nameIPSet struct {
	byName map[string]set.Set[netip.Addr]
}

func newNameIPSet() nameIPSet {
	return nameIPSet{byName: make(map[string]set.Set[netip.Addr])}
}

// add returns whether any new name/IP pairs were inserted.
func (s *nameIPSet) add(name string, ips ...netip.Addr) bool {
	addresses := s.byName[name]
	previousLen := addresses.Len()
	for _, ip := range ips {
		addresses.Insert(ip)
	}
	if addresses.Len() == previousLen {
		return false
	}
	s.byName[name] = addresses
	return true
}
