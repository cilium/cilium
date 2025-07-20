// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"net/netip"

	"github.com/cilium/cilium/pkg/datapath/iptables/ipset"
)

var _ ipset.Manager = &IPSet{}

type IPSet struct{}

func (f *IPSet) NewInitializer() ipset.Initializer { return &initializer{} }

func (f *IPSet) AddToIPSet(_ string, _ ipset.Family, _ ...netip.Addr) {}

func (f *IPSet) RemoveFromIPSet(name string, addrs ...netip.Addr) {}

type initializer struct {
}

func (i *initializer) InitDone() {
}
