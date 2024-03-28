// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"net/netip"

	"github.com/cilium/cilium/pkg/datapath/types"
)

var _ types.IPSetManager = &IPSet{}

type IPSet struct{}

func (f *IPSet) AddToIPSet(_ string, _ types.IPSetFamily, _ ...netip.Addr) {}

func (f *IPSet) RemoveFromIPSet(name string, addrs ...netip.Addr) {}
