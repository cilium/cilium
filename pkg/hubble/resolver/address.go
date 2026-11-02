// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package resolver

import (
	"net/netip"

	"github.com/cilium/cilium/pkg/hubble/resolver/types"
	"github.com/cilium/cilium/pkg/ipcache"
)

type IPGetter struct {
	ipcache *ipcache.IPCache
}

func NewIPGetter(ipcache *ipcache.IPCache) types.IPGetter {
	return &IPGetter{ipcache: ipcache}
}

func (g *IPGetter) GetK8sMetadata(ip netip.Addr) *ipcache.K8sMetadata {
	if g.ipcache == nil {
		return nil
	}
	return g.ipcache.GetK8sMetadata(ip)
}

func (g *IPGetter) LookupSecIDByIP(ip netip.Addr) (ipcache.Identity, bool) {
	if g.ipcache == nil {
		return ipcache.Identity{}, false
	}
	return g.ipcache.LookupSecIDByIP(ip)
}
