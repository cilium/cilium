// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package resolver

import (
	"net/netip"
	"strings"

	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/hubble/resolver/types"
)

// DNSGetter implements types.DNSGetter using Cilium's endpoint manager.
type DNSGetter struct {
	endpointManager endpointmanager.EndpointManager
}

func NewDNSGetter(endpointManager endpointmanager.EndpointManager) types.DNSGetter {
	return &DNSGetter{endpointManager: endpointManager}
}

// GetNamesOf implements types.DNSGetter. It looks up DNS names of a given
// IP from the FQDN cache of an endpoint specified by sourceEpID.
func (g *DNSGetter) GetNamesOf(sourceEpID uint32, ip netip.Addr) []string {
	ep := g.endpointManager.LookupCiliumID(uint16(sourceEpID))
	if ep == nil {
		return nil
	}

	if !ip.IsValid() {
		return nil
	}
	names := ep.DNSHistory.LookupIP(ip)

	for i := range names {
		names[i] = strings.TrimSuffix(names[i], ".")
	}

	return names
}
